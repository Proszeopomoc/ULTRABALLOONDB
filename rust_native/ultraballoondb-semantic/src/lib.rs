use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use ultraballoondb_lifecycle::ReadSnapshot;
use ultraballoondb_storage::{hex_digest, sha256, sha256_file, StorageError};

pub const VECTOR_STORE_FORMAT_VERSION: u16 = 1;
pub const VECTOR_SPACE_SCHEMA_VERSION: u16 = 1;
pub const MAX_VECTOR_DIM: u32 = 65_536;
pub const MAX_STRING_BYTES: usize = 4_096;
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
pub const MAX_TOP_K: usize = 100_000;

const REGISTRY_MAGIC: [u8; 8] = *b"UBVSR01\0";
const COLUMN_MAGIC: [u8; 8] = *b"UBVCL01\0";
const JOURNAL_MAGIC: [u8; 8] = *b"UBVJ001\0";
const DESCRIPTOR_MAGIC: [u8; 8] = *b"UBVSD01\0";

#[derive(Debug)]
pub enum VectorStoreError {
    Io(std::io::Error),
    Storage(StorageError),
    Lifecycle(String),
    Invalid(String),
    Corrupt(String),
    Conflict(String),
    NotFound(String),
}

impl fmt::Display for VectorStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Storage(error) => {
                write!(f, "storage error: {error}")
            }
            Self::Lifecycle(message) => {
                write!(f, "lifecycle error: {message}")
            }
            Self::Invalid(message) => {
                write!(f, "invalid vector store input: {message}")
            }
            Self::Corrupt(message) => {
                write!(f, "corrupt vector store: {message}")
            }
            Self::Conflict(message) => {
                write!(f, "vector store conflict: {message}")
            }
            Self::NotFound(message) => {
                write!(f, "vector store item not found: {message}")
            }
        }
    }
}

impl std::error::Error for VectorStoreError {}

impl From<std::io::Error> for VectorStoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<StorageError> for VectorStoreError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

pub type Result<T> = std::result::Result<T, VectorStoreError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpaceId([u8; 32]);

impl SpaceId {
    pub const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex_digest(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum VectorOrigin {
    ExternalModel = 1,
    UltraBalloonNative = 2,
}

impl VectorOrigin {
    const fn code(self) -> u16 {
        self as u16
    }

    fn from_code(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::ExternalModel),
            2 => Ok(Self::UltraBalloonNative),
            _ => Err(VectorStoreError::Corrupt(format!(
                "unknown vector origin {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum VectorDType {
    F32 = 1,
}

impl VectorDType {
    const fn code(self) -> u16 {
        self as u16
    }

    fn from_code(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::F32),
            _ => Err(VectorStoreError::Corrupt(format!(
                "unknown vector dtype {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum VectorMetric {
    Cosine = 1,
}

impl VectorMetric {
    const fn code(self) -> u16 {
        self as u16
    }

    fn from_code(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::Cosine),
            _ => Err(VectorStoreError::Corrupt(format!(
                "unknown vector metric {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum VectorNormalization {
    None = 1,
    UnitL2 = 2,
}

impl VectorNormalization {
    const fn code(self) -> u16 {
        self as u16
    }

    fn from_code(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::None),
            2 => Ok(Self::UnitL2),
            _ => Err(VectorStoreError::Corrupt(format!(
                "unknown vector normalization {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VectorSpaceDescriptor {
    pub schema_version: u16,
    pub origin: VectorOrigin,
    pub provider_id: String,
    pub model_id: String,
    pub model_revision: String,
    pub preprocessing_id: String,
    pub dim: u32,
    pub dtype: VectorDType,
    pub metric: VectorMetric,
    pub normalization: VectorNormalization,
}

impl VectorSpaceDescriptor {
    pub fn external(
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        model_revision: impl Into<String>,
        preprocessing_id: impl Into<String>,
        dim: u32,
        normalization: VectorNormalization,
    ) -> Self {
        Self {
            schema_version: VECTOR_SPACE_SCHEMA_VERSION,
            origin: VectorOrigin::ExternalModel,
            provider_id: provider_id.into(),
            model_id: model_id.into(),
            model_revision: model_revision.into(),
            preprocessing_id: preprocessing_id.into(),
            dim,
            dtype: VectorDType::F32,
            metric: VectorMetric::Cosine,
            normalization,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != VECTOR_SPACE_SCHEMA_VERSION {
            return Err(VectorStoreError::Invalid(format!(
                "unsupported descriptor schema version {}",
                self.schema_version
            )));
        }
        if self.dim == 0 || self.dim > MAX_VECTOR_DIM {
            return Err(VectorStoreError::Invalid(format!(
                "dimension must be in 1..={MAX_VECTOR_DIM}"
            )));
        }
        validate_descriptor_string("provider_id", &self.provider_id)?;
        validate_descriptor_string("model_id", &self.model_id)?;
        validate_descriptor_string("model_revision", &self.model_revision)?;
        validate_descriptor_string("preprocessing_id", &self.preprocessing_id)?;
        if self.origin == VectorOrigin::ExternalModel
            && (self.provider_id.is_empty()
                || self.model_id.is_empty()
                || self.model_revision.is_empty()
                || self.preprocessing_id.is_empty())
        {
            return Err(VectorStoreError::Invalid(
                "external spaces require provider, model, revision and preprocessing IDs"
                    .to_string(),
            ));
        }
        if self.dtype != VectorDType::F32 {
            return Err(VectorStoreError::Invalid(
                "V1 supports only f32".to_string(),
            ));
        }
        if self.metric != VectorMetric::Cosine {
            return Err(VectorStoreError::Invalid(
                "V1 supports only cosine".to_string(),
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&DESCRIPTOR_MAGIC);
        bytes.extend_from_slice(&self.schema_version.to_le_bytes());
        bytes.extend_from_slice(&self.origin.code().to_le_bytes());
        bytes.extend_from_slice(&self.dtype.code().to_le_bytes());
        bytes.extend_from_slice(&self.metric.code().to_le_bytes());
        bytes.extend_from_slice(&self.normalization.code().to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&self.dim.to_le_bytes());
        append_string(&mut bytes, &self.provider_id)?;
        append_string(&mut bytes, &self.model_id)?;
        append_string(&mut bytes, &self.model_revision)?;
        append_string(&mut bytes, &self.preprocessing_id)?;
        Ok(bytes)
    }

    pub fn space_id(&self) -> Result<SpaceId> {
        Ok(SpaceId::from_bytes(sha256(&self.canonical_bytes()?)))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateSpaceOutcome {
    Created,
    Existing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PutVectorOutcome {
    Inserted,
    Updated,
    Unchanged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportOutcome {
    Applied,
    DuplicateIgnored,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VectorInput {
    pub record_id: String,
    pub vector: Vec<f32>,
}

impl VectorInput {
    pub fn new(record_id: impl Into<String>, vector: Vec<f32>) -> Self {
        Self {
            record_id: record_id.into(),
            vector,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VectorHit {
    pub record_id: String,
    pub cosine_score: f64,
    pub rank: usize,
    pub exact: bool,
    pub space_id: SpaceId,
    pub column_generation: u64,
    pub database_snapshot_sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupFileEntry {
    pub relative_path: String,
    pub byte_count: u64,
    pub sha256: [u8; 32],
}

impl BackupFileEntry {
    pub fn sha256_hex(&self) -> String {
        hex_digest(&self.sha256)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VectorStoreVerification {
    pub space_count: u64,
    pub vector_count: u64,
    pub import_receipt_count: u64,
    pub verified_file_count: u64,
    pub registry_sha256: [u8; 32],
}

impl VectorStoreVerification {
    pub fn registry_sha256_hex(&self) -> String {
        hex_digest(&self.registry_sha256)
    }
}

#[derive(Clone, Debug)]
struct VectorColumn {
    space_id: SpaceId,
    generation: u64,
    dim: u32,
    imports: BTreeMap<String, [u8; 32]>,
    record_ids: Vec<String>,
    vectors: Vec<f32>,
}

impl VectorColumn {
    fn empty(space_id: SpaceId, dim: u32) -> Self {
        Self {
            space_id,
            generation: 0,
            dim,
            imports: BTreeMap::new(),
            record_ids: Vec::new(),
            vectors: Vec::new(),
        }
    }

    fn vector_count(&self) -> usize {
        self.record_ids.len()
    }

    fn vector_at(&self, index: usize) -> &[f32] {
        let dim = self.dim as usize;
        let start = index * dim;
        &self.vectors[start..start + dim]
    }

    fn upsert(&mut self, record_id: String, vector: &[f32]) -> PutVectorOutcome {
        let dim = self.dim as usize;
        match self.record_ids.binary_search(&record_id) {
            Ok(index) => {
                let start = index * dim;
                let end = start + dim;
                if vector_bits_equal(&self.vectors[start..end], vector) {
                    PutVectorOutcome::Unchanged
                } else {
                    self.vectors[start..end].copy_from_slice(vector);
                    PutVectorOutcome::Updated
                }
            }
            Err(index) => {
                self.record_ids.insert(index, record_id);
                let start = index * dim;
                self.vectors.splice(start..start, vector.iter().copied());
                PutVectorOutcome::Inserted
            }
        }
    }

    fn validate(&self) -> Result<()> {
        if self.dim == 0 || self.dim > MAX_VECTOR_DIM {
            return Err(VectorStoreError::Corrupt(
                "column dimension is invalid".to_string(),
            ));
        }
        let expected = self
            .record_ids
            .len()
            .checked_mul(self.dim as usize)
            .ok_or_else(|| {
                VectorStoreError::Corrupt("column vector length overflow".to_string())
            })?;
        if self.vectors.len() != expected {
            return Err(VectorStoreError::Corrupt(
                "column matrix length mismatch".to_string(),
            ));
        }
        for window in self.record_ids.windows(2) {
            if window[0] >= window[1] {
                return Err(VectorStoreError::Corrupt(
                    "column record IDs are not strictly sorted".to_string(),
                ));
            }
        }
        for (index, record_id) in self.record_ids.iter().enumerate() {
            validate_record_id(record_id)?;
            validate_vector(self.vector_at(index), self.dim)?;
        }
        for key in self.imports.keys() {
            validate_idempotency_key(key)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct VectorStore {
    root: PathBuf,
    registry: BTreeMap<SpaceId, VectorSpaceDescriptor>,
    columns: BTreeMap<SpaceId, VectorColumn>,
}

impl VectorStore {
    pub fn create(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let vectors_root = vectors_root(&root);
        if vectors_root.exists() {
            return Err(VectorStoreError::Conflict(
                "vectors directory already exists".to_string(),
            ));
        }
        fs::create_dir_all(columns_root(&root))?;
        let registry = BTreeMap::new();
        persist_image(&registry_path(&root), &encode_registry(&registry)?)?;
        Ok(Self {
            root,
            registry,
            columns: BTreeMap::new(),
        })
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let registry_file = registry_path(&root);
        recover_image(&registry_file)?;
        if !registry_file.is_file() {
            return Err(VectorStoreError::NotFound(
                "vector registry does not exist".to_string(),
            ));
        }
        let registry = decode_registry(&read_all(&registry_file)?)?;
        let columns_directory = columns_root(&root);
        if !columns_directory.is_dir() {
            return Err(VectorStoreError::Corrupt(
                "vector columns directory is missing".to_string(),
            ));
        }

        let mut columns = BTreeMap::new();
        for (space_id, descriptor) in &registry {
            let path = column_path(&root, *space_id);
            recover_image(&path)?;
            if !path.is_file() {
                return Err(VectorStoreError::Corrupt(format!(
                    "column missing for space {}",
                    space_id.to_hex()
                )));
            }
            let column = decode_column(&read_all(&path)?)?;
            if column.space_id != *space_id {
                return Err(VectorStoreError::Corrupt(
                    "column space ID mismatch".to_string(),
                ));
            }
            if column.dim != descriptor.dim {
                return Err(VectorStoreError::Corrupt(
                    "column dimension differs from descriptor".to_string(),
                ));
            }
            columns.insert(*space_id, column);
        }

        verify_column_directory(&root, registry.keys().copied().collect())?;

        let store = Self {
            root,
            registry,
            columns,
        };
        store.verify()?;
        Ok(store)
    }

    pub fn open_or_create(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if vectors_root(&root).exists() {
            Self::open(root)
        } else {
            Self::create(root)
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn space_count(&self) -> usize {
        self.registry.len()
    }

    pub fn descriptor(&self, space_id: SpaceId) -> Option<&VectorSpaceDescriptor> {
        self.registry.get(&space_id)
    }

    pub fn column_generation(&self, space_id: SpaceId) -> Option<u64> {
        self.columns.get(&space_id).map(|column| column.generation)
    }

    pub fn create_space(
        &mut self,
        descriptor: VectorSpaceDescriptor,
    ) -> Result<(SpaceId, CreateSpaceOutcome)> {
        descriptor.validate()?;
        let space_id = descriptor.space_id()?;
        if let Some(existing) = self.registry.get(&space_id) {
            if existing == &descriptor {
                return Ok((space_id, CreateSpaceOutcome::Existing));
            }
            return Err(VectorStoreError::Conflict(
                "space ID collision with different descriptor".to_string(),
            ));
        }

        let column = VectorColumn::empty(space_id, descriptor.dim);
        let column_file = column_path(&self.root, space_id);
        persist_image(&column_file, &encode_column(&column)?)?;

        let mut next_registry = self.registry.clone();
        next_registry.insert(space_id, descriptor.clone());
        if let Err(error) = persist_image(
            &registry_path(&self.root),
            &encode_registry(&next_registry)?,
        ) {
            remove_image_and_residue(&column_file)?;
            return Err(error);
        }

        self.registry = next_registry;
        self.columns.insert(space_id, column);
        Ok((space_id, CreateSpaceOutcome::Created))
    }

    pub fn put_vector(
        &mut self,
        snapshot: &ReadSnapshot<'_>,
        space_id: SpaceId,
        record_id: &str,
        vector: &[f32],
    ) -> Result<PutVectorOutcome> {
        validate_record_exists(snapshot, record_id)?;
        let descriptor = self
            .registry
            .get(&space_id)
            .ok_or_else(|| VectorStoreError::NotFound(format!("space {}", space_id.to_hex())))?;
        validate_vector(vector, descriptor.dim)?;

        let current = self.columns.get(&space_id).ok_or_else(|| {
            VectorStoreError::Corrupt("registered space has no loaded column".to_string())
        })?;
        let mut next = current.clone();
        let outcome = next.upsert(record_id.to_string(), vector);
        if outcome == PutVectorOutcome::Unchanged {
            return Ok(outcome);
        }
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or_else(|| VectorStoreError::Conflict("column generation overflow".to_string()))?;
        persist_image(&column_path(&self.root, space_id), &encode_column(&next)?)?;
        self.columns.insert(space_id, next);
        Ok(outcome)
    }

    pub fn import_vectors(
        &mut self,
        snapshot: &ReadSnapshot<'_>,
        space_id: SpaceId,
        idempotency_key: &str,
        batch: &[VectorInput],
    ) -> Result<ImportOutcome> {
        validate_idempotency_key(idempotency_key)?;
        if batch.is_empty() {
            return Err(VectorStoreError::Invalid(
                "import batch cannot be empty".to_string(),
            ));
        }

        let descriptor = self
            .registry
            .get(&space_id)
            .ok_or_else(|| VectorStoreError::NotFound(format!("space {}", space_id.to_hex())))?;
        let mut sorted = batch.to_vec();
        sorted.sort_by(|left, right| left.record_id.cmp(&right.record_id));
        for window in sorted.windows(2) {
            if window[0].record_id == window[1].record_id {
                return Err(VectorStoreError::Invalid(format!(
                    "duplicate record ID in import batch: {}",
                    window[0].record_id
                )));
            }
        }
        for item in &sorted {
            validate_record_exists(snapshot, &item.record_id)?;
            validate_vector(&item.vector, descriptor.dim)?;
        }
        let digest = import_batch_digest(space_id, &sorted)?;

        let current = self.columns.get(&space_id).ok_or_else(|| {
            VectorStoreError::Corrupt("registered space has no loaded column".to_string())
        })?;
        if let Some(existing) = current.imports.get(idempotency_key) {
            if existing == &digest {
                return Ok(ImportOutcome::DuplicateIgnored);
            }
            return Err(VectorStoreError::Conflict(
                "idempotency key already refers to a different batch".to_string(),
            ));
        }

        let mut next = current.clone();
        for item in sorted {
            next.upsert(item.record_id, &item.vector);
        }
        next.imports.insert(idempotency_key.to_string(), digest);
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or_else(|| VectorStoreError::Conflict("column generation overflow".to_string()))?;
        persist_image(&column_path(&self.root, space_id), &encode_column(&next)?)?;
        self.columns.insert(space_id, next);
        Ok(ImportOutcome::Applied)
    }

    pub fn find_exact(
        &self,
        snapshot: &ReadSnapshot<'_>,
        space_id: SpaceId,
        query_vector: &[f32],
        k: usize,
    ) -> Result<Vec<VectorHit>> {
        if k == 0 || k > MAX_TOP_K {
            return Err(VectorStoreError::Invalid(format!(
                "k must be in 1..={MAX_TOP_K}"
            )));
        }
        let descriptor = self
            .registry
            .get(&space_id)
            .ok_or_else(|| VectorStoreError::NotFound(format!("space {}", space_id.to_hex())))?;
        validate_vector(query_vector, descriptor.dim)?;

        let query_norm = squared_norm(query_vector);
        let column = self.columns.get(&space_id).ok_or_else(|| {
            VectorStoreError::Corrupt("registered space has no loaded column".to_string())
        })?;

        let mut scored = Vec::new();
        for (index, record_id) in column.record_ids.iter().enumerate() {
            if snapshot
                .record(record_id)
                .map_err(|error| VectorStoreError::Lifecycle(error.to_string()))?
                .is_none()
            {
                continue;
            }
            let vector = column.vector_at(index);
            let score = cosine_with_query_norm(query_vector, query_norm, vector);
            scored.push((record_id.clone(), score));
        }

        scored.sort_by(|left, right| match right.1.total_cmp(&left.1) {
            Ordering::Equal => left.0.cmp(&right.0),
            ordering => ordering,
        });
        scored.truncate(k.min(scored.len()));

        let snapshot_sha256 = snapshot.descriptor().snapshot_sha256;
        Ok(scored
            .into_iter()
            .enumerate()
            .map(|(index, (record_id, cosine_score))| VectorHit {
                record_id,
                cosine_score,
                rank: index + 1,
                exact: true,
                space_id,
                column_generation: column.generation,
                database_snapshot_sha256: snapshot_sha256,
            })
            .collect())
    }

    pub fn verify(&self) -> Result<VectorStoreVerification> {
        let registry_file = registry_path(&self.root);
        let decoded_registry = decode_registry(&read_all(&registry_file)?)?;
        if decoded_registry != self.registry {
            return Err(VectorStoreError::Corrupt(
                "in-memory registry differs from disk".to_string(),
            ));
        }
        verify_no_residue(&registry_file)?;

        let mut vector_count = 0u64;
        let mut import_receipt_count = 0u64;
        let mut verified_file_count = 1u64;
        for (space_id, descriptor) in &self.registry {
            let path = column_path(&self.root, *space_id);
            let decoded = decode_column(&read_all(&path)?)?;
            let loaded = self
                .columns
                .get(space_id)
                .ok_or_else(|| VectorStoreError::Corrupt("loaded column missing".to_string()))?;
            if decoded.space_id != *space_id
                || decoded.dim != descriptor.dim
                || decoded.generation != loaded.generation
                || decoded.record_ids != loaded.record_ids
                || !vector_bits_equal(&decoded.vectors, &loaded.vectors)
                || decoded.imports != loaded.imports
            {
                return Err(VectorStoreError::Corrupt(
                    "loaded column differs from disk".to_string(),
                ));
            }
            verify_no_residue(&path)?;
            vector_count = vector_count
                .checked_add(decoded.vector_count() as u64)
                .ok_or_else(|| VectorStoreError::Corrupt("vector count overflow".to_string()))?;
            import_receipt_count = import_receipt_count
                .checked_add(decoded.imports.len() as u64)
                .ok_or_else(|| VectorStoreError::Corrupt("import count overflow".to_string()))?;
            verified_file_count += 1;
        }

        verify_column_directory(&self.root, self.registry.keys().copied().collect())?;

        Ok(VectorStoreVerification {
            space_count: self.registry.len() as u64,
            vector_count,
            import_receipt_count,
            verified_file_count,
            registry_sha256: sha256_file(&registry_file)?,
        })
    }

    pub fn backup_file_set(&self) -> Result<Vec<BackupFileEntry>> {
        self.verify()?;
        let mut paths = vec![registry_path(&self.root)];
        for space_id in self.registry.keys() {
            paths.push(column_path(&self.root, *space_id));
        }
        let mut entries = Vec::new();
        for path in paths {
            let relative = path.strip_prefix(&self.root).map_err(|_| {
                VectorStoreError::Corrupt("backup path escapes store root".to_string())
            })?;
            validate_relative_path(relative)?;
            let metadata = fs::metadata(&path)?;
            entries.push(BackupFileEntry {
                relative_path: relative
                    .to_str()
                    .ok_or_else(|| {
                        VectorStoreError::Corrupt("backup path is not UTF-8".to_string())
                    })?
                    .replace('\\', "/"),
                byte_count: metadata.len(),
                sha256: sha256_file(&path)?,
            });
        }
        entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        Ok(entries)
    }

    #[doc(hidden)]
    pub fn stage_put_vector_journal_for_probe(
        &self,
        snapshot: &ReadSnapshot<'_>,
        space_id: SpaceId,
        record_id: &str,
        vector: &[f32],
    ) -> Result<u64> {
        validate_record_exists(snapshot, record_id)?;
        let descriptor = self
            .registry
            .get(&space_id)
            .ok_or_else(|| VectorStoreError::NotFound(format!("space {}", space_id.to_hex())))?;
        validate_vector(vector, descriptor.dim)?;
        let current = self.columns.get(&space_id).ok_or_else(|| {
            VectorStoreError::Corrupt("registered space has no loaded column".to_string())
        })?;
        let mut next = current.clone();
        let outcome = next.upsert(record_id.to_string(), vector);
        if outcome == PutVectorOutcome::Unchanged {
            return Ok(next.generation);
        }
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or_else(|| VectorStoreError::Conflict("column generation overflow".to_string()))?;
        let path = column_path(&self.root, space_id);
        write_journal_only(&path, &encode_column(&next)?)?;
        Ok(next.generation)
    }
}

fn validate_record_exists(snapshot: &ReadSnapshot<'_>, record_id: &str) -> Result<()> {
    validate_record_id(record_id)?;
    let exists = snapshot
        .record(record_id)
        .map_err(|error| VectorStoreError::Lifecycle(error.to_string()))?
        .is_some();
    if !exists {
        return Err(VectorStoreError::NotFound(format!(
            "canonical record {record_id}"
        )));
    }
    Ok(())
}

fn validate_descriptor_string(name: &str, value: &str) -> Result<()> {
    if value.as_bytes().len() > MAX_STRING_BYTES {
        return Err(VectorStoreError::Invalid(format!(
            "{name} exceeds {MAX_STRING_BYTES} bytes"
        )));
    }
    if value.as_bytes().contains(&0) {
        return Err(VectorStoreError::Invalid(format!("{name} contains NUL")));
    }
    Ok(())
}

fn validate_record_id(record_id: &str) -> Result<()> {
    if record_id.is_empty()
        || record_id.as_bytes().len() > MAX_STRING_BYTES
        || record_id.as_bytes().contains(&0)
    {
        return Err(VectorStoreError::Invalid(
            "record ID must be non-empty UTF-8 without NUL and within the size limit".to_string(),
        ));
    }
    Ok(())
}

fn validate_idempotency_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.as_bytes().len() > MAX_IDEMPOTENCY_KEY_BYTES
        || key.as_bytes().contains(&0)
    {
        return Err(VectorStoreError::Invalid(
            "idempotency key is invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_vector(vector: &[f32], dim: u32) -> Result<()> {
    if vector.len() != dim as usize {
        return Err(VectorStoreError::Invalid(format!(
            "vector dimension mismatch: expected={dim} actual={}",
            vector.len()
        )));
    }
    let mut norm = 0.0f64;
    for value in vector {
        if !value.is_finite() {
            return Err(VectorStoreError::Invalid(
                "vector contains NaN or infinity".to_string(),
            ));
        }
        let value = *value as f64;
        norm += value * value;
    }
    if norm == 0.0 || !norm.is_finite() {
        return Err(VectorStoreError::Invalid(
            "vector norm must be finite and non-zero".to_string(),
        ));
    }
    Ok(())
}

fn squared_norm(vector: &[f32]) -> f64 {
    let mut value = 0.0f64;
    for coordinate in vector {
        let coordinate = *coordinate as f64;
        value += coordinate * coordinate;
    }
    value
}

fn cosine_with_query_norm(query: &[f32], query_norm: f64, vector: &[f32]) -> f64 {
    let mut dot = 0.0f64;
    let mut vector_norm = 0.0f64;
    for index in 0..query.len() {
        let left = query[index] as f64;
        let right = vector[index] as f64;
        dot += left * right;
        vector_norm += right * right;
    }
    dot / (query_norm.sqrt() * vector_norm.sqrt())
}

fn vector_bits_equal(left: &[f32], right: &[f32]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(left, right)| left.to_bits() == right.to_bits())
}

fn import_batch_digest(space_id: SpaceId, batch: &[VectorInput]) -> Result<[u8; 32]> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"UBVIMP01");
    bytes.extend_from_slice(space_id.as_bytes());
    bytes.extend_from_slice(&(batch.len() as u64).to_le_bytes());
    for item in batch {
        append_string(&mut bytes, &item.record_id)?;
        bytes.extend_from_slice(&(item.vector.len() as u32).to_le_bytes());
        for value in &item.vector {
            bytes.extend_from_slice(&value.to_bits().to_le_bytes());
        }
    }
    Ok(sha256(&bytes))
}

fn encode_registry(registry: &BTreeMap<SpaceId, VectorSpaceDescriptor>) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    body.extend_from_slice(&REGISTRY_MAGIC);
    body.extend_from_slice(&VECTOR_STORE_FORMAT_VERSION.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&(registry.len() as u64).to_le_bytes());
    for (space_id, descriptor) in registry {
        let descriptor_bytes = descriptor.canonical_bytes()?;
        body.extend_from_slice(space_id.as_bytes());
        body.extend_from_slice(&(descriptor_bytes.len() as u32).to_le_bytes());
        body.extend_from_slice(&descriptor_bytes);
    }
    append_footer(body)
}

fn decode_registry(bytes: &[u8]) -> Result<BTreeMap<SpaceId, VectorSpaceDescriptor>> {
    let body = verify_footer(bytes, "registry")?;
    let mut reader = Reader::new(body);
    if reader.take(8)? != REGISTRY_MAGIC.as_slice() {
        return Err(VectorStoreError::Corrupt(
            "registry magic mismatch".to_string(),
        ));
    }
    let version = reader.u16()?;
    if version != VECTOR_STORE_FORMAT_VERSION {
        return Err(VectorStoreError::Corrupt(format!(
            "unsupported registry version {version}"
        )));
    }
    if reader.u16()? != 0 {
        return Err(VectorStoreError::Corrupt(
            "registry reserved field is non-zero".to_string(),
        ));
    }
    let count = reader.u64()?;
    let mut registry = BTreeMap::new();
    for _ in 0..count {
        let space_id = SpaceId::from_bytes(reader.array_32()?);
        let descriptor_length = reader.u32()? as usize;
        let descriptor = decode_descriptor(reader.take(descriptor_length)?)?;
        if descriptor.space_id()? != space_id {
            return Err(VectorStoreError::Corrupt(
                "registry descriptor hash mismatch".to_string(),
            ));
        }
        if registry.insert(space_id, descriptor).is_some() {
            return Err(VectorStoreError::Corrupt(
                "duplicate space ID in registry".to_string(),
            ));
        }
    }
    reader.finish("registry")?;
    Ok(registry)
}

fn decode_descriptor(bytes: &[u8]) -> Result<VectorSpaceDescriptor> {
    let mut reader = Reader::new(bytes);
    if reader.take(8)? != DESCRIPTOR_MAGIC.as_slice() {
        return Err(VectorStoreError::Corrupt(
            "descriptor magic mismatch".to_string(),
        ));
    }
    let schema_version = reader.u16()?;
    let origin = VectorOrigin::from_code(reader.u16()?)?;
    let dtype = VectorDType::from_code(reader.u16()?)?;
    let metric = VectorMetric::from_code(reader.u16()?)?;
    let normalization = VectorNormalization::from_code(reader.u16()?)?;
    if reader.u16()? != 0 {
        return Err(VectorStoreError::Corrupt(
            "descriptor reserved field is non-zero".to_string(),
        ));
    }
    let dim = reader.u32()?;
    let descriptor = VectorSpaceDescriptor {
        schema_version,
        origin,
        provider_id: reader.string()?,
        model_id: reader.string()?,
        model_revision: reader.string()?,
        preprocessing_id: reader.string()?,
        dim,
        dtype,
        metric,
        normalization,
    };
    reader.finish("descriptor")?;
    descriptor
        .validate()
        .map_err(|error| VectorStoreError::Corrupt(error.to_string()))?;
    Ok(descriptor)
}

fn encode_column(column: &VectorColumn) -> Result<Vec<u8>> {
    column.validate()?;
    let mut body = Vec::new();
    body.extend_from_slice(&COLUMN_MAGIC);
    body.extend_from_slice(&VECTOR_STORE_FORMAT_VERSION.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(column.space_id.as_bytes());
    body.extend_from_slice(&column.generation.to_le_bytes());
    body.extend_from_slice(&column.dim.to_le_bytes());
    body.extend_from_slice(&(column.record_ids.len() as u64).to_le_bytes());
    body.extend_from_slice(&(column.imports.len() as u64).to_le_bytes());

    for (key, digest) in &column.imports {
        append_string(&mut body, key)?;
        body.extend_from_slice(digest);
    }
    for record_id in &column.record_ids {
        append_string(&mut body, record_id)?;
    }
    for value in &column.vectors {
        body.extend_from_slice(&value.to_bits().to_le_bytes());
    }
    append_footer(body)
}

fn decode_column(bytes: &[u8]) -> Result<VectorColumn> {
    let body = verify_footer(bytes, "column")?;
    let mut reader = Reader::new(body);
    if reader.take(8)? != COLUMN_MAGIC.as_slice() {
        return Err(VectorStoreError::Corrupt(
            "column magic mismatch".to_string(),
        ));
    }
    let version = reader.u16()?;
    if version != VECTOR_STORE_FORMAT_VERSION {
        return Err(VectorStoreError::Corrupt(format!(
            "unsupported column version {version}"
        )));
    }
    if reader.u16()? != 0 {
        return Err(VectorStoreError::Corrupt(
            "column reserved field is non-zero".to_string(),
        ));
    }
    let space_id = SpaceId::from_bytes(reader.array_32()?);
    let generation = reader.u64()?;
    let dim = reader.u32()?;
    let record_count = usize::try_from(reader.u64()?)
        .map_err(|_| VectorStoreError::Corrupt("record count does not fit usize".to_string()))?;
    let import_count = usize::try_from(reader.u64()?)
        .map_err(|_| VectorStoreError::Corrupt("import count does not fit usize".to_string()))?;

    let mut imports = BTreeMap::new();
    for _ in 0..import_count {
        let key = reader.string()?;
        validate_idempotency_key(&key)
            .map_err(|error| VectorStoreError::Corrupt(error.to_string()))?;
        let digest = reader.array_32()?;
        if imports.insert(key, digest).is_some() {
            return Err(VectorStoreError::Corrupt(
                "duplicate import key".to_string(),
            ));
        }
    }

    let mut record_ids = Vec::with_capacity(record_count);
    for _ in 0..record_count {
        let record_id = reader.string()?;
        validate_record_id(&record_id)
            .map_err(|error| VectorStoreError::Corrupt(error.to_string()))?;
        record_ids.push(record_id);
    }

    let coordinate_count = record_count
        .checked_mul(dim as usize)
        .ok_or_else(|| VectorStoreError::Corrupt("coordinate count overflow".to_string()))?;
    let mut vectors = Vec::with_capacity(coordinate_count);
    for _ in 0..coordinate_count {
        vectors.push(f32::from_bits(reader.u32()?));
    }
    reader.finish("column")?;

    let column = VectorColumn {
        space_id,
        generation,
        dim,
        imports,
        record_ids,
        vectors,
    };
    column
        .validate()
        .map_err(|error| VectorStoreError::Corrupt(error.to_string()))?;
    Ok(column)
}

fn append_footer(mut body: Vec<u8>) -> Result<Vec<u8>> {
    let footer = sha256(&body);
    body.extend_from_slice(&footer);
    Ok(body)
}

fn verify_footer<'a>(bytes: &'a [u8], name: &str) -> Result<&'a [u8]> {
    if bytes.len() < 32 {
        return Err(VectorStoreError::Corrupt(format!("{name} is truncated")));
    }
    let split = bytes.len() - 32;
    let (body, footer) = bytes.split_at(split);
    let expected = sha256(body);
    if expected.as_slice() != footer {
        return Err(VectorStoreError::Corrupt(format!(
            "{name} SHA256 footer mismatch"
        )));
    }
    Ok(body)
}

fn encode_journal(payload: &[u8]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    body.extend_from_slice(&JOURNAL_MAGIC);
    body.extend_from_slice(&VECTOR_STORE_FORMAT_VERSION.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    body.extend_from_slice(&sha256(payload));
    body.extend_from_slice(payload);
    append_footer(body)
}

fn decode_journal(bytes: &[u8]) -> Result<Vec<u8>> {
    let body = verify_footer(bytes, "journal")?;
    let mut reader = Reader::new(body);
    if reader.take(8)? != JOURNAL_MAGIC.as_slice() {
        return Err(VectorStoreError::Corrupt(
            "journal magic mismatch".to_string(),
        ));
    }
    let version = reader.u16()?;
    if version != VECTOR_STORE_FORMAT_VERSION {
        return Err(VectorStoreError::Corrupt(format!(
            "unsupported journal version {version}"
        )));
    }
    if reader.u16()? != 0 {
        return Err(VectorStoreError::Corrupt(
            "journal reserved field is non-zero".to_string(),
        ));
    }
    let payload_length = usize::try_from(reader.u64()?).map_err(|_| {
        VectorStoreError::Corrupt("journal payload length does not fit usize".to_string())
    })?;
    let expected_sha = reader.array_32()?;
    let payload = reader.take(payload_length)?.to_vec();
    reader.finish("journal")?;
    if sha256(&payload) != expected_sha {
        return Err(VectorStoreError::Corrupt(
            "journal payload SHA mismatch".to_string(),
        ));
    }
    Ok(payload)
}

fn persist_image(path: &Path, payload: &[u8]) -> Result<()> {
    recover_image(path)?;
    write_journal_only(path, payload)?;
    replay_journal(path)
}

fn write_journal_only(path: &Path, payload: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let journal = journal_path(path);
    if journal.exists() {
        return Err(VectorStoreError::Conflict(format!(
            "journal already exists: {}",
            journal.display()
        )));
    }
    write_file_sync(&journal, &encode_journal(payload)?, true)
}

fn recover_image(path: &Path) -> Result<()> {
    let journal = journal_path(path);
    let temporary = temporary_path(path);
    let backup = backup_path(path);

    if journal.exists() {
        return replay_journal(path);
    }

    if !path.exists() && backup.exists() {
        fs::rename(&backup, path)?;
    }
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    if path.exists() && backup.exists() {
        fs::remove_file(&backup)?;
    }
    Ok(())
}

fn replay_journal(path: &Path) -> Result<()> {
    let journal = journal_path(path);
    if !journal.is_file() {
        return Err(VectorStoreError::Corrupt(format!(
            "journal is not a regular file: {}",
            journal.display()
        )));
    }
    let payload = decode_journal(&read_all(&journal)?)?;
    let payload_sha = sha256(&payload);
    if path.is_file() && sha256_file(path)? == payload_sha {
        cleanup_replacement_residue(path)?;
        return Ok(());
    }

    let temporary = temporary_path(path);
    let backup = backup_path(path);
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    if backup.exists() {
        fs::remove_file(&backup)?;
    }
    write_file_sync(&temporary, &payload, true)?;
    if path.exists() {
        fs::rename(path, &backup)?;
    }
    if let Err(error) = fs::rename(&temporary, path) {
        if backup.exists() && !path.exists() {
            let _ = fs::rename(&backup, path);
        }
        return Err(VectorStoreError::Io(error));
    }
    if backup.exists() {
        fs::remove_file(&backup)?;
    }
    if journal.exists() {
        fs::remove_file(journal)?;
    }
    Ok(())
}

fn cleanup_replacement_residue(path: &Path) -> Result<()> {
    for residue in [temporary_path(path), backup_path(path), journal_path(path)] {
        if residue.exists() {
            fs::remove_file(residue)?;
        }
    }
    Ok(())
}

fn remove_image_and_residue(path: &Path) -> Result<()> {
    for target in [
        path.to_path_buf(),
        temporary_path(path),
        backup_path(path),
        journal_path(path),
    ] {
        if target.exists() {
            fs::remove_file(target)?;
        }
    }
    Ok(())
}

fn verify_no_residue(path: &Path) -> Result<()> {
    for residue in [temporary_path(path), backup_path(path), journal_path(path)] {
        if residue.exists() {
            return Err(VectorStoreError::Corrupt(format!(
                "transaction residue exists: {}",
                residue.display()
            )));
        }
    }
    Ok(())
}

fn write_file_sync(path: &Path, bytes: &[u8], create_new: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn read_all(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(VectorStoreError::Corrupt(format!(
            "path is not a regular file: {}",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn verify_column_directory(root: &Path, expected: BTreeSet<SpaceId>) -> Result<()> {
    let directory = columns_root(root);
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(VectorStoreError::Corrupt(format!(
                "unexpected non-file in columns directory: {}",
                path.display()
            )));
        }
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| VectorStoreError::Corrupt("column filename is not UTF-8".to_string()))?;
        if !name.ends_with(".ubvc") {
            return Err(VectorStoreError::Corrupt(format!(
                "unexpected column-directory file {name}"
            )));
        }
        let hex = &name[..name.len() - 5];
        let bytes = decode_hex_32(hex)?;
        actual.insert(SpaceId::from_bytes(bytes));
    }
    if actual != expected {
        return Err(VectorStoreError::Corrupt(
            "registered and physical column sets differ".to_string(),
        ));
    }
    Ok(())
}

fn decode_hex_32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err(VectorStoreError::Corrupt(
            "space filename is not a 64-character hex digest".to_string(),
        ));
    }
    let mut result = [0u8; 32];
    for index in 0..32 {
        result[index] = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
            VectorStoreError::Corrupt("space filename contains invalid hex".to_string())
        })?;
    }
    Ok(result)
}

fn validate_relative_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(VectorStoreError::Invalid(
            "path must be non-empty and relative".to_string(),
        ));
    }
    if !path
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(VectorStoreError::Invalid(
            "path contains a non-normal component".to_string(),
        ));
    }
    Ok(())
}

fn append_string(bytes: &mut Vec<u8>, value: &str) -> Result<()> {
    validate_descriptor_string("string", value)?;
    let length = u32::try_from(value.as_bytes().len())
        .map_err(|_| VectorStoreError::Invalid("string length does not fit u32".to_string()))?;
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn vectors_root(root: &Path) -> PathBuf {
    root.join("vectors")
}

fn columns_root(root: &Path) -> PathBuf {
    vectors_root(root).join("COLUMNS")
}

fn registry_path(root: &Path) -> PathBuf {
    vectors_root(root).join("REGISTRY.ubvs")
}

fn column_path(root: &Path, space_id: SpaceId) -> PathBuf {
    columns_root(root).join(format!("{}.ubvc", space_id.to_hex()))
}

fn suffix_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(suffix);
    PathBuf::from(value)
}

fn journal_path(path: &Path) -> PathBuf {
    suffix_path(path, ".journal")
}

fn temporary_path(path: &Path) -> PathBuf {
    suffix_path(path, ".tmp")
}

fn backup_path(path: &Path) -> PathBuf {
    suffix_path(path, ".bak")
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or_else(|| VectorStoreError::Corrupt("binary offset overflow".to_string()))?;
        if end > self.bytes.len() {
            return Err(VectorStoreError::Corrupt(
                "binary field is truncated".to_string(),
            ));
        }
        let value = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16> {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(bytes))
    }

    fn array_32(&mut self) -> Result<[u8; 32]> {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(self.take(32)?);
        Ok(bytes)
    }

    fn string(&mut self) -> Result<String> {
        let length = self.u32()? as usize;
        if length > MAX_STRING_BYTES {
            return Err(VectorStoreError::Corrupt(
                "encoded string exceeds size limit".to_string(),
            ));
        }
        String::from_utf8(self.take(length)?.to_vec())
            .map_err(|_| VectorStoreError::Corrupt("encoded string is not UTF-8".to_string()))
    }

    fn finish(&self, name: &str) -> Result<()> {
        if self.cursor != self.bytes.len() {
            return Err(VectorStoreError::Corrupt(format!(
                "{name} contains trailing bytes"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(revision: &str) -> VectorSpaceDescriptor {
        VectorSpaceDescriptor::external(
            "test-provider",
            "test-model",
            revision,
            "utf8-v1",
            3,
            VectorNormalization::None,
        )
    }

    #[test]
    fn descriptor_space_id_is_deterministic_and_revision_bound() {
        let first = descriptor("r1");
        let second = descriptor("r1");
        let third = descriptor("r2");
        assert_eq!(first.space_id().unwrap(), second.space_id().unwrap());
        assert_ne!(first.space_id().unwrap(), third.space_id().unwrap());
    }

    #[test]
    fn exact_cosine_and_tie_order_are_deterministic() {
        let query = [1.0f32, 0.0, 0.0];
        let left = [1.0f32, 1.0, 0.0];
        let right = [1.0f32, -1.0, 0.0];
        let query_norm = squared_norm(&query);
        let left_score = cosine_with_query_norm(&query, query_norm, &left);
        let right_score = cosine_with_query_norm(&query, query_norm, &right);
        assert_eq!(left_score.to_bits(), right_score.to_bits());

        let mut rows = vec![
            ("b".to_string(), right_score),
            ("a".to_string(), left_score),
        ];
        rows.sort_by(|left, right| match right.1.total_cmp(&left.1) {
            Ordering::Equal => left.0.cmp(&right.0),
            ordering => ordering,
        });
        assert_eq!(rows[0].0, "a");
        assert_eq!(rows[1].0, "b");
    }

    #[test]
    fn invalid_vectors_are_rejected() {
        assert!(validate_vector(&[0.0, 0.0], 2).is_err());
        assert!(validate_vector(&[f32::NAN, 1.0], 2).is_err());
        assert!(validate_vector(&[1.0], 2).is_err());
    }

    #[test]
    fn registry_and_column_round_trip() {
        let descriptor = descriptor("r1");
        let space_id = descriptor.space_id().unwrap();
        let mut registry = BTreeMap::new();
        registry.insert(space_id, descriptor.clone());
        let encoded = encode_registry(&registry).unwrap();
        assert_eq!(decode_registry(&encoded).unwrap(), registry);

        let mut column = VectorColumn::empty(space_id, 3);
        assert_eq!(
            column.upsert("record-a".to_string(), &[1.0, 0.0, 0.0],),
            PutVectorOutcome::Inserted
        );
        column.generation = 1;
        let encoded = encode_column(&column).unwrap();
        let decoded = decode_column(&encoded).unwrap();
        assert_eq!(decoded.space_id, space_id);
        assert_eq!(decoded.record_ids, vec!["record-a"]);
        assert!(vector_bits_equal(&decoded.vectors, &[1.0, 0.0, 0.0]));
    }
}

mod gpu_router;
pub use gpu_router::*;

mod hybrid;
pub use hybrid::*;
