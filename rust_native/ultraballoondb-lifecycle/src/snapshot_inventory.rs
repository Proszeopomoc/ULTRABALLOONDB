use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use ultraballoondb_storage::{hex_digest, sha256, sha256_file, StorageError};

use crate::{DatabaseEdge, DatabaseRecord, DurableDatabase, DurableResult};

pub const READ_SNAPSHOT_MAGIC: [u8; 8] = *b"UBRDS01\0";
pub const READ_SNAPSHOT_FORMAT_VERSION: u16 = 1;
pub const DERIVED_INVENTORY_MAGIC: [u8; 8] = *b"UBDAI01\0";
pub const DERIVED_INVENTORY_FORMAT_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadSnapshotDescriptor {
    pub format_version: u16,
    pub checkpoint_generation: u64,
    pub committed_transaction_count: u64,
    pub record_count: u64,
    pub edge_count: u64,
    pub state_sha256: [u8; 32],
    pub snapshot_sha256: [u8; 32],
}

impl ReadSnapshotDescriptor {
    fn capture(database: &DurableDatabase) -> Self {
        let state_sha256 = database.state_sha256();
        let (record_count, edge_count) = database.state_counts();
        let checkpoint_generation = database.checkpoint_generation();
        let committed_transaction_count = database.committed_transaction_count();

        let mut preimage = Vec::with_capacity(98);
        preimage.extend_from_slice(&READ_SNAPSHOT_MAGIC);
        preimage.extend_from_slice(&READ_SNAPSHOT_FORMAT_VERSION.to_le_bytes());
        preimage.extend_from_slice(&0u16.to_le_bytes());
        preimage.extend_from_slice(&committed_transaction_count.to_le_bytes());
        preimage.extend_from_slice(&record_count.to_le_bytes());
        preimage.extend_from_slice(&edge_count.to_le_bytes());
        preimage.extend_from_slice(&state_sha256);
        let snapshot_sha256 = sha256(&preimage);

        Self {
            format_version: READ_SNAPSHOT_FORMAT_VERSION,
            checkpoint_generation,
            committed_transaction_count,
            record_count,
            edge_count,
            state_sha256,
            snapshot_sha256,
        }
    }

    pub fn snapshot_sha256_hex(&self) -> String {
        hex_digest(&self.snapshot_sha256)
    }

    pub fn state_sha256_hex(&self) -> String {
        hex_digest(&self.state_sha256)
    }
}

pub struct ReadSnapshot<'a> {
    database: &'a DurableDatabase,
    descriptor: ReadSnapshotDescriptor,
}

impl<'a> ReadSnapshot<'a> {
    fn new(database: &'a DurableDatabase) -> Self {
        Self {
            database,
            descriptor: ReadSnapshotDescriptor::capture(database),
        }
    }

    pub fn descriptor(&self) -> &ReadSnapshotDescriptor {
        &self.descriptor
    }

    pub fn record(&self, record_id: &str) -> DurableResult<Option<DatabaseRecord>> {
        self.database.record(record_id)
    }

    pub fn records(&self) -> DurableResult<Vec<DatabaseRecord>> {
        self.database.records()
    }

    pub fn edge(
        &self,
        src: u64,
        dst: u64,
        edge_type: u32,
        weight: f64,
    ) -> DurableResult<Option<DatabaseEdge>> {
        self.database.edge(src, dst, edge_type, weight)
    }

    pub fn edges(&self) -> DurableResult<Vec<DatabaseEdge>> {
        self.database.edges()
    }
}

impl DurableDatabase {
    pub fn read_snapshot(&self) -> ReadSnapshot<'_> {
        ReadSnapshot::new(self)
    }
}

#[derive(Debug)]
pub enum DerivedInventoryError {
    Io(std::io::Error),
    Storage(StorageError),
    Invalid(String),
    Corrupt(String),
    Conflict(String),
}

impl fmt::Display for DerivedInventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Storage(error) => {
                write!(f, "storage error: {error}")
            }
            Self::Invalid(message) => {
                write!(f, "invalid derived inventory: {message}")
            }
            Self::Corrupt(message) => {
                write!(f, "corrupt derived inventory: {message}")
            }
            Self::Conflict(message) => {
                write!(f, "derived inventory conflict: {message}")
            }
        }
    }
}

impl std::error::Error for DerivedInventoryError {}

impl From<std::io::Error> for DerivedInventoryError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<StorageError> for DerivedInventoryError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

pub type DerivedInventoryResult<T> = std::result::Result<T, DerivedInventoryError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum DerivedArtifactKind {
    HotSnapshot = 1,
    Crystallization = 2,
    FloatingSubgraph = 3,
    VectorColumn = 4,
    VectorIndex = 5,
    GpuSnapshot = 6,
}

impl DerivedArtifactKind {
    pub const fn code(self) -> u16 {
        self as u16
    }

    fn from_code(value: u16) -> DerivedInventoryResult<Self> {
        match value {
            1 => Ok(Self::HotSnapshot),
            2 => Ok(Self::Crystallization),
            3 => Ok(Self::FloatingSubgraph),
            4 => Ok(Self::VectorColumn),
            5 => Ok(Self::VectorIndex),
            6 => Ok(Self::GpuSnapshot),
            _ => Err(DerivedInventoryError::Corrupt(format!(
                "unknown artifact kind {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum DerivedArtifactState {
    Complete = 1,
    Invalidated = 2,
}

impl DerivedArtifactState {
    pub const fn code(self) -> u16 {
        self as u16
    }

    fn from_code(value: u16) -> DerivedInventoryResult<Self> {
        match value {
            1 => Ok(Self::Complete),
            2 => Ok(Self::Invalidated),
            _ => Err(DerivedInventoryError::Corrupt(format!(
                "unknown artifact state {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedArtifactRecord {
    pub artifact_id: [u8; 32],
    pub kind: DerivedArtifactKind,
    pub state: DerivedArtifactState,
    pub generation: u64,
    pub source_snapshot_sha256: [u8; 32],
    pub artifact_sha256: [u8; 32],
    pub relative_path: String,
    pub item_count: u64,
    pub byte_count: u64,
}

impl DerivedArtifactRecord {
    pub fn artifact_id_hex(&self) -> String {
        hex_digest(&self.artifact_id)
    }

    pub fn source_snapshot_sha256_hex(&self) -> String {
        hex_digest(&self.source_snapshot_sha256)
    }

    pub fn artifact_sha256_hex(&self) -> String {
        hex_digest(&self.artifact_sha256)
    }

    pub fn is_compatible(&self, snapshot: &ReadSnapshotDescriptor) -> bool {
        self.state == DerivedArtifactState::Complete
            && self.source_snapshot_sha256 == snapshot.snapshot_sha256
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterOutcome {
    Registered,
    DuplicateIgnored,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedInventoryVerification {
    pub total_records: u64,
    pub complete_records: u64,
    pub invalidated_records: u64,
    pub verified_files: u64,
    pub inventory_sha256: [u8; 32],
}

impl DerivedInventoryVerification {
    pub fn inventory_sha256_hex(&self) -> String {
        hex_digest(&self.inventory_sha256)
    }
}

#[derive(Debug)]
pub struct DerivedArtifactInventory {
    root: PathBuf,
    path: PathBuf,
    records: BTreeMap<[u8; 32], DerivedArtifactRecord>,
}

impl DerivedArtifactInventory {
    pub fn create(root: impl AsRef<Path>) -> DerivedInventoryResult<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("derived"))?;
        let path = inventory_path(&root);
        let backup = backup_path(&path);
        let temporary = temporary_path(&path);
        if path.exists() || backup.exists() || temporary.exists() {
            return Err(DerivedInventoryError::Conflict(
                "derived inventory already exists".to_string(),
            ));
        }
        let inventory = Self {
            root,
            path,
            records: BTreeMap::new(),
        };
        inventory.persist()?;
        Ok(inventory)
    }

    pub fn open(root: impl AsRef<Path>) -> DerivedInventoryResult<Self> {
        let root = root.as_ref().to_path_buf();
        let path = inventory_path(&root);
        recover_inventory_files(&path)?;
        let mut bytes = Vec::new();
        File::open(&path)?.read_to_end(&mut bytes)?;
        let records = decode_inventory(&bytes)?;
        Ok(Self {
            root,
            path,
            records,
        })
    }

    pub fn open_or_create(root: impl AsRef<Path>) -> DerivedInventoryResult<Self> {
        let root = root.as_ref().to_path_buf();
        let path = inventory_path(&root);
        if path.exists() || backup_path(&path).exists() || temporary_path(&path).exists() {
            Self::open(root)
        } else {
            Self::create(root)
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn records(&self) -> impl Iterator<Item = &DerivedArtifactRecord> {
        self.records.values()
    }

    pub fn record(&self, artifact_id: &[u8; 32]) -> Option<&DerivedArtifactRecord> {
        self.records.get(artifact_id)
    }

    pub fn register_complete_file(
        &mut self,
        kind: DerivedArtifactKind,
        generation: u64,
        snapshot: &ReadSnapshotDescriptor,
        relative_path: impl AsRef<Path>,
        item_count: u64,
    ) -> DerivedInventoryResult<RegisterOutcome> {
        let relative_path = relative_path.as_ref();
        validate_relative_path(relative_path)?;
        let relative_path_text = relative_path
            .to_str()
            .ok_or_else(|| {
                DerivedInventoryError::Invalid("artifact path is not UTF-8".to_string())
            })?
            .replace('\\', "/");
        let absolute_path = self.root.join(relative_path);
        let metadata = fs::symlink_metadata(&absolute_path)?;
        if metadata.file_type().is_symlink() {
            return Err(DerivedInventoryError::Invalid(
                "artifact path cannot be a symlink".to_string(),
            ));
        }
        if !metadata.is_file() {
            return Err(DerivedInventoryError::Invalid(
                "artifact path is not a regular file".to_string(),
            ));
        }
        let artifact_sha256 = sha256_file(&absolute_path)?;
        let artifact_id = derive_artifact_id(
            kind,
            generation,
            snapshot.snapshot_sha256,
            &relative_path_text,
        );
        let record = DerivedArtifactRecord {
            artifact_id,
            kind,
            state: DerivedArtifactState::Complete,
            generation,
            source_snapshot_sha256: snapshot.snapshot_sha256,
            artifact_sha256,
            relative_path: relative_path_text,
            item_count,
            byte_count: metadata.len(),
        };
        validate_record(&record)?;

        if let Some(existing) = self.records.get(&artifact_id) {
            if existing == &record {
                return Ok(RegisterOutcome::DuplicateIgnored);
            }
            return Err(DerivedInventoryError::Conflict(format!(
                "artifact ID {} already has different metadata",
                hex_digest(&artifact_id)
            )));
        }

        self.records.insert(artifact_id, record);
        self.persist()?;
        Ok(RegisterOutcome::Registered)
    }

    pub fn invalidate(&mut self, artifact_id: &[u8; 32]) -> DerivedInventoryResult<bool> {
        let Some(record) = self.records.get_mut(artifact_id) else {
            return Ok(false);
        };
        if record.state == DerivedArtifactState::Invalidated {
            return Ok(false);
        }
        record.state = DerivedArtifactState::Invalidated;
        self.persist()?;
        Ok(true)
    }

    pub fn invalidate_stale(
        &mut self,
        snapshot: &ReadSnapshotDescriptor,
    ) -> DerivedInventoryResult<u64> {
        let mut changed = 0u64;
        for record in self.records.values_mut() {
            if record.state == DerivedArtifactState::Complete
                && record.source_snapshot_sha256 != snapshot.snapshot_sha256
            {
                record.state = DerivedArtifactState::Invalidated;
                changed = changed.saturating_add(1);
            }
        }
        if changed > 0 {
            self.persist()?;
        }
        Ok(changed)
    }

    pub fn compatible_complete(
        &self,
        snapshot: &ReadSnapshotDescriptor,
        kind: DerivedArtifactKind,
    ) -> Vec<DerivedArtifactRecord> {
        self.records
            .values()
            .filter(|record| record.kind == kind && record.is_compatible(snapshot))
            .cloned()
            .collect()
    }

    pub fn verify_files(&self) -> DerivedInventoryResult<DerivedInventoryVerification> {
        let mut complete_records = 0u64;
        let mut invalidated_records = 0u64;
        let mut verified_files = 0u64;

        for record in self.records.values() {
            validate_record(record)?;
            match record.state {
                DerivedArtifactState::Complete => {
                    complete_records = complete_records.saturating_add(1);
                    let relative = Path::new(&record.relative_path);
                    validate_relative_path(relative)?;
                    let absolute = self.root.join(relative);
                    let metadata = fs::symlink_metadata(&absolute)?;
                    if metadata.file_type().is_symlink() || !metadata.is_file() {
                        return Err(DerivedInventoryError::Corrupt(format!(
                            "complete artifact is not a regular file: {}",
                            record.relative_path
                        )));
                    }
                    if metadata.len() != record.byte_count {
                        return Err(DerivedInventoryError::Corrupt(format!(
                            "artifact byte count mismatch: {}",
                            record.relative_path
                        )));
                    }
                    if sha256_file(&absolute)? != record.artifact_sha256 {
                        return Err(DerivedInventoryError::Corrupt(format!(
                            "artifact SHA mismatch: {}",
                            record.relative_path
                        )));
                    }
                    verified_files = verified_files.saturating_add(1);
                }
                DerivedArtifactState::Invalidated => {
                    invalidated_records = invalidated_records.saturating_add(1);
                }
            }
        }

        Ok(DerivedInventoryVerification {
            total_records: self.records.len() as u64,
            complete_records,
            invalidated_records,
            verified_files,
            inventory_sha256: sha256_file(&self.path)?,
        })
    }

    pub fn inventory_sha256(&self) -> DerivedInventoryResult<[u8; 32]> {
        Ok(sha256_file(&self.path)?)
    }

    fn persist(&self) -> DerivedInventoryResult<()> {
        let bytes = encode_inventory(&self.records)?;
        let temporary = temporary_path(&self.path);
        let backup = backup_path(&self.path);

        if temporary.exists() {
            fs::remove_file(&temporary)?;
        }
        if backup.exists() {
            fs::remove_file(&backup)?;
        }

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);

        if self.path.exists() {
            fs::rename(&self.path, &backup)?;
        }

        if let Err(error) = fs::rename(&temporary, &self.path) {
            if backup.exists() && !self.path.exists() {
                let _ = fs::rename(&backup, &self.path);
            }
            return Err(DerivedInventoryError::Io(error));
        }

        if backup.exists() {
            fs::remove_file(backup)?;
        }
        Ok(())
    }
}

pub fn derive_artifact_id(
    kind: DerivedArtifactKind,
    generation: u64,
    source_snapshot_sha256: [u8; 32],
    relative_path: &str,
) -> [u8; 32] {
    let path_bytes = relative_path.as_bytes();
    let mut preimage = Vec::with_capacity(54usize.saturating_add(path_bytes.len()));
    preimage.extend_from_slice(b"UBDAID01");
    preimage.extend_from_slice(&kind.code().to_le_bytes());
    preimage.extend_from_slice(&generation.to_le_bytes());
    preimage.extend_from_slice(&source_snapshot_sha256);
    preimage.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
    preimage.extend_from_slice(path_bytes);
    sha256(&preimage)
}

fn inventory_path(root: &Path) -> PathBuf {
    root.join("derived").join("INVENTORY.ubdai")
}

fn backup_path(path: &Path) -> PathBuf {
    path.with_extension("ubdai.bak")
}

fn temporary_path(path: &Path) -> PathBuf {
    path.with_extension("ubdai.tmp")
}

fn recover_inventory_files(path: &Path) -> DerivedInventoryResult<()> {
    let backup = backup_path(path);
    let temporary = temporary_path(path);

    if !path.exists() {
        if backup.exists() {
            fs::rename(&backup, path)?;
        } else if temporary.exists() {
            fs::rename(&temporary, path)?;
        }
    }

    if !path.exists() {
        return Err(DerivedInventoryError::Invalid(
            "derived inventory does not exist".to_string(),
        ));
    }

    if backup.exists() {
        fs::remove_file(backup)?;
    }
    if temporary.exists() {
        fs::remove_file(temporary)?;
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> DerivedInventoryResult<()> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(DerivedInventoryError::Invalid(
            "artifact path must be non-empty and relative".to_string(),
        ));
    }
    if !path
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(DerivedInventoryError::Invalid(
            "artifact path contains a non-normal component".to_string(),
        ));
    }
    Ok(())
}

fn validate_record(record: &DerivedArtifactRecord) -> DerivedInventoryResult<()> {
    validate_relative_path(Path::new(&record.relative_path))?;
    let expected = derive_artifact_id(
        record.kind,
        record.generation,
        record.source_snapshot_sha256,
        &record.relative_path,
    );
    if expected != record.artifact_id {
        return Err(DerivedInventoryError::Corrupt(
            "artifact ID does not match record fields".to_string(),
        ));
    }
    Ok(())
}

fn encode_inventory(
    records: &BTreeMap<[u8; 32], DerivedArtifactRecord>,
) -> DerivedInventoryResult<Vec<u8>> {
    let mut body = Vec::new();
    body.extend_from_slice(&DERIVED_INVENTORY_MAGIC);
    body.extend_from_slice(&DERIVED_INVENTORY_FORMAT_VERSION.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&(records.len() as u64).to_le_bytes());

    for record in records.values() {
        validate_record(record)?;
        let path_bytes = record.relative_path.as_bytes();
        let path_length = u32::try_from(path_bytes.len())
            .map_err(|_| DerivedInventoryError::Invalid("artifact path is too long".to_string()))?;
        body.extend_from_slice(&record.kind.code().to_le_bytes());
        body.extend_from_slice(&record.state.code().to_le_bytes());
        body.extend_from_slice(&record.generation.to_le_bytes());
        body.extend_from_slice(&record.item_count.to_le_bytes());
        body.extend_from_slice(&record.byte_count.to_le_bytes());
        body.extend_from_slice(&record.source_snapshot_sha256);
        body.extend_from_slice(&record.artifact_sha256);
        body.extend_from_slice(&record.artifact_id);
        body.extend_from_slice(&path_length.to_le_bytes());
        body.extend_from_slice(path_bytes);
    }

    let body_sha256 = sha256(&body);
    body.extend_from_slice(&body_sha256);
    Ok(body)
}

fn decode_inventory(
    bytes: &[u8],
) -> DerivedInventoryResult<BTreeMap<[u8; 32], DerivedArtifactRecord>> {
    const MINIMUM_SIZE: usize = 8 + 2 + 2 + 8 + 32;
    if bytes.len() < MINIMUM_SIZE {
        return Err(DerivedInventoryError::Corrupt(
            "inventory is truncated".to_string(),
        ));
    }
    let body_length = bytes.len() - 32;
    let (body, footer) = bytes.split_at(body_length);
    let expected_footer = sha256(body);
    if expected_footer.as_slice() != footer {
        return Err(DerivedInventoryError::Corrupt(
            "inventory SHA footer mismatch".to_string(),
        ));
    }

    let mut cursor = 0usize;
    let magic = take(body, &mut cursor, 8)?;
    if magic != DERIVED_INVENTORY_MAGIC.as_slice() {
        return Err(DerivedInventoryError::Corrupt(
            "inventory magic mismatch".to_string(),
        ));
    }
    let version = read_u16(body, &mut cursor)?;
    if version != DERIVED_INVENTORY_FORMAT_VERSION {
        return Err(DerivedInventoryError::Corrupt(format!(
            "unsupported inventory version {version}"
        )));
    }
    let reserved = read_u16(body, &mut cursor)?;
    if reserved != 0 {
        return Err(DerivedInventoryError::Corrupt(
            "inventory reserved field is non-zero".to_string(),
        ));
    }
    let count = read_u64(body, &mut cursor)?;
    let capacity = usize::try_from(count).map_err(|_| {
        DerivedInventoryError::Corrupt("inventory count does not fit usize".to_string())
    })?;
    let mut records = BTreeMap::new();

    for _ in 0..capacity {
        let kind = DerivedArtifactKind::from_code(read_u16(body, &mut cursor)?)?;
        let state = DerivedArtifactState::from_code(read_u16(body, &mut cursor)?)?;
        let generation = read_u64(body, &mut cursor)?;
        let item_count = read_u64(body, &mut cursor)?;
        let byte_count = read_u64(body, &mut cursor)?;
        let source_snapshot_sha256 = read_array_32(body, &mut cursor)?;
        let artifact_sha256 = read_array_32(body, &mut cursor)?;
        let artifact_id = read_array_32(body, &mut cursor)?;
        let path_length = read_u32(body, &mut cursor)? as usize;
        let path_bytes = take(body, &mut cursor, path_length)?;
        let relative_path = String::from_utf8(path_bytes.to_vec()).map_err(|_| {
            DerivedInventoryError::Corrupt("artifact path is not UTF-8".to_string())
        })?;
        let record = DerivedArtifactRecord {
            artifact_id,
            kind,
            state,
            generation,
            source_snapshot_sha256,
            artifact_sha256,
            relative_path,
            item_count,
            byte_count,
        };
        validate_record(&record)?;
        if records.insert(artifact_id, record).is_some() {
            return Err(DerivedInventoryError::Corrupt(
                "duplicate artifact ID".to_string(),
            ));
        }
    }

    if cursor != body.len() {
        return Err(DerivedInventoryError::Corrupt(
            "inventory has trailing bytes".to_string(),
        ));
    }
    Ok(records)
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> DerivedInventoryResult<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| DerivedInventoryError::Corrupt("inventory offset overflow".to_string()))?;
    if end > bytes.len() {
        return Err(DerivedInventoryError::Corrupt(
            "inventory field is truncated".to_string(),
        ));
    }
    let value = &bytes[*cursor..end];
    *cursor = end;
    Ok(value)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> DerivedInventoryResult<u16> {
    let mut value = [0u8; 2];
    value.copy_from_slice(take(bytes, cursor, 2)?);
    Ok(u16::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> DerivedInventoryResult<u32> {
    let mut value = [0u8; 4];
    value.copy_from_slice(take(bytes, cursor, 4)?);
    Ok(u32::from_le_bytes(value))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> DerivedInventoryResult<u64> {
    let mut value = [0u8; 8];
    value.copy_from_slice(take(bytes, cursor, 8)?);
    Ok(u64::from_le_bytes(value))
}

fn read_array_32(bytes: &[u8], cursor: &mut usize) -> DerivedInventoryResult<[u8; 32]> {
    let mut value = [0u8; 32];
    value.copy_from_slice(take(bytes, cursor, 32)?);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BatchLimits, TransactionCore, TransactionId, TransactionState};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_root(name: &str) -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "ultraballoondb-r4-1b-{name}-{}-{counter}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        root
    }

    fn commit_record(
        database: &mut DurableDatabase,
        seed: u8,
        logical_id: u64,
        record_id: &str,
        node_id: u64,
        generation: u64,
        sequence: u64,
    ) {
        let transaction_id = TransactionId::new([seed; 16]);
        let mut transaction = TransactionCore::new(BatchLimits::default());
        transaction.begin(transaction_id).unwrap();
        transaction
            .put_record(logical_id, record_id, node_id, record_id.as_bytes())
            .unwrap();
        transaction.prepare().unwrap();
        let receipt = transaction
            .commit_durable(database, generation, sequence)
            .unwrap();
        assert!(receipt.durable_commit);
        assert_eq!(
            transaction.release_terminal(transaction_id).unwrap(),
            TransactionState::DurableCommitted
        );
    }

    #[test]
    fn read_snapshot_is_stable_and_changes_with_state() {
        let root = test_root("snapshot");
        let mut database = DurableDatabase::create(&root).unwrap();

        let empty = {
            let snapshot = database.read_snapshot();
            assert_eq!(snapshot.records().unwrap().len(), 0);
            snapshot.descriptor().clone()
        };

        commit_record(&mut database, 1, 1, "alpha", 10, 1, 1);

        let populated = {
            let snapshot = database.read_snapshot();
            assert!(snapshot.record("alpha").unwrap().is_some());
            assert_eq!(snapshot.records().unwrap().len(), 1);
            snapshot.descriptor().clone()
        };

        assert_ne!(empty.snapshot_sha256, populated.snapshot_sha256);
        assert_eq!(populated.record_count, 1);
        assert_eq!(populated.edge_count, 0);

        database.checkpoint(2).unwrap();
        drop(database);
        let reopened = DurableDatabase::open(&root, false).unwrap();
        let after_restart = reopened.read_snapshot().descriptor().clone();
        assert_eq!(populated.snapshot_sha256, after_restart.snapshot_sha256);
        assert_eq!(populated.state_sha256, after_restart.state_sha256);
        drop(reopened);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inventory_registers_verifies_and_invalidates_stale() {
        let root = test_root("inventory");
        let mut database = DurableDatabase::create(&root).unwrap();
        commit_record(&mut database, 2, 1, "alpha", 10, 1, 1);
        let first_snapshot = database.read_snapshot().descriptor().clone();

        let artifact_relative = PathBuf::from("artifacts/crystallization.bin");
        let artifact_absolute = root.join(&artifact_relative);
        fs::create_dir_all(artifact_absolute.parent().unwrap()).unwrap();
        fs::write(&artifact_absolute, b"crystallized-alpha").unwrap();

        let mut inventory = DerivedArtifactInventory::create(&root).unwrap();
        assert_eq!(
            inventory
                .register_complete_file(
                    DerivedArtifactKind::Crystallization,
                    1,
                    &first_snapshot,
                    &artifact_relative,
                    1,
                )
                .unwrap(),
            RegisterOutcome::Registered
        );
        assert_eq!(
            inventory
                .register_complete_file(
                    DerivedArtifactKind::Crystallization,
                    1,
                    &first_snapshot,
                    &artifact_relative,
                    1,
                )
                .unwrap(),
            RegisterOutcome::DuplicateIgnored
        );
        let verification = inventory.verify_files().unwrap();
        assert_eq!(verification.total_records, 1);
        assert_eq!(verification.complete_records, 1);
        assert_eq!(verification.verified_files, 1);
        drop(inventory);

        let mut reopened = DerivedArtifactInventory::open(&root).unwrap();
        assert_eq!(
            reopened
                .compatible_complete(&first_snapshot, DerivedArtifactKind::Crystallization,)
                .len(),
            1
        );

        commit_record(&mut database, 3, 2, "beta", 20, 2, 2);
        let second_snapshot = database.read_snapshot().descriptor().clone();
        assert_ne!(
            first_snapshot.snapshot_sha256,
            second_snapshot.snapshot_sha256
        );
        assert_eq!(reopened.invalidate_stale(&second_snapshot).unwrap(), 1);
        assert_eq!(
            reopened
                .compatible_complete(&second_snapshot, DerivedArtifactKind::Crystallization,)
                .len(),
            0
        );
        let verification = reopened.verify_files().unwrap();
        assert_eq!(verification.invalidated_records, 1);
        drop(reopened);
        drop(database);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inventory_recovers_backup_and_rejects_corruption() {
        let root = test_root("recovery");
        let inventory = DerivedArtifactInventory::create(&root).unwrap();
        let path = inventory.path().to_path_buf();
        drop(inventory);

        let backup = backup_path(&path);
        fs::rename(&path, &backup).unwrap();
        let recovered = DerivedArtifactInventory::open(&root).unwrap();
        assert!(recovered.path().is_file());
        drop(recovered);

        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 0xFF;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            DerivedArtifactInventory::open(&root),
            Err(DerivedInventoryError::Corrupt(_))
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_artifact_paths_are_rejected() {
        let root = test_root("paths");
        let database = DurableDatabase::create(&root).unwrap();
        let snapshot = database.read_snapshot().descriptor().clone();
        let mut inventory = DerivedArtifactInventory::create(&root).unwrap();

        assert!(matches!(
            inventory.register_complete_file(
                DerivedArtifactKind::Crystallization,
                1,
                &snapshot,
                Path::new("../escape.bin"),
                0,
            ),
            Err(DerivedInventoryError::Invalid(_))
        ));
        drop(inventory);
        drop(database);

        fs::remove_dir_all(root).unwrap();
    }
}
