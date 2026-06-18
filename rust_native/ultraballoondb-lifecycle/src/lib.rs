use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use ultraballoondb_storage::{
    hex_digest, sha256, sha256_file, IntegrityReport, PageStore, RecordKind,
    SegmentEntry, StorageError,
};

pub const BATCH_DIGEST_MAGIC: [u8; 8] = *b"UBTXB01\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionState {
    Active,
    Prepared,
    ShadowMaterialized,
    Aborted,
}

impl TransactionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Prepared => "PREPARED",
            Self::ShadowMaterialized => "SHADOW_MATERIALIZED",
            Self::Aborted => "ABORTED",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::ShadowMaterialized | Self::Aborted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransactionId([u8; 16]);

impl TransactionId {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }

    pub fn to_hex(self) -> String {
        let mut output = String::with_capacity(32);
        for byte in self.0 {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02X}")
                .expect("writing to String cannot fail");
        }
        output
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchLimits {
    pub max_operations: usize,
    pub max_payload_bytes: u64,
}

impl Default for BatchLimits {
    fn default() -> Self {
        Self {
            max_operations: 100_000,
            max_payload_bytes: 256 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddOutcome {
    Added,
    DuplicateIgnored,
}

#[derive(Debug)]
pub enum TransactionError {
    Storage(StorageError),
    InvalidState {
        operation: &'static str,
        actual: TransactionState,
    },
    WriterAlreadyActive(TransactionId),
    NoActiveTransaction,
    TransactionIdMismatch {
        expected: TransactionId,
        actual: TransactionId,
    },
    Conflict(String),
    LimitExceeded {
        limit: &'static str,
        maximum: u64,
        attempted: u64,
    },
    InvalidInput(String),
    Integrity(String),
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "storage error: {error}"),
            Self::InvalidState { operation, actual } => write!(
                f,
                "operation {operation} is invalid in state {}",
                actual.as_str()
            ),
            Self::WriterAlreadyActive(transaction_id) => write!(
                f,
                "single writer already active: {}",
                transaction_id.to_hex()
            ),
            Self::NoActiveTransaction => write!(f, "no active transaction"),
            Self::TransactionIdMismatch { expected, actual } => write!(
                f,
                "transaction ID mismatch expected={} actual={}",
                expected.to_hex(),
                actual.to_hex()
            ),
            Self::Conflict(message) => write!(f, "write batch conflict: {message}"),
            Self::LimitExceeded {
                limit,
                maximum,
                attempted,
            } => write!(
                f,
                "write batch limit exceeded {limit}: maximum={maximum} attempted={attempted}"
            ),
            Self::InvalidInput(message) => write!(f, "invalid input: {message}"),
            Self::Integrity(message) => write!(f, "integrity error: {message}"),
        }
    }
}

impl std::error::Error for TransactionError {}

impl From<StorageError> for TransactionError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

pub type Result<T> = std::result::Result<T, TransactionError>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum DomainKey {
    Record(String),
    Edge {
        src: u64,
        dst: u64,
        edge_type: u32,
        weight_bits: u64,
    },
}

#[derive(Clone, Debug)]
pub struct PreparedBatch {
    transaction_id: TransactionId,
    entries: Vec<SegmentEntry>,
    batch_digest: [u8; 32],
    total_payload_bytes: u64,
}

impl PreparedBatch {
    pub fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    pub fn entries(&self) -> &[SegmentEntry] {
        &self.entries
    }

    pub fn operation_count(&self) -> usize {
        self.entries.len()
    }

    pub fn total_payload_bytes(&self) -> u64 {
        self.total_payload_bytes
    }

    pub fn batch_digest(&self) -> [u8; 32] {
        self.batch_digest
    }

    pub fn batch_digest_hex(&self) -> String {
        hex_digest(&self.batch_digest)
    }
}

#[derive(Clone, Debug)]
pub struct WriteBatch {
    entries: Vec<SegmentEntry>,
    logical_fingerprints: BTreeMap<u64, [u8; 32]>,
    domain_fingerprints: BTreeMap<DomainKey, [u8; 32]>,
    total_payload_bytes: u64,
    limits: BatchLimits,
}

impl WriteBatch {
    pub fn new(limits: BatchLimits) -> Self {
        Self {
            entries: Vec::new(),
            logical_fingerprints: BTreeMap::new(),
            domain_fingerprints: BTreeMap::new(),
            total_payload_bytes: 0,
            limits,
        }
    }

    pub fn operation_count(&self) -> usize {
        self.entries.len()
    }

    pub fn total_payload_bytes(&self) -> u64 {
        self.total_payload_bytes
    }

    pub fn entries(&self) -> &[SegmentEntry] {
        &self.entries
    }

    pub fn put_record(
        &mut self,
        logical_id: u64,
        record_id: &str,
        node_id: u64,
        user_payload: &[u8],
    ) -> Result<AddOutcome> {
        let entry = SegmentEntry::record(
            logical_id,
            record_id,
            node_id,
            user_payload,
        )?;
        self.add_entry(
            DomainKey::Record(record_id.to_string()),
            entry,
        )
    }

    pub fn delete_record(
        &mut self,
        logical_id: u64,
        record_id: &str,
    ) -> Result<AddOutcome> {
        if record_id.is_empty() {
            return Err(TransactionError::InvalidInput(
                "record_id cannot be empty".to_string(),
            ));
        }
        let record_id_bytes = record_id.as_bytes();
        let record_id_len = u32::try_from(record_id_bytes.len())
            .map_err(|_| TransactionError::InvalidInput(
                "record_id too long".to_string()
            ))?;
        let mut payload = Vec::with_capacity(8 + record_id_bytes.len());
        payload.extend_from_slice(&record_id_len.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(record_id_bytes);
        let entry = SegmentEntry::new(
            RecordKind::RecordTombstone,
            logical_id,
            payload,
        )?;
        self.add_entry(
            DomainKey::Record(record_id.to_string()),
            entry,
        )
    }

    pub fn put_edge(
        &mut self,
        logical_id: u64,
        src: u64,
        dst: u64,
        edge_type: u32,
        weight: f64,
    ) -> Result<AddOutcome> {
        let canonical_weight = canonical_weight(weight)?;
        let entry = SegmentEntry::typed_edge(
            logical_id,
            src,
            dst,
            edge_type,
            canonical_weight,
        )?;
        self.add_entry(
            DomainKey::Edge {
                src,
                dst,
                edge_type,
                weight_bits: canonical_weight.to_bits(),
            },
            entry,
        )
    }

    pub fn delete_edge(
        &mut self,
        logical_id: u64,
        src: u64,
        dst: u64,
        edge_type: u32,
        weight: f64,
    ) -> Result<AddOutcome> {
        let canonical_weight = canonical_weight(weight)?;
        let mut payload = Vec::with_capacity(32);
        payload.extend_from_slice(&src.to_le_bytes());
        payload.extend_from_slice(&dst.to_le_bytes());
        payload.extend_from_slice(&edge_type.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(
            &canonical_weight.to_bits().to_le_bytes(),
        );
        let entry = SegmentEntry::new(
            RecordKind::EdgeTombstone,
            logical_id,
            payload,
        )?;
        self.add_entry(
            DomainKey::Edge {
                src,
                dst,
                edge_type,
                weight_bits: canonical_weight.to_bits(),
            },
            entry,
        )
    }

    pub fn prepare(
        &self,
        transaction_id: TransactionId,
    ) -> PreparedBatch {
        let batch_digest = batch_digest(
            transaction_id,
            &self.entries,
            self.total_payload_bytes,
        );
        PreparedBatch {
            transaction_id,
            entries: self.entries.clone(),
            batch_digest,
            total_payload_bytes: self.total_payload_bytes,
        }
    }

    fn add_entry(
        &mut self,
        domain_key: DomainKey,
        entry: SegmentEntry,
    ) -> Result<AddOutcome> {
        let fingerprint = operation_fingerprint(&entry);

        if let Some(existing) = self.logical_fingerprints.get(
            &entry.logical_id
        ) {
            if existing == &fingerprint {
                return Ok(AddOutcome::DuplicateIgnored);
            }
            return Err(TransactionError::Conflict(format!(
                "logical_id {} already belongs to a different operation",
                entry.logical_id
            )));
        }

        if let Some(existing) = self.domain_fingerprints.get(&domain_key) {
            if existing == &fingerprint {
                return Ok(AddOutcome::DuplicateIgnored);
            }
            return Err(TransactionError::Conflict(
                "domain key already has a different operation".to_string(),
            ));
        }

        let attempted_operations = self
            .entries
            .len()
            .checked_add(1)
            .ok_or(TransactionError::LimitExceeded {
                limit: "max_operations",
                maximum: self.limits.max_operations as u64,
                attempted: u64::MAX,
            })?;
        if attempted_operations > self.limits.max_operations {
            return Err(TransactionError::LimitExceeded {
                limit: "max_operations",
                maximum: self.limits.max_operations as u64,
                attempted: attempted_operations as u64,
            });
        }

        let attempted_payload = self
            .total_payload_bytes
            .checked_add(entry.payload.len() as u64)
            .ok_or(TransactionError::LimitExceeded {
                limit: "max_payload_bytes",
                maximum: self.limits.max_payload_bytes,
                attempted: u64::MAX,
            })?;
        if attempted_payload > self.limits.max_payload_bytes {
            return Err(TransactionError::LimitExceeded {
                limit: "max_payload_bytes",
                maximum: self.limits.max_payload_bytes,
                attempted: attempted_payload,
            });
        }

        self.logical_fingerprints
            .insert(entry.logical_id, fingerprint);
        self.domain_fingerprints
            .insert(domain_key, fingerprint);
        self.total_payload_bytes = attempted_payload;
        self.entries.push(entry);
        Ok(AddOutcome::Added)
    }
}

fn canonical_weight(weight: f64) -> Result<f64> {
    if !weight.is_finite() {
        return Err(TransactionError::InvalidInput(
            "typed edge weight must be finite".to_string(),
        ));
    }
    Ok(if weight == 0.0 { 0.0 } else { weight })
}

fn operation_fingerprint(entry: &SegmentEntry) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(
        52usize.saturating_add(entry.payload.len())
    );
    preimage.extend_from_slice(&(entry.kind as u16).to_le_bytes());
    preimage.extend_from_slice(&0u16.to_le_bytes());
    preimage.extend_from_slice(&entry.logical_id.to_le_bytes());
    preimage.extend_from_slice(
        &(entry.payload.len() as u64).to_le_bytes(),
    );
    preimage.extend_from_slice(&sha256(&entry.payload));
    preimage.extend_from_slice(&entry.payload);
    sha256(&preimage)
}

fn batch_digest(
    transaction_id: TransactionId,
    entries: &[SegmentEntry],
    total_payload_bytes: u64,
) -> [u8; 32] {
    let payload_capacity = usize::try_from(total_payload_bytes)
        .unwrap_or(usize::MAX.saturating_sub(64));
    let mut preimage = Vec::with_capacity(
        40usize
            .saturating_add(entries.len().saturating_mul(52))
            .saturating_add(payload_capacity),
    );
    preimage.extend_from_slice(&BATCH_DIGEST_MAGIC);
    preimage.extend_from_slice(&transaction_id.bytes());
    preimage.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    preimage.extend_from_slice(&total_payload_bytes.to_le_bytes());
    for entry in entries {
        preimage.extend_from_slice(&(entry.kind as u16).to_le_bytes());
        preimage.extend_from_slice(&0u16.to_le_bytes());
        preimage.extend_from_slice(&entry.logical_id.to_le_bytes());
        preimage.extend_from_slice(
            &(entry.payload.len() as u64).to_le_bytes(),
        );
        preimage.extend_from_slice(&sha256(&entry.payload));
        preimage.extend_from_slice(&entry.payload);
    }
    sha256(&preimage)
}

#[derive(Clone, Debug)]
struct ActiveTransaction {
    transaction_id: TransactionId,
    state: TransactionState,
    batch: WriteBatch,
    prepared: Option<PreparedBatch>,
}

#[derive(Clone, Debug)]
pub struct ShadowMaterializationReceipt {
    pub transaction_id: TransactionId,
    pub batch_digest: [u8; 32],
    pub operation_count: u64,
    pub total_payload_bytes: u64,
    pub generation: u64,
    pub sequence: u64,
    pub segment_path: PathBuf,
    pub segment_file_sha256: [u8; 32],
    pub segment_payload_sha256: [u8; 32],
    pub durable_commit: bool,
    pub wal_recorded: bool,
    pub head_published: bool,
    pub active_runtime_changed: bool,
}

impl ShadowMaterializationReceipt {
    pub fn batch_digest_hex(&self) -> String {
        hex_digest(&self.batch_digest)
    }

    pub fn segment_file_sha256_hex(&self) -> String {
        hex_digest(&self.segment_file_sha256)
    }
}

#[derive(Clone, Debug)]
pub struct TransactionCore {
    limits: BatchLimits,
    active: Option<ActiveTransaction>,
}

impl TransactionCore {
    pub fn new(limits: BatchLimits) -> Self {
        Self {
            limits,
            active: None,
        }
    }

    pub fn active_transaction_id(&self) -> Option<TransactionId> {
        self.active.as_ref().map(|value| value.transaction_id)
    }

    pub fn active_state(&self) -> Option<TransactionState> {
        self.active.as_ref().map(|value| value.state)
    }

    pub fn begin(&mut self, transaction_id: TransactionId) -> Result<()> {
        if let Some(active) = &self.active {
            return Err(TransactionError::WriterAlreadyActive(
                active.transaction_id,
            ));
        }
        self.active = Some(ActiveTransaction {
            transaction_id,
            state: TransactionState::Active,
            batch: WriteBatch::new(self.limits),
            prepared: None,
        });
        Ok(())
    }

    pub fn put_record(
        &mut self,
        logical_id: u64,
        record_id: &str,
        node_id: u64,
        user_payload: &[u8],
    ) -> Result<AddOutcome> {
        self.active_batch_mut("put_record")?
            .put_record(logical_id, record_id, node_id, user_payload)
    }

    pub fn delete_record(
        &mut self,
        logical_id: u64,
        record_id: &str,
    ) -> Result<AddOutcome> {
        self.active_batch_mut("delete_record")?
            .delete_record(logical_id, record_id)
    }

    pub fn put_edge(
        &mut self,
        logical_id: u64,
        src: u64,
        dst: u64,
        edge_type: u32,
        weight: f64,
    ) -> Result<AddOutcome> {
        self.active_batch_mut("put_edge")?
            .put_edge(logical_id, src, dst, edge_type, weight)
    }

    pub fn delete_edge(
        &mut self,
        logical_id: u64,
        src: u64,
        dst: u64,
        edge_type: u32,
        weight: f64,
    ) -> Result<AddOutcome> {
        self.active_batch_mut("delete_edge")?
            .delete_edge(logical_id, src, dst, edge_type, weight)
    }

    pub fn prepare(&mut self) -> Result<PreparedBatch> {
        let active = self
            .active
            .as_mut()
            .ok_or(TransactionError::NoActiveTransaction)?;
        match active.state {
            TransactionState::Active => {
                let prepared = active.batch.prepare(active.transaction_id);
                active.prepared = Some(prepared.clone());
                active.state = TransactionState::Prepared;
                Ok(prepared)
            }
            TransactionState::Prepared => active
                .prepared
                .clone()
                .ok_or_else(|| TransactionError::Integrity(
                    "prepared state has no prepared batch".to_string()
                )),
            actual => Err(TransactionError::InvalidState {
                operation: "prepare",
                actual,
            }),
        }
    }

    pub fn materialize_shadow(
        &mut self,
        store: &PageStore,
        generation: u64,
        sequence: u64,
    ) -> Result<ShadowMaterializationReceipt> {
        let active = self
            .active
            .as_mut()
            .ok_or(TransactionError::NoActiveTransaction)?;
        if active.state != TransactionState::Prepared {
            return Err(TransactionError::InvalidState {
                operation: "materialize_shadow",
                actual: active.state,
            });
        }
        let prepared = active
            .prepared
            .clone()
            .ok_or_else(|| TransactionError::Integrity(
                "prepared state has no batch".to_string()
            ))?;
        let report: IntegrityReport = store.write_segment(
            generation,
            sequence,
            prepared.entries.clone(),
        )?;
        if report.item_count != prepared.operation_count() as u64 {
            return Err(TransactionError::Integrity(format!(
                "segment item_count mismatch expected={} actual={}",
                prepared.operation_count(),
                report.item_count
            )));
        }
        let segment_file_sha256 = sha256_file(&report.path)?;
        active.state = TransactionState::ShadowMaterialized;

        Ok(ShadowMaterializationReceipt {
            transaction_id: prepared.transaction_id,
            batch_digest: prepared.batch_digest,
            operation_count: prepared.operation_count() as u64,
            total_payload_bytes: prepared.total_payload_bytes,
            generation,
            sequence,
            segment_path: report.path,
            segment_file_sha256,
            segment_payload_sha256: report.payload_sha256,
            durable_commit: false,
            wal_recorded: false,
            head_published: false,
            active_runtime_changed: false,
        })
    }

    pub fn abort(&mut self) -> Result<()> {
        let active = self
            .active
            .as_mut()
            .ok_or(TransactionError::NoActiveTransaction)?;
        match active.state {
            TransactionState::Active | TransactionState::Prepared => {
                active.state = TransactionState::Aborted;
                Ok(())
            }
            actual => Err(TransactionError::InvalidState {
                operation: "abort",
                actual,
            }),
        }
    }

    pub fn release_terminal(
        &mut self,
        transaction_id: TransactionId,
    ) -> Result<TransactionState> {
        let active = self
            .active
            .as_ref()
            .ok_or(TransactionError::NoActiveTransaction)?;
        if active.transaction_id != transaction_id {
            return Err(TransactionError::TransactionIdMismatch {
                expected: active.transaction_id,
                actual: transaction_id,
            });
        }
        if !active.state.is_terminal() {
            return Err(TransactionError::InvalidState {
                operation: "release_terminal",
                actual: active.state,
            });
        }
        let state = active.state;
        self.active = None;
        Ok(state)
    }

    fn active_batch_mut(
        &mut self,
        operation: &'static str,
    ) -> Result<&mut WriteBatch> {
        let active = self
            .active
            .as_mut()
            .ok_or(TransactionError::NoActiveTransaction)?;
        if active.state != TransactionState::Active {
            return Err(TransactionError::InvalidState {
                operation,
                actual: active.state,
            });
        }
        Ok(&mut active.batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn transaction_id(seed: u8) -> TransactionId {
        TransactionId::new([seed; 16])
    }

    fn test_root(name: &str) -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "ultraballoondb-lifecycle-{name}-{}-{counter}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn deterministic_batch_digest() {
        let mut left = WriteBatch::new(BatchLimits::default());
        let mut right = WriteBatch::new(BatchLimits::default());

        left.put_record(1, "alpha", 10, b"payload").unwrap();
        left.put_edge(2, 10, 20, 7, 0.75).unwrap();

        right.put_record(1, "alpha", 10, b"payload").unwrap();
        right.put_edge(2, 10, 20, 7, 0.75).unwrap();

        let tx = transaction_id(1);
        assert_eq!(
            left.prepare(tx).batch_digest(),
            right.prepare(tx).batch_digest()
        );
    }

    #[test]
    fn duplicate_is_ignored_and_conflict_is_rejected() {
        let mut batch = WriteBatch::new(BatchLimits::default());
        assert_eq!(
            batch.put_record(1, "alpha", 10, b"payload").unwrap(),
            AddOutcome::Added
        );
        assert_eq!(
            batch.put_record(1, "alpha", 10, b"payload").unwrap(),
            AddOutcome::DuplicateIgnored
        );
        assert_eq!(batch.operation_count(), 1);
        assert!(matches!(
            batch.put_record(2, "alpha", 10, b"different"),
            Err(TransactionError::Conflict(_))
        ));
        assert!(matches!(
            batch.put_edge(1, 10, 20, 7, 0.5),
            Err(TransactionError::Conflict(_))
        ));
    }

    #[test]
    fn single_writer_and_state_machine() {
        let mut core = TransactionCore::new(BatchLimits::default());
        let tx1 = transaction_id(1);
        let tx2 = transaction_id(2);
        core.begin(tx1).unwrap();
        assert!(matches!(
            core.begin(tx2),
            Err(TransactionError::WriterAlreadyActive(_))
        ));
        core.put_record(1, "alpha", 10, b"payload").unwrap();
        core.prepare().unwrap();
        assert!(matches!(
            core.put_record(2, "beta", 20, b"payload"),
            Err(TransactionError::InvalidState { .. })
        ));
        core.abort().unwrap();
        assert_eq!(
            core.release_terminal(tx1).unwrap(),
            TransactionState::Aborted
        );
        core.begin(tx2).unwrap();
    }

    #[test]
    fn limits_are_enforced() {
        let mut batch = WriteBatch::new(BatchLimits {
            max_operations: 1,
            max_payload_bytes: 1_000,
        });
        batch.put_record(1, "alpha", 10, b"a").unwrap();
        assert!(matches!(
            batch.put_record(2, "beta", 20, b"b"),
            Err(TransactionError::LimitExceeded {
                limit: "max_operations",
                ..
            })
        ));

        let mut small_payload = WriteBatch::new(BatchLimits {
            max_operations: 10,
            max_payload_bytes: 10,
        });
        assert!(matches!(
            small_payload.put_record(1, "alpha", 10, b"large-payload"),
            Err(TransactionError::LimitExceeded {
                limit: "max_payload_bytes",
                ..
            })
        ));
    }

    #[test]
    fn delete_operations_are_deterministic() {
        let mut batch = WriteBatch::new(BatchLimits::default());
        batch.delete_record(1, "old-record").unwrap();
        batch.delete_edge(2, 1, 2, 3, -0.0).unwrap();
        let prepared = batch.prepare(transaction_id(3));
        assert_eq!(prepared.operation_count(), 2);
        assert_eq!(
            prepared.entries()[0].kind,
            RecordKind::RecordTombstone
        );
        assert_eq!(
            prepared.entries()[1].kind,
            RecordKind::EdgeTombstone
        );
        assert_eq!(
            &prepared.entries()[1].payload[24..32],
            &[0u8; 8]
        );
    }

    #[test]
    fn shadow_materialization_is_verified_and_not_durable() {
        let root = test_root("shadow");
        let store = PageStore::create(&root).unwrap();
        let mut core = TransactionCore::new(BatchLimits::default());
        let tx = transaction_id(4);
        core.begin(tx).unwrap();
        core.put_record(1, "alpha", 10, b"payload").unwrap();
        core.put_edge(2, 10, 20, 7, 0.75).unwrap();
        core.prepare().unwrap();

        let receipt = core
            .materialize_shadow(&store, 7, 0)
            .unwrap();
        assert_eq!(receipt.operation_count, 2);
        assert!(!receipt.durable_commit);
        assert!(!receipt.wal_recorded);
        assert!(!receipt.head_published);
        assert_eq!(
            core.active_state(),
            Some(TransactionState::ShadowMaterialized)
        );

        let integrity = PageStore::open(&root).unwrap().verify().unwrap();
        assert_eq!(integrity.segment_count, 1);
        assert_eq!(integrity.segments[0].item_count, 2);
        assert_eq!(
            core.release_terminal(tx).unwrap(),
            TransactionState::ShadowMaterialized
        );
        fs::remove_dir_all(root).unwrap();
    }
}
