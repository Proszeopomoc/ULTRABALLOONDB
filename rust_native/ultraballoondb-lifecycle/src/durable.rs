use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ultraballoondb_storage::{
    hex_digest, sha256, sha256_file, Head, PageStore, RecordKind,
    SegmentEntry, StorageError,
};
use ultraballoondb_wal::{
    scan_wal, FrameType, WalError, WalScan, WalWriter,
};

use crate::{
    PreparedBatch, TransactionCore, TransactionError, TransactionId,
    TransactionState,
};

pub const STATE_HASH_MAGIC: [u8; 8] = *b"UBSTA01\0";
pub const CHECKPOINT_MAGIC: [u8; 8] = *b"UBCHK01\0";
pub const CHECKPOINT_HEADER_BYTES: usize = 80;
pub const MANIFEST_PAYLOAD_MAGIC: [u8; 8] = *b"UBMNF01\0";
pub const OPERATION_FRAME_FIXED_BYTES: usize = 48;
pub const ENTRY_FIXED_BYTES: usize = 52;

#[derive(Debug)]
pub enum DurableError {
    Io(io::Error),
    Storage(StorageError),
    Wal(WalError),
    Invalid(String),
    Integrity {
        context: String,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    DuplicateTransaction(TransactionId),
}

impl fmt::Display for DurableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Storage(error) => write!(f, "storage error: {error}"),
            Self::Wal(error) => write!(f, "WAL error: {error}"),
            Self::Invalid(message) => write!(f, "invalid durable state: {message}"),
            Self::Integrity {
                context,
                expected,
                actual,
            } => write!(
                f,
                "durable integrity mismatch for {context}: expected={} actual={}",
                hex_digest(expected),
                hex_digest(actual)
            ),
            Self::DuplicateTransaction(transaction_id) => write!(
                f,
                "transaction already committed: {}",
                transaction_id.to_hex()
            ),
        }
    }
}

impl std::error::Error for DurableError {}

impl From<io::Error> for DurableError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<StorageError> for DurableError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

impl From<WalError> for DurableError {
    fn from(value: WalError) -> Self {
        Self::Wal(value)
    }
}

pub type DurableResult<T> = std::result::Result<T, DurableError>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct EdgeKey {
    src: u64,
    dst: u64,
    edge_type: u32,
    weight_bits: u64,
}

#[derive(Clone, Debug, Default)]
struct RecoveredState {
    records: BTreeMap<String, SegmentEntry>,
    edges: BTreeMap<EdgeKey, SegmentEntry>,
}

impl RecoveredState {
    fn apply(&mut self, entry: SegmentEntry) -> DurableResult<()> {
        match entry.kind {
            RecordKind::Record => {
                let record_id = record_id_from_put(&entry.payload)?;
                self.records.insert(record_id, entry);
            }
            RecordKind::TypedEdge => {
                let key = edge_key(&entry.payload)?;
                self.edges.insert(key, entry);
            }
            RecordKind::RecordTombstone => {
                let record_id = record_id_from_delete(&entry.payload)?;
                self.records.remove(&record_id);
            }
            RecordKind::EdgeTombstone => {
                let key = edge_key(&entry.payload)?;
                self.edges.remove(&key);
            }
            RecordKind::Metadata => {
                return Err(DurableError::Invalid(
                    "metadata is not a transactional operation in B3".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn apply_all(&mut self, entries: &[SegmentEntry]) -> DurableResult<()> {
        for entry in entries {
            self.apply(entry.clone())?;
        }
        Ok(())
    }

    fn state_hash(&self) -> [u8; 32] {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&STATE_HASH_MAGIC);
        preimage.extend_from_slice(&(self.records.len() as u64).to_le_bytes());
        preimage.extend_from_slice(&(self.edges.len() as u64).to_le_bytes());
        for entry in self.records.values() {
            encode_entry_for_hash(entry, &mut preimage);
        }
        for entry in self.edges.values() {
            encode_entry_for_hash(entry, &mut preimage);
        }
        sha256(&preimage)
    }

    fn counts(&self) -> (u64, u64) {
        (self.records.len() as u64, self.edges.len() as u64)
    }

    fn entries(&self) -> impl Iterator<Item = &SegmentEntry> {
        self.records.values().chain(self.edges.values())
    }
}

#[derive(Clone, Debug)]
struct PendingTransaction {
    expected_operations: u64,
    expected_payload_bytes: u64,
    expected_batch_digest: [u8; 32],
    entries: Vec<SegmentEntry>,
}

#[derive(Clone, Debug)]
pub struct DurableCommitReceipt {
    pub transaction_id: TransactionId,
    pub begin_lsn: u64,
    pub commit_lsn: u64,
    pub operation_count: u64,
    pub batch_digest: [u8; 32],
    pub state_sha256: [u8; 32],
    pub segment_path: PathBuf,
    pub segment_file_sha256: [u8; 32],
    pub durable_commit: bool,
    pub wal_recorded: bool,
    pub wal_fsynced: bool,
    pub segment_materialized: bool,
    pub head_published: bool,
    pub active_runtime_changed: bool,
}

#[derive(Clone, Debug)]
pub struct CheckpointReceipt {
    pub generation: u64,
    pub checkpoint_lsn: u64,
    pub state_sha256: [u8; 32],
    pub checkpoint_path: PathBuf,
    pub checkpoint_file_sha256: [u8; 32],
    pub manifest_path: PathBuf,
    pub manifest_file_sha256: [u8; 32],
    pub head_path: PathBuf,
    pub head_published: bool,
    pub wal_checkpoint_recorded: bool,
}

#[derive(Clone, Debug)]
pub struct RecoveryReceipt {
    pub checkpoint_generation: u64,
    pub checkpoint_lsn: u64,
    pub maximum_valid_wal_lsn: u64,
    pub replayed_transaction_count: u64,
    pub ignored_uncommitted_count: u64,
    pub repaired_trailing_bytes: u64,
    pub record_count: u64,
    pub edge_count: u64,
    pub state_sha256: [u8; 32],
    pub restart_deterministic: bool,
}

pub struct DurableDatabase {
    store: PageStore,
    wal_path: PathBuf,
    wal: WalWriter,
    state: RecoveredState,
    committed_transactions: BTreeSet<[u8; 16]>,
    last_lsn: u64,
    recovery: RecoveryReceipt,
}

impl DurableDatabase {
    pub fn create(root: impl AsRef<Path>) -> DurableResult<Self> {
        let store = PageStore::create(root)?;
        let wal_path = default_wal_path(store.root());
        let wal = WalWriter::open(&wal_path, true)?;
        let state = RecoveredState::default();
        let state_sha256 = state.state_hash();
        Ok(Self {
            store,
            wal_path,
            wal,
            state,
            committed_transactions: BTreeSet::new(),
            last_lsn: 0,
            recovery: RecoveryReceipt {
                checkpoint_generation: 0,
                checkpoint_lsn: 0,
                maximum_valid_wal_lsn: 0,
                replayed_transaction_count: 0,
                ignored_uncommitted_count: 0,
                repaired_trailing_bytes: 0,
                record_count: 0,
                edge_count: 0,
                state_sha256,
                restart_deterministic: true,
            },
        })
    }

    pub fn open(
        root: impl AsRef<Path>,
        repair_trailing: bool,
    ) -> DurableResult<Self> {
        let store = PageStore::open(root)?;
        let (
            mut state,
            mut committed_transactions,
            checkpoint_generation,
            checkpoint_lsn,
        ) = load_checkpoint(&store)?;
        let wal_path = default_wal_path(store.root());
        let scan = scan_wal(&wal_path, repair_trailing)?;
        let (
            replayed_transaction_count,
            ignored_uncommitted_count,
        ) = replay_after_checkpoint(
            &mut state,
            &mut committed_transactions,
            checkpoint_lsn,
            &scan,
        )?;
        let state_sha256 = state.state_hash();
        let (record_count, edge_count) = state.counts();
        let wal = WalWriter::open(&wal_path, false)?;
        let maximum_valid_wal_lsn = scan.maximum_lsn;
        Ok(Self {
            store,
            wal_path,
            wal,
            state,
            committed_transactions,
            last_lsn: maximum_valid_wal_lsn,
            recovery: RecoveryReceipt {
                checkpoint_generation,
                checkpoint_lsn,
                maximum_valid_wal_lsn,
                replayed_transaction_count,
                ignored_uncommitted_count,
                repaired_trailing_bytes: scan.repaired_trailing_bytes,
                record_count,
                edge_count,
                state_sha256,
                restart_deterministic: true,
            },
        })
    }

    pub fn recovery_receipt(&self) -> &RecoveryReceipt {
        &self.recovery
    }

    pub fn wal_path(&self) -> &Path {
        &self.wal_path
    }

    pub fn state_sha256(&self) -> [u8; 32] {
        self.state.state_hash()
    }

    pub fn state_counts(&self) -> (u64, u64) {
        self.state.counts()
    }

    pub fn commit_prepared(
        &mut self,
        prepared: &PreparedBatch,
        generation: u64,
        sequence: u64,
    ) -> DurableResult<DurableCommitReceipt> {
        let transaction_id = prepared.transaction_id();
        if self
            .committed_transactions
            .contains(&transaction_id.bytes())
        {
            return Err(DurableError::DuplicateTransaction(transaction_id));
        }

        let segment = self.store.write_segment(
            generation,
            sequence,
            prepared.entries().to_vec(),
        )?;
        let segment_file_sha256 = sha256_file(&segment.path)?;

        let mut candidate = self.state.clone();
        candidate.apply_all(prepared.entries())?;
        let candidate_state_hash = candidate.state_hash();

        let begin_payload = encode_begin_payload(prepared);
        let begin_lsn = self.wal.append(
            FrameType::Begin,
            transaction_id.bytes(),
            &begin_payload,
        )?;
        for entry in prepared.entries() {
            let frame_type = frame_type_for_entry(entry)?;
            let payload = encode_operation_payload(entry);
            self.wal.append(
                frame_type,
                transaction_id.bytes(),
                &payload,
            )?;
        }
        let commit_payload = encode_commit_payload(
            prepared,
            candidate_state_hash,
        );
        let commit_lsn = self.wal.append(
            FrameType::Commit,
            transaction_id.bytes(),
            &commit_payload,
        )?;
        self.wal.flush_and_sync()?;

        self.state = candidate;
        self.committed_transactions
            .insert(transaction_id.bytes());
        self.last_lsn = commit_lsn;

        Ok(DurableCommitReceipt {
            transaction_id,
            begin_lsn,
            commit_lsn,
            operation_count: prepared.operation_count() as u64,
            batch_digest: prepared.batch_digest(),
            state_sha256: candidate_state_hash,
            segment_path: segment.path,
            segment_file_sha256,
            durable_commit: true,
            wal_recorded: true,
            wal_fsynced: true,
            segment_materialized: true,
            head_published: false,
            active_runtime_changed: false,
        })
    }

    pub fn checkpoint(
        &mut self,
        generation: u64,
    ) -> DurableResult<CheckpointReceipt> {
        let state_sha256 = self.state.state_hash();
        let checkpoint_frame_payload =
            encode_checkpoint_frame_payload(generation, state_sha256);
        let checkpoint_lsn = self.wal.append(
            FrameType::Checkpoint,
            [0u8; 16],
            &checkpoint_frame_payload,
        )?;
        self.wal.flush_and_sync()?;
        self.last_lsn = checkpoint_lsn;

        let checkpoint_path = self
            .store
            .root()
            .join("checkpoints")
            .join(format!("CHECKPOINT-{generation:020}.ubchk"));
        write_checkpoint(
            &checkpoint_path,
            generation,
            checkpoint_lsn,
            &self.state,
            &self.committed_transactions,
        )?;
        let checkpoint_file_sha256 = sha256_file(&checkpoint_path)?;

        let checkpoint_filename = checkpoint_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| DurableError::Invalid(
                "checkpoint filename is not UTF-8".to_string()
            ))?
            .to_string();
        let manifest_payload = encode_manifest_payload(
            generation,
            checkpoint_lsn,
            state_sha256,
            checkpoint_file_sha256,
            &checkpoint_filename,
        )?;
        let manifest = self.store.write_manifest(
            generation,
            1,
            &manifest_payload,
        )?;
        let manifest_file_sha256 = sha256_file(&manifest.path)?;
        let manifest_filename = manifest
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| DurableError::Invalid(
                "manifest filename is not UTF-8".to_string()
            ))?
            .to_string();
        self.store.publish_head(&Head {
            generation,
            manifest_filename,
            manifest_sha256: manifest_file_sha256,
        })?;

        Ok(CheckpointReceipt {
            generation,
            checkpoint_lsn,
            state_sha256,
            checkpoint_path,
            checkpoint_file_sha256,
            manifest_path: manifest.path,
            manifest_file_sha256,
            head_path: self.store.root().join("CURRENT.ubhead"),
            head_published: true,
            wal_checkpoint_recorded: true,
        })
    }

    #[doc(hidden)]
    pub fn append_uncommitted_for_probe(
        &mut self,
        prepared: &PreparedBatch,
    ) -> DurableResult<(u64, u64)> {
        let transaction_id = prepared.transaction_id();
        let begin_lsn = self.wal.append(
            FrameType::Begin,
            transaction_id.bytes(),
            &encode_begin_payload(prepared),
        )?;
        let mut last_lsn = begin_lsn;
        for entry in prepared.entries() {
            last_lsn = self.wal.append(
                frame_type_for_entry(entry)?,
                transaction_id.bytes(),
                &encode_operation_payload(entry),
            )?;
        }
        self.wal.flush_and_sync()?;
        self.last_lsn = last_lsn;
        Ok((begin_lsn, last_lsn))
    }
}

impl TransactionCore {
    pub fn commit_durable(
        &mut self,
        database: &mut DurableDatabase,
        generation: u64,
        sequence: u64,
    ) -> crate::Result<DurableCommitReceipt> {
        let prepared = {
            let active = self
                .active
                .as_ref()
                .ok_or(TransactionError::NoActiveTransaction)?;
            if active.state != TransactionState::Prepared {
                return Err(TransactionError::InvalidState {
                    operation: "commit_durable",
                    actual: active.state,
                });
            }
            active.prepared.clone().ok_or_else(|| {
                TransactionError::Integrity(
                    "prepared state has no batch".to_string(),
                )
            })?
        };
        let receipt = database
            .commit_prepared(&prepared, generation, sequence)
            .map_err(|error| {
                TransactionError::Integrity(format!(
                    "durable commit failed: {error}"
                ))
            })?;
        let active = self
            .active
            .as_mut()
            .ok_or(TransactionError::NoActiveTransaction)?;
        active.state = TransactionState::DurableCommitted;
        Ok(receipt)
    }
}

fn default_wal_path(root: &Path) -> PathBuf {
    root.join("wal")
        .join("WAL-00000000000000000001-00000000000000000000.ubwal")
}

fn frame_type_for_entry(entry: &SegmentEntry) -> DurableResult<FrameType> {
    match entry.kind {
        RecordKind::Record => Ok(FrameType::PutRecord),
        RecordKind::TypedEdge => Ok(FrameType::PutEdge),
        RecordKind::RecordTombstone => Ok(FrameType::DeleteRecord),
        RecordKind::EdgeTombstone => Ok(FrameType::DeleteEdge),
        RecordKind::Metadata => Err(DurableError::Invalid(
            "metadata cannot be committed through B3".to_string(),
        )),
    }
}

fn record_kind_for_frame(frame_type: FrameType) -> DurableResult<RecordKind> {
    match frame_type {
        FrameType::PutRecord => Ok(RecordKind::Record),
        FrameType::PutEdge => Ok(RecordKind::TypedEdge),
        FrameType::DeleteRecord => Ok(RecordKind::RecordTombstone),
        FrameType::DeleteEdge => Ok(RecordKind::EdgeTombstone),
        _ => Err(DurableError::Invalid(
            "frame is not an operation".to_string(),
        )),
    }
}

fn encode_begin_payload(prepared: &PreparedBatch) -> Vec<u8> {
    let mut payload = Vec::with_capacity(48);
    payload.extend_from_slice(
        &(prepared.operation_count() as u64).to_le_bytes(),
    );
    payload.extend_from_slice(
        &prepared.total_payload_bytes().to_le_bytes(),
    );
    payload.extend_from_slice(&prepared.batch_digest());
    payload
}

fn decode_begin_payload(
    payload: &[u8],
) -> DurableResult<(u64, u64, [u8; 32])> {
    if payload.len() != 48 {
        return Err(DurableError::Invalid(
            "BEGIN payload must be 48 bytes".to_string(),
        ));
    }
    Ok((
        read_u64(payload, 0)?,
        read_u64(payload, 8)?,
        read_digest(payload, 16)?,
    ))
}

fn encode_commit_payload(
    prepared: &PreparedBatch,
    state_sha256: [u8; 32],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(72);
    payload.extend_from_slice(
        &(prepared.operation_count() as u64).to_le_bytes(),
    );
    payload.extend_from_slice(&prepared.batch_digest());
    payload.extend_from_slice(&state_sha256);
    payload
}

fn decode_commit_payload(
    payload: &[u8],
) -> DurableResult<(u64, [u8; 32], [u8; 32])> {
    if payload.len() != 72 {
        return Err(DurableError::Invalid(
            "COMMIT payload must be 72 bytes".to_string(),
        ));
    }
    Ok((
        read_u64(payload, 0)?,
        read_digest(payload, 8)?,
        read_digest(payload, 40)?,
    ))
}

fn encode_checkpoint_frame_payload(
    generation: u64,
    state_sha256: [u8; 32],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(40);
    payload.extend_from_slice(&generation.to_le_bytes());
    payload.extend_from_slice(&state_sha256);
    payload
}

fn encode_operation_payload(entry: &SegmentEntry) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        OPERATION_FRAME_FIXED_BYTES + entry.payload.len(),
    );
    payload.extend_from_slice(&entry.logical_id.to_le_bytes());
    payload.extend_from_slice(
        &(entry.payload.len() as u64).to_le_bytes(),
    );
    payload.extend_from_slice(&sha256(&entry.payload));
    payload.extend_from_slice(&entry.payload);
    payload
}

fn decode_operation_payload(
    frame_type: FrameType,
    payload: &[u8],
) -> DurableResult<SegmentEntry> {
    if payload.len() < OPERATION_FRAME_FIXED_BYTES {
        return Err(DurableError::Invalid(
            "operation frame payload is truncated".to_string(),
        ));
    }
    let logical_id = read_u64(payload, 0)?;
    let payload_bytes = usize::try_from(read_u64(payload, 8)?)
        .map_err(|_| DurableError::Invalid(
            "operation payload is too large".to_string()
        ))?;
    let expected_hash = read_digest(payload, 16)?;
    let expected_len = OPERATION_FRAME_FIXED_BYTES
        .checked_add(payload_bytes)
        .ok_or_else(|| DurableError::Invalid(
            "operation length overflow".to_string()
        ))?;
    if payload.len() != expected_len {
        return Err(DurableError::Invalid(
            "operation payload length mismatch".to_string(),
        ));
    }
    let entry_payload = payload[OPERATION_FRAME_FIXED_BYTES..].to_vec();
    let actual_hash = sha256(&entry_payload);
    if actual_hash != expected_hash {
        return Err(DurableError::Integrity {
            context: "operation payload".to_string(),
            expected: expected_hash,
            actual: actual_hash,
        });
    }
    Ok(SegmentEntry::new(
        record_kind_for_frame(frame_type)?,
        logical_id,
        entry_payload,
    )?)
}

fn compute_batch_digest(
    transaction_id: [u8; 16],
    entries: &[SegmentEntry],
) -> [u8; 32] {
    let total_payload_bytes: u64 = entries
        .iter()
        .map(|entry| entry.payload.len() as u64)
        .sum();
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"UBTXB01\0");
    preimage.extend_from_slice(&transaction_id);
    preimage.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    preimage.extend_from_slice(&total_payload_bytes.to_le_bytes());
    for entry in entries {
        encode_entry_for_hash(entry, &mut preimage);
    }
    sha256(&preimage)
}

fn encode_entry_for_hash(entry: &SegmentEntry, output: &mut Vec<u8>) {
    output.extend_from_slice(&(entry.kind as u16).to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&entry.logical_id.to_le_bytes());
    output.extend_from_slice(
        &(entry.payload.len() as u64).to_le_bytes(),
    );
    output.extend_from_slice(&sha256(&entry.payload));
    output.extend_from_slice(&entry.payload);
}

fn replay_after_checkpoint(
    state: &mut RecoveredState,
    committed_transactions: &mut BTreeSet<[u8; 16]>,
    checkpoint_lsn: u64,
    scan: &WalScan,
) -> DurableResult<(u64, u64)> {
    let mut pending: BTreeMap<[u8; 16], PendingTransaction> =
        BTreeMap::new();
    let mut replayed = 0u64;

    for frame in scan
        .frames
        .iter()
        .filter(|frame| frame.lsn > checkpoint_lsn)
    {
        match frame.frame_type {
            FrameType::Begin => {
                if frame.transaction_id == [0u8; 16] {
                    return Err(DurableError::Invalid(
                        "BEGIN transaction ID cannot be zero".to_string(),
                    ));
                }
                if pending.contains_key(&frame.transaction_id) {
                    return Err(DurableError::Invalid(
                        "duplicate BEGIN".to_string(),
                    ));
                }
                let (
                    expected_operations,
                    expected_payload_bytes,
                    expected_batch_digest,
                ) = decode_begin_payload(&frame.payload)?;
                pending.insert(
                    frame.transaction_id,
                    PendingTransaction {
                        expected_operations,
                        expected_payload_bytes,
                        expected_batch_digest,
                        entries: Vec::new(),
                    },
                );
            }
            FrameType::PutRecord
            | FrameType::PutEdge
            | FrameType::DeleteRecord
            | FrameType::DeleteEdge => {
                let transaction = pending
                    .get_mut(&frame.transaction_id)
                    .ok_or_else(|| DurableError::Invalid(
                        "operation without BEGIN".to_string()
                    ))?;
                transaction.entries.push(
                    decode_operation_payload(
                        frame.frame_type,
                        &frame.payload,
                    )?,
                );
            }
            FrameType::Commit => {
                let transaction = pending
                    .remove(&frame.transaction_id)
                    .ok_or_else(|| DurableError::Invalid(
                        "COMMIT without BEGIN".to_string()
                    ))?;
                let (
                    operation_count,
                    batch_digest,
                    expected_state_hash,
                ) = decode_commit_payload(&frame.payload)?;
                if operation_count != transaction.expected_operations
                    || operation_count
                        != transaction.entries.len() as u64
                {
                    return Err(DurableError::Invalid(
                        "COMMIT operation count mismatch".to_string(),
                    ));
                }
                let payload_bytes: u64 = transaction
                    .entries
                    .iter()
                    .map(|entry| entry.payload.len() as u64)
                    .sum();
                if payload_bytes != transaction.expected_payload_bytes {
                    return Err(DurableError::Invalid(
                        "BEGIN payload byte count mismatch".to_string(),
                    ));
                }
                let actual_batch_digest = compute_batch_digest(
                    frame.transaction_id,
                    &transaction.entries,
                );
                if actual_batch_digest
                    != transaction.expected_batch_digest
                    || actual_batch_digest != batch_digest
                {
                    return Err(DurableError::Integrity {
                        context: "transaction batch digest".to_string(),
                        expected: batch_digest,
                        actual: actual_batch_digest,
                    });
                }
                if committed_transactions
                    .contains(&frame.transaction_id)
                {
                    return Err(DurableError::Invalid(
                        "duplicate committed transaction ID".to_string(),
                    ));
                }
                let mut candidate = state.clone();
                candidate.apply_all(&transaction.entries)?;
                let actual_state_hash = candidate.state_hash();
                if actual_state_hash != expected_state_hash {
                    return Err(DurableError::Integrity {
                        context: "COMMIT state hash".to_string(),
                        expected: expected_state_hash,
                        actual: actual_state_hash,
                    });
                }
                *state = candidate;
                committed_transactions.insert(frame.transaction_id);
                replayed = replayed
                    .checked_add(1)
                    .ok_or_else(|| DurableError::Invalid(
                        "replayed transaction count overflow".to_string()
                    ))?;
            }
            FrameType::Abort => {
                if pending.remove(&frame.transaction_id).is_none() {
                    return Err(DurableError::Invalid(
                        "ABORT without BEGIN".to_string(),
                    ));
                }
            }
            FrameType::Checkpoint => {
                if frame.transaction_id != [0u8; 16]
                    || frame.payload.len() != 40
                {
                    return Err(DurableError::Invalid(
                        "invalid CHECKPOINT frame".to_string(),
                    ));
                }
            }
        }
    }

    Ok((replayed, pending.len() as u64))
}

fn record_id_from_put(payload: &[u8]) -> DurableResult<String> {
    if payload.len() < 56 {
        return Err(DurableError::Invalid(
            "record payload too short".to_string(),
        ));
    }
    let length = read_u32(payload, 0)? as usize;
    let end = 56usize
        .checked_add(length)
        .ok_or_else(|| DurableError::Invalid(
            "record ID length overflow".to_string()
        ))?;
    let bytes = payload
        .get(56..end)
        .ok_or_else(|| DurableError::Invalid(
            "record ID is truncated".to_string()
        ))?;
    Ok(std::str::from_utf8(bytes)
        .map_err(|_| DurableError::Invalid(
            "record ID is not UTF-8".to_string()
        ))?
        .to_string())
}

fn record_id_from_delete(payload: &[u8]) -> DurableResult<String> {
    if payload.len() < 8 {
        return Err(DurableError::Invalid(
            "record tombstone is too short".to_string(),
        ));
    }
    let length = read_u32(payload, 0)? as usize;
    let end = 8usize
        .checked_add(length)
        .ok_or_else(|| DurableError::Invalid(
            "record tombstone length overflow".to_string()
        ))?;
    if payload.len() != end {
        return Err(DurableError::Invalid(
            "record tombstone length mismatch".to_string(),
        ));
    }
    Ok(std::str::from_utf8(&payload[8..])
        .map_err(|_| DurableError::Invalid(
            "record tombstone ID is not UTF-8".to_string()
        ))?
        .to_string())
}

fn edge_key(payload: &[u8]) -> DurableResult<EdgeKey> {
    if payload.len() != 32 {
        return Err(DurableError::Invalid(
            "edge payload must be 32 bytes".to_string(),
        ));
    }
    Ok(EdgeKey {
        src: read_u64(payload, 0)?,
        dst: read_u64(payload, 8)?,
        edge_type: read_u32(payload, 16)?,
        weight_bits: read_u64(payload, 24)?,
    })
}

fn encode_checkpoint_payload(
    last_lsn: u64,
    state: &RecoveredState,
    committed_transactions: &BTreeSet<[u8; 16]>,
) -> Vec<u8> {
    let state_hash = state.state_hash();
    let (record_count, edge_count) = state.counts();
    let mut payload = Vec::new();
    payload.extend_from_slice(&last_lsn.to_le_bytes());
    payload.extend_from_slice(&state_hash);
    payload.extend_from_slice(&record_count.to_le_bytes());
    payload.extend_from_slice(&edge_count.to_le_bytes());
    payload.extend_from_slice(
        &(committed_transactions.len() as u64).to_le_bytes(),
    );
    for transaction_id in committed_transactions {
        payload.extend_from_slice(transaction_id);
    }
    for entry in state.entries() {
        encode_entry_for_hash(entry, &mut payload);
    }
    payload
}

fn decode_checkpoint_payload(
    payload: &[u8],
) -> DurableResult<(
    u64,
    RecoveredState,
    BTreeSet<[u8; 16]>,
    [u8; 32],
)> {
    if payload.len() < 64 {
        return Err(DurableError::Invalid(
            "checkpoint payload is too short".to_string(),
        ));
    }
    let last_lsn = read_u64(payload, 0)?;
    let expected_state_hash = read_digest(payload, 8)?;
    let record_count = read_u64(payload, 40)?;
    let edge_count = read_u64(payload, 48)?;
    let committed_count = read_u64(payload, 56)?;
    let mut offset = 64usize;
    let mut committed = BTreeSet::new();
    for _ in 0..committed_count {
        let end = offset
            .checked_add(16)
            .ok_or_else(|| DurableError::Invalid(
                "checkpoint transaction ID overflow".to_string()
            ))?;
        let transaction_id: [u8; 16] = payload
            .get(offset..end)
            .ok_or_else(|| DurableError::Invalid(
                "checkpoint transaction ID truncated".to_string()
            ))?
            .try_into()
            .expect("checked transaction ID");
        if !committed.insert(transaction_id) {
            return Err(DurableError::Invalid(
                "duplicate checkpoint transaction ID".to_string(),
            ));
        }
        offset = end;
    }

    let total_entries = record_count
        .checked_add(edge_count)
        .ok_or_else(|| DurableError::Invalid(
            "checkpoint entry count overflow".to_string()
        ))?;
    let mut state = RecoveredState::default();
    for _ in 0..total_entries {
        let fixed_end = offset
            .checked_add(ENTRY_FIXED_BYTES)
            .ok_or_else(|| DurableError::Invalid(
                "checkpoint entry overflow".to_string()
            ))?;
        let fixed = payload
            .get(offset..fixed_end)
            .ok_or_else(|| DurableError::Invalid(
                "checkpoint entry truncated".to_string()
            ))?;
        let kind = match read_u16(fixed, 0)? {
            1 => RecordKind::Record,
            2 => RecordKind::TypedEdge,
            value => {
                return Err(DurableError::Invalid(format!(
                    "checkpoint contains non-state kind {value}"
                )))
            }
        };
        if read_u16(fixed, 2)? != 0 {
            return Err(DurableError::Invalid(
                "checkpoint entry flags non-zero".to_string(),
            ));
        }
        let logical_id = read_u64(fixed, 4)?;
        let entry_payload_bytes = usize::try_from(read_u64(fixed, 12)?)
            .map_err(|_| DurableError::Invalid(
                "checkpoint entry payload too large".to_string()
            ))?;
        let expected_hash = read_digest(fixed, 20)?;
        let entry_end = fixed_end
            .checked_add(entry_payload_bytes)
            .ok_or_else(|| DurableError::Invalid(
                "checkpoint entry length overflow".to_string()
            ))?;
        let entry_payload = payload
            .get(fixed_end..entry_end)
            .ok_or_else(|| DurableError::Invalid(
                "checkpoint entry payload truncated".to_string()
            ))?
            .to_vec();
        let actual_hash = sha256(&entry_payload);
        if actual_hash != expected_hash {
            return Err(DurableError::Integrity {
                context: "checkpoint entry".to_string(),
                expected: expected_hash,
                actual: actual_hash,
            });
        }
        state.apply(SegmentEntry::new(
            kind,
            logical_id,
            entry_payload,
        )?)?;
        offset = entry_end;
    }
    if offset != payload.len() {
        return Err(DurableError::Invalid(
            "checkpoint has trailing bytes".to_string(),
        ));
    }
    let actual_state_hash = state.state_hash();
    if actual_state_hash != expected_state_hash {
        return Err(DurableError::Integrity {
            context: "checkpoint state".to_string(),
            expected: expected_state_hash,
            actual: actual_state_hash,
        });
    }
    Ok((last_lsn, state, committed, expected_state_hash))
}

fn write_checkpoint(
    path: &Path,
    generation: u64,
    last_lsn: u64,
    state: &RecoveredState,
    committed_transactions: &BTreeSet<[u8; 16]>,
) -> DurableResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let payload = encode_checkpoint_payload(
        last_lsn,
        state,
        committed_transactions,
    );
    let (record_count, edge_count) = state.counts();
    let item_count = record_count
        .checked_add(edge_count)
        .ok_or_else(|| DurableError::Invalid(
            "checkpoint item count overflow".to_string()
        ))?;
    let header = encode_file_header(
        CHECKPOINT_MAGIC,
        generation,
        payload.len() as u64,
        item_count,
        sha256(&payload),
    );
    let temporary = temporary_path(path)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&header)?;
    file.write_all(&payload)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    publish_immutable(&temporary, path)?;
    Ok(())
}

fn read_checkpoint(
    path: &Path,
) -> DurableResult<(
    u64,
    u64,
    RecoveredState,
    BTreeSet<[u8; 16]>,
    [u8; 32],
)> {
    let (generation, _item_count, payload) =
        read_versioned_file(path, CHECKPOINT_MAGIC)?;
    let (last_lsn, state, committed, state_hash) =
        decode_checkpoint_payload(&payload)?;
    Ok((
        generation,
        last_lsn,
        state,
        committed,
        state_hash,
    ))
}

fn encode_manifest_payload(
    generation: u64,
    last_lsn: u64,
    state_sha256: [u8; 32],
    checkpoint_sha256: [u8; 32],
    checkpoint_filename: &str,
) -> DurableResult<Vec<u8>> {
    validate_single_filename(
        checkpoint_filename,
        "CHECKPOINT-",
        ".ubchk",
    )?;
    let filename = checkpoint_filename.as_bytes();
    let filename_len = u32::try_from(filename.len())
        .map_err(|_| DurableError::Invalid(
            "checkpoint filename too long".to_string()
        ))?;
    let mut payload = Vec::new();
    payload.extend_from_slice(&MANIFEST_PAYLOAD_MAGIC);
    payload.extend_from_slice(&generation.to_le_bytes());
    payload.extend_from_slice(&last_lsn.to_le_bytes());
    payload.extend_from_slice(&state_sha256);
    payload.extend_from_slice(&checkpoint_sha256);
    payload.extend_from_slice(&filename_len.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(filename);
    Ok(payload)
}

fn decode_manifest_payload(
    payload: &[u8],
) -> DurableResult<(
    u64,
    u64,
    [u8; 32],
    [u8; 32],
    String,
)> {
    if payload.len() < 96
        || &payload[0..8] != &MANIFEST_PAYLOAD_MAGIC[..]
    {
        return Err(DurableError::Invalid(
            "manifest payload header mismatch".to_string(),
        ));
    }
    let generation = read_u64(payload, 8)?;
    let last_lsn = read_u64(payload, 16)?;
    let state_sha256 = read_digest(payload, 24)?;
    let checkpoint_sha256 = read_digest(payload, 56)?;
    let filename_len = read_u32(payload, 88)? as usize;
    if read_u32(payload, 92)? != 0 {
        return Err(DurableError::Invalid(
            "manifest reserved field non-zero".to_string(),
        ));
    }
    let end = 96usize
        .checked_add(filename_len)
        .ok_or_else(|| DurableError::Invalid(
            "manifest filename overflow".to_string()
        ))?;
    if payload.len() != end {
        return Err(DurableError::Invalid(
            "manifest filename length mismatch".to_string(),
        ));
    }
    let filename = std::str::from_utf8(&payload[96..])
        .map_err(|_| DurableError::Invalid(
            "manifest filename is not UTF-8".to_string()
        ))?
        .to_string();
    validate_single_filename(&filename, "CHECKPOINT-", ".ubchk")?;
    Ok((
        generation,
        last_lsn,
        state_sha256,
        checkpoint_sha256,
        filename,
    ))
}

fn load_checkpoint(
    store: &PageStore,
) -> DurableResult<(
    RecoveredState,
    BTreeSet<[u8; 16]>,
    u64,
    u64,
)> {
    let head = match store.read_head()? {
        Some(value) => value,
        None => {
            return Ok((
                RecoveredState::default(),
                BTreeSet::new(),
                0,
                0,
            ))
        }
    };
    let manifest_path = store
        .root()
        .join("manifests")
        .join(&head.manifest_filename);
    let actual_manifest_hash = sha256_file(&manifest_path)?;
    if actual_manifest_hash != head.manifest_sha256 {
        return Err(DurableError::Integrity {
            context: "head manifest".to_string(),
            expected: head.manifest_sha256,
            actual: actual_manifest_hash,
        });
    }
    let (
        manifest_generation,
        _manifest_items,
        manifest_payload,
    ) = read_versioned_file(&manifest_path, *b"UBMETA1\0")?;
    let (
        generation,
        manifest_lsn,
        manifest_state_hash,
        checkpoint_hash,
        checkpoint_filename,
    ) = decode_manifest_payload(&manifest_payload)?;
    if generation != head.generation
        || manifest_generation != generation
    {
        return Err(DurableError::Invalid(
            "head/manifest generation mismatch".to_string(),
        ));
    }
    let checkpoint_path = store
        .root()
        .join("checkpoints")
        .join(checkpoint_filename);
    let actual_checkpoint_hash = sha256_file(&checkpoint_path)?;
    if actual_checkpoint_hash != checkpoint_hash {
        return Err(DurableError::Integrity {
            context: "manifest checkpoint".to_string(),
            expected: checkpoint_hash,
            actual: actual_checkpoint_hash,
        });
    }
    let (
        checkpoint_generation,
        checkpoint_lsn,
        state,
        committed,
        checkpoint_state_hash,
    ) = read_checkpoint(&checkpoint_path)?;
    if checkpoint_generation != generation
        || checkpoint_lsn != manifest_lsn
        || checkpoint_state_hash != manifest_state_hash
    {
        return Err(DurableError::Invalid(
            "manifest/checkpoint binding mismatch".to_string(),
        ));
    }
    Ok((state, committed, generation, checkpoint_lsn))
}

fn encode_file_header(
    magic: [u8; 8],
    generation: u64,
    payload_bytes: u64,
    item_count: u64,
    payload_sha256: [u8; 32],
) -> [u8; CHECKPOINT_HEADER_BYTES] {
    let mut header = [0u8; CHECKPOINT_HEADER_BYTES];
    header[0..8].copy_from_slice(&magic);
    header[8..10].copy_from_slice(&1u16.to_le_bytes());
    header[10..12].copy_from_slice(&0u16.to_le_bytes());
    header[12..16].copy_from_slice(
        &(CHECKPOINT_HEADER_BYTES as u32).to_le_bytes(),
    );
    header[16..24].copy_from_slice(&generation.to_le_bytes());
    header[24..32].copy_from_slice(&payload_bytes.to_le_bytes());
    header[32..40].copy_from_slice(&item_count.to_le_bytes());
    header[40..48].copy_from_slice(&0u64.to_le_bytes());
    header[48..80].copy_from_slice(&payload_sha256);
    header
}

fn read_versioned_file(
    path: &Path,
    expected_magic: [u8; 8],
) -> DurableResult<(u64, u64, Vec<u8>)> {
    let mut file = File::open(path)?;
    let file_bytes = file.metadata()?.len();
    if file_bytes < CHECKPOINT_HEADER_BYTES as u64 {
        return Err(DurableError::Invalid(
            "versioned file shorter than header".to_string(),
        ));
    }
    let mut header = [0u8; CHECKPOINT_HEADER_BYTES];
    file.read_exact(&mut header)?;
    if &header[0..8] != &expected_magic[..]
        || read_u16(&header, 8)? != 1
        || read_u16(&header, 10)? != 0
        || read_u32(&header, 12)?
            != CHECKPOINT_HEADER_BYTES as u32
        || read_u64(&header, 40)? != 0
    {
        return Err(DurableError::Invalid(
            "versioned file header mismatch".to_string(),
        ));
    }
    let generation = read_u64(&header, 16)?;
    let payload_bytes = read_u64(&header, 24)?;
    let item_count = read_u64(&header, 32)?;
    let expected_hash = read_digest(&header, 48)?;
    let expected_file_bytes = (CHECKPOINT_HEADER_BYTES as u64)
        .checked_add(payload_bytes)
        .ok_or_else(|| DurableError::Invalid(
            "versioned file length overflow".to_string()
        ))?;
    if file_bytes != expected_file_bytes {
        return Err(DurableError::Invalid(
            "versioned file length mismatch".to_string(),
        ));
    }
    let payload_len = usize::try_from(payload_bytes)
        .map_err(|_| DurableError::Invalid(
            "versioned payload too large".to_string()
        ))?;
    let mut payload = vec![0u8; payload_len];
    file.read_exact(&mut payload)?;
    let actual_hash = sha256(&payload);
    if actual_hash != expected_hash {
        return Err(DurableError::Integrity {
            context: path.display().to_string(),
            expected: expected_hash,
            actual: actual_hash,
        });
    }
    Ok((generation, item_count, payload))
}

fn read_u16(bytes: &[u8], offset: usize) -> DurableResult<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| DurableError::Invalid(
            "u16 offset overflow".to_string()
        ))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| DurableError::Invalid(
            "truncated u16".to_string()
        ))?;
    Ok(u16::from_le_bytes(value.try_into().expect("checked u16")))
}

fn read_u32(bytes: &[u8], offset: usize) -> DurableResult<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| DurableError::Invalid(
            "u32 offset overflow".to_string()
        ))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| DurableError::Invalid(
            "truncated u32".to_string()
        ))?;
    Ok(u32::from_le_bytes(value.try_into().expect("checked u32")))
}

fn read_u64(bytes: &[u8], offset: usize) -> DurableResult<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| DurableError::Invalid(
            "u64 offset overflow".to_string()
        ))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| DurableError::Invalid(
            "truncated u64".to_string()
        ))?;
    Ok(u64::from_le_bytes(value.try_into().expect("checked u64")))
}

fn read_digest(bytes: &[u8], offset: usize) -> DurableResult<[u8; 32]> {
    let end = offset
        .checked_add(32)
        .ok_or_else(|| DurableError::Invalid(
            "digest offset overflow".to_string()
        ))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| DurableError::Invalid(
            "truncated digest".to_string()
        ))?;
    Ok(value.try_into().expect("checked digest"))
}

fn validate_single_filename(
    filename: &str,
    prefix: &str,
    suffix: &str,
) -> DurableResult<()> {
    let path = Path::new(filename);
    if filename.is_empty()
        || path.is_absolute()
        || path.components().count() != 1
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_))
        })
        || !filename.starts_with(prefix)
        || !filename.ends_with(suffix)
    {
        return Err(DurableError::Invalid(
            "unsafe checkpoint filename".to_string(),
        ));
    }
    Ok(())
}

fn temporary_path(path: &Path) -> DurableResult<PathBuf> {
    let parent = path.parent().ok_or_else(|| DurableError::Invalid(
        "file has no parent".to_string()
    ))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| DurableError::Invalid(
            "filename is not UTF-8".to_string()
        ))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DurableError::Invalid(
            "system time before UNIX epoch".to_string()
        ))?
        .as_nanos();
    Ok(parent.join(format!(
        ".{name}.tmp-{}-{nonce}",
        std::process::id()
    )))
}

fn publish_immutable(
    temporary: &Path,
    destination: &Path,
) -> DurableResult<()> {
    if destination.exists() {
        let existing_hash = sha256_file(destination)?;
        let temporary_hash = sha256_file(temporary)?;
        if existing_hash == temporary_hash
            && fs::metadata(destination)?.len()
                == fs::metadata(temporary)?.len()
        {
            fs::remove_file(temporary)?;
            return Ok(());
        }
        return Err(DurableError::Invalid(
            "immutable checkpoint already exists with different bytes"
                .to_string(),
        ));
    }
    atomic_move(temporary, destination, false)?;
    sync_parent_dir(destination.parent().ok_or_else(|| {
        DurableError::Invalid("destination has no parent".to_string())
    })?)?;
    Ok(())
}

#[cfg(unix)]
fn atomic_move(
    temporary: &Path,
    destination: &Path,
    _replace: bool,
) -> DurableResult<()> {
    fs::rename(temporary, destination)?;
    Ok(())
}

#[cfg(windows)]
fn atomic_move(
    temporary: &Path,
    destination: &Path,
    replace: bool,
) -> DurableResult<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    let source: Vec<u16> = temporary
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let target: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut flags = MOVEFILE_WRITE_THROUGH;
    if replace {
        flags |= MOVEFILE_REPLACE_EXISTING;
    }
    let result = unsafe {
        MoveFileExW(source.as_ptr(), target.as_ptr(), flags)
    };
    if result == 0 {
        return Err(DurableError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(windows)]
#[link(name = "Kernel32")]
extern "system" {
    fn MoveFileExW(
        existing_file_name: *const u16,
        new_file_name: *const u16,
        flags: u32,
    ) -> i32;
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> DurableResult<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_parent_dir(_path: &Path) -> DurableResult<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn atomic_move(
    temporary: &Path,
    destination: &Path,
    replace: bool,
) -> DurableResult<()> {
    if destination.exists() && replace {
        fs::remove_file(destination)?;
    }
    fs::rename(temporary, destination)?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_parent_dir(_path: &Path) -> DurableResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BatchLimits, TransactionCore, WriteBatch};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn root(name: &str) -> PathBuf {
        let value = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "ultraballoondb-durable-{name}-{}-{value}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn durable_commit_checkpoint_and_restart() {
        let root = root("restart");
        let mut database = DurableDatabase::create(&root).unwrap();
        let mut core = TransactionCore::new(BatchLimits::default());
        let transaction_id = TransactionId::new([1; 16]);
        core.begin(transaction_id).unwrap();
        core.put_record(1, "alpha", 10, b"payload").unwrap();
        core.put_edge(2, 10, 20, 7, 0.75).unwrap();
        core.prepare().unwrap();
        let receipt = core
            .commit_durable(&mut database, 1, 0)
            .unwrap();
        assert!(receipt.durable_commit);
        assert!(receipt.wal_recorded);
        assert!(receipt.wal_fsynced);
        assert_eq!(
            core.active_state(),
            Some(TransactionState::DurableCommitted)
        );
        core.release_terminal(transaction_id).unwrap();
        database.checkpoint(1).unwrap();
        let expected_hash = database.state_sha256();
        drop(database);

        let reopened = DurableDatabase::open(&root, true).unwrap();
        assert_eq!(reopened.state_sha256(), expected_hash);
        assert_eq!(reopened.state_counts(), (1, 1));
        drop(reopened);
        let reopened_again = DurableDatabase::open(&root, true).unwrap();
        assert_eq!(reopened_again.state_sha256(), expected_hash);
        drop(reopened_again);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn uncommitted_transaction_is_ignored() {
        let root = root("uncommitted");
        let mut database = DurableDatabase::create(&root).unwrap();
        let mut batch = WriteBatch::new(BatchLimits::default());
        batch.put_record(1, "alpha", 10, b"payload").unwrap();
        let prepared = batch.prepare(TransactionId::new([2; 16]));
        database
            .append_uncommitted_for_probe(&prepared)
            .unwrap();
        drop(database);
        let reopened = DurableDatabase::open(&root, true).unwrap();
        assert_eq!(reopened.state_counts(), (0, 0));
        assert_eq!(
            reopened.recovery_receipt().ignored_uncommitted_count,
            1
        );
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }
}
