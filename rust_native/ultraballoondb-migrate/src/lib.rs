use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ultraballoondb_lifecycle::{
    BatchLimits, DurableDatabase, TransactionCore, TransactionId,
};
use ultraballoondb_storage::{hex_digest, sha256};

pub const PLAN_MAGIC: [u8; 8] = *b"UBMIG01\0";
pub const PLAN_MAJOR: u16 = 1;
pub const PLAN_HEADER_BYTES: usize = 160;
pub const ENTRY_FIXED_BYTES: usize = 52;
pub const SEMANTIC_MAGIC: [u8; 8] = *b"UBMIGS1\0";
pub const DEFAULT_MAX_OPERATIONS_PER_BATCH: usize = 10_000;
pub const DEFAULT_MAX_PAYLOAD_BYTES_PER_BATCH: u64 = 128 * 1024 * 1024;

#[derive(Debug)]
pub enum MigrationError {
    Io(io::Error),
    Invalid(String),
    Integrity {
        context: String,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    Lifecycle(String),
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Invalid(message) => write!(f, "invalid migration plan: {message}"),
            Self::Integrity {
                context,
                expected,
                actual,
            } => write!(
                f,
                "migration integrity mismatch for {context}: expected={} actual={}",
                hex_digest(expected),
                hex_digest(actual),
            ),
            Self::Lifecycle(message) => write!(f, "lifecycle error: {message}"),
        }
    }
}

impl std::error::Error for MigrationError {}

impl From<io::Error> for MigrationError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, MigrationError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationRecord {
    pub logical_id: u64,
    pub record_id: String,
    pub node_id: u64,
    pub payload: Vec<u8>,
    pub payload_sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq)]
pub struct MigrationEdge {
    pub logical_id: u64,
    pub src: u64,
    pub dst: u64,
    pub edge_type: u32,
    pub weight: f64,
    pub weight_million: i64,
}

#[derive(Clone, Debug)]
pub enum MigrationOperation {
    Record(MigrationRecord),
    Edge(MigrationEdge),
}

impl MigrationOperation {
    fn logical_id(&self) -> u64 {
        match self {
            Self::Record(record) => record.logical_id,
            Self::Edge(edge) => edge.logical_id,
        }
    }

    fn payload_bytes(&self) -> u64 {
        match self {
            Self::Record(record) => record.payload.len() as u64,
            Self::Edge(_) => 32,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MigrationPlan {
    pub record_count: u64,
    pub edge_count: u64,
    pub source_committed_transaction_count: u64,
    pub source_checkpoint_lsn: u64,
    pub source_last_valid_lsn: u64,
    pub source_python_state_sha256: [u8; 32],
    pub semantic_state_sha256: [u8; 32],
    pub payload_sha256: [u8; 32],
    pub operations: Vec<MigrationOperation>,
}

#[derive(Clone, Debug)]
pub struct MigrationReceipt {
    pub source_python_state_sha256: [u8; 32],
    pub semantic_state_sha256: [u8; 32],
    pub target_state_sha256: [u8; 32],
    pub record_count: u64,
    pub edge_count: u64,
    pub source_committed_transaction_count: u64,
    pub canonical_batch_count: u64,
    pub durable_commit_count: u64,
    pub checkpoint_generation: u64,
    pub checkpoint_lsn: u64,
    pub target_root: PathBuf,
    pub target_wal_path: PathBuf,
    pub target_checkpoint_path: PathBuf,
    pub target_manifest_path: PathBuf,
    pub target_head_path: PathBuf,
    pub restart_deterministic: bool,
    pub source_overwritten: bool,
    pub active_runtime_changed: bool,
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| MigrationError::Invalid("u16 offset overflow".to_string()))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| MigrationError::Invalid("truncated u16".to_string()))?;
    Ok(u16::from_le_bytes(value.try_into().expect("checked u16")))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| MigrationError::Invalid("u32 offset overflow".to_string()))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| MigrationError::Invalid("truncated u32".to_string()))?;
    Ok(u32::from_le_bytes(value.try_into().expect("checked u32")))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| MigrationError::Invalid("u64 offset overflow".to_string()))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| MigrationError::Invalid("truncated u64".to_string()))?;
    Ok(u64::from_le_bytes(value.try_into().expect("checked u64")))
}

fn read_digest(bytes: &[u8], offset: usize) -> Result<[u8; 32]> {
    let end = offset
        .checked_add(32)
        .ok_or_else(|| MigrationError::Invalid("digest offset overflow".to_string()))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| MigrationError::Invalid("truncated digest".to_string()))?;
    Ok(value.try_into().expect("checked digest"))
}

fn parse_record(
    logical_id: u64,
    payload: &[u8],
) -> Result<MigrationRecord> {
    if payload.len() < 56 {
        return Err(MigrationError::Invalid(
            "record payload shorter than 56 bytes".to_string(),
        ));
    }
    let record_id_bytes = read_u32(payload, 0)? as usize;
    if read_u32(payload, 4)? != 0 {
        return Err(MigrationError::Invalid(
            "record reserved field is non-zero".to_string(),
        ));
    }
    let node_id = read_u64(payload, 8)?;
    let user_payload_bytes = usize::try_from(read_u64(payload, 16)?)
        .map_err(|_| MigrationError::Invalid(
            "record user payload too large".to_string()
        ))?;
    let expected_user_hash = read_digest(payload, 24)?;
    let record_id_end = 56usize
        .checked_add(record_id_bytes)
        .ok_or_else(|| MigrationError::Invalid(
            "record ID length overflow".to_string()
        ))?;
    let payload_end = record_id_end
        .checked_add(user_payload_bytes)
        .ok_or_else(|| MigrationError::Invalid(
            "record payload length overflow".to_string()
        ))?;
    if payload_end != payload.len() {
        return Err(MigrationError::Invalid(
            "record payload length mismatch".to_string(),
        ));
    }
    let record_id = std::str::from_utf8(&payload[56..record_id_end])
        .map_err(|_| MigrationError::Invalid(
            "record ID is not UTF-8".to_string()
        ))?
        .to_string();
    if record_id.is_empty() {
        return Err(MigrationError::Invalid(
            "record ID is empty".to_string(),
        ));
    }
    let user_payload = payload[record_id_end..].to_vec();
    let actual_user_hash = sha256(&user_payload);
    if actual_user_hash != expected_user_hash {
        return Err(MigrationError::Integrity {
            context: format!("record {record_id} payload"),
            expected: expected_user_hash,
            actual: actual_user_hash,
        });
    }
    Ok(MigrationRecord {
        logical_id,
        record_id,
        node_id,
        payload: user_payload,
        payload_sha256: expected_user_hash,
    })
}

fn parse_edge(
    logical_id: u64,
    payload: &[u8],
) -> Result<MigrationEdge> {
    if payload.len() != 32 {
        return Err(MigrationError::Invalid(
            "edge payload must be 32 bytes".to_string(),
        ));
    }
    let src = read_u64(payload, 0)?;
    let dst = read_u64(payload, 8)?;
    let edge_type = read_u32(payload, 16)?;
    if read_u32(payload, 20)? != 0 {
        return Err(MigrationError::Invalid(
            "edge reserved field is non-zero".to_string(),
        ));
    }
    let weight_bits = read_u64(payload, 24)?;
    let weight = f64::from_bits(weight_bits);
    if !weight.is_finite() || !(0.0..=1.0).contains(&weight) {
        return Err(MigrationError::Invalid(
            "edge weight is outside [0,1]".to_string(),
        ));
    }
    let weight_million = (weight * 1_000_000.0).round() as i64;
    if !(0..=1_000_000).contains(&weight_million) {
        return Err(MigrationError::Invalid(
            "edge weight_million outside range".to_string(),
        ));
    }
    Ok(MigrationEdge {
        logical_id,
        src,
        dst,
        edge_type,
        weight,
        weight_million,
    })
}

fn semantic_hash(operations: &[MigrationOperation]) -> [u8; 32] {
    let mut records: Vec<&MigrationRecord> = operations
        .iter()
        .filter_map(|operation| match operation {
            MigrationOperation::Record(record) => Some(record),
            MigrationOperation::Edge(_) => None,
        })
        .collect();
    let mut edges: Vec<&MigrationEdge> = operations
        .iter()
        .filter_map(|operation| match operation {
            MigrationOperation::Record(_) => None,
            MigrationOperation::Edge(edge) => Some(edge),
        })
        .collect();
    records.sort_by(|left, right| left.record_id.cmp(&right.record_id));
    edges.sort_by_key(|edge| (
        edge.src,
        edge.dst,
        edge.edge_type,
        edge.weight_million,
    ));

    let mut preimage = Vec::new();
    preimage.extend_from_slice(&SEMANTIC_MAGIC);
    preimage.extend_from_slice(&(records.len() as u64).to_le_bytes());
    preimage.extend_from_slice(&(edges.len() as u64).to_le_bytes());
    for record in records {
        let record_id = record.record_id.as_bytes();
        preimage.extend_from_slice(&(record_id.len() as u32).to_le_bytes());
        preimage.extend_from_slice(record_id);
        preimage.extend_from_slice(&record.node_id.to_le_bytes());
        preimage.extend_from_slice(&(record.payload.len() as u64).to_le_bytes());
        preimage.extend_from_slice(&record.payload_sha256);
        preimage.extend_from_slice(&record.payload);
    }
    for edge in edges {
        preimage.extend_from_slice(&edge.src.to_le_bytes());
        preimage.extend_from_slice(&edge.dst.to_le_bytes());
        preimage.extend_from_slice(&edge.edge_type.to_le_bytes());
        preimage.extend_from_slice(&edge.weight_million.to_le_bytes());
    }
    sha256(&preimage)
}

impl MigrationPlan {
    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = fs::read(path)?;
        if bytes.len() < PLAN_HEADER_BYTES {
            return Err(MigrationError::Invalid(
                "plan shorter than header".to_string(),
            ));
        }
        if bytes[0..8] != PLAN_MAGIC[..] {
            return Err(MigrationError::Invalid(
                "plan magic mismatch".to_string(),
            ));
        }
        if read_u16(&bytes, 8)? != PLAN_MAJOR
            || read_u16(&bytes, 10)? != 0
            || read_u32(&bytes, 12)? != PLAN_HEADER_BYTES as u32
        {
            return Err(MigrationError::Invalid(
                "plan version/header mismatch".to_string(),
            ));
        }

        let record_count = read_u64(&bytes, 16)?;
        let edge_count = read_u64(&bytes, 24)?;
        let source_committed_transaction_count = read_u64(&bytes, 32)?;
        let source_checkpoint_lsn = read_u64(&bytes, 40)?;
        let source_last_valid_lsn = read_u64(&bytes, 48)?;
        let payload_bytes = usize::try_from(read_u64(&bytes, 56)?)
            .map_err(|_| MigrationError::Invalid(
                "plan payload too large".to_string()
            ))?;
        let source_python_state_sha256 = read_digest(&bytes, 64)?;
        let semantic_state_sha256 = read_digest(&bytes, 96)?;
        let payload_sha256 = read_digest(&bytes, 128)?;

        let expected_file_bytes = PLAN_HEADER_BYTES
            .checked_add(payload_bytes)
            .ok_or_else(|| MigrationError::Invalid(
                "plan length overflow".to_string()
            ))?;
        if bytes.len() != expected_file_bytes {
            return Err(MigrationError::Invalid(
                "plan file length mismatch".to_string(),
            ));
        }
        let payload = &bytes[PLAN_HEADER_BYTES..];
        let actual_payload_hash = sha256(payload);
        if actual_payload_hash != payload_sha256 {
            return Err(MigrationError::Integrity {
                context: "plan payload".to_string(),
                expected: payload_sha256,
                actual: actual_payload_hash,
            });
        }

        let expected_entries = record_count
            .checked_add(edge_count)
            .ok_or_else(|| MigrationError::Invalid(
                "plan entry count overflow".to_string()
            ))?;
        let mut offset = 0usize;
        let mut operations = Vec::with_capacity(
            usize::try_from(expected_entries).map_err(|_| {
                MigrationError::Invalid(
                    "plan entry count too large".to_string()
                )
            })?,
        );
        let mut previous_logical_id = 0u64;
        for index in 0..expected_entries {
            let fixed_end = offset
                .checked_add(ENTRY_FIXED_BYTES)
                .ok_or_else(|| MigrationError::Invalid(
                    "entry fixed length overflow".to_string()
                ))?;
            let fixed = payload
                .get(offset..fixed_end)
                .ok_or_else(|| MigrationError::Invalid(
                    "truncated plan entry".to_string()
                ))?;
            let kind = read_u16(fixed, 0)?;
            if read_u16(fixed, 2)? != 0 {
                return Err(MigrationError::Invalid(
                    "plan entry flags are non-zero".to_string(),
                ));
            }
            let logical_id = read_u64(fixed, 4)?;
            if logical_id == 0 || logical_id <= previous_logical_id {
                return Err(MigrationError::Invalid(
                    "logical IDs are not strictly increasing".to_string(),
                ));
            }
            previous_logical_id = logical_id;
            let entry_payload_bytes = usize::try_from(read_u64(fixed, 12)?)
                .map_err(|_| MigrationError::Invalid(
                    "entry payload too large".to_string()
                ))?;
            let expected_entry_hash = read_digest(fixed, 20)?;
            let entry_end = fixed_end
                .checked_add(entry_payload_bytes)
                .ok_or_else(|| MigrationError::Invalid(
                    "entry length overflow".to_string()
                ))?;
            let entry_payload = payload
                .get(fixed_end..entry_end)
                .ok_or_else(|| MigrationError::Invalid(
                    "truncated entry payload".to_string()
                ))?;
            let actual_entry_hash = sha256(entry_payload);
            if actual_entry_hash != expected_entry_hash {
                return Err(MigrationError::Integrity {
                    context: format!("entry {index}"),
                    expected: expected_entry_hash,
                    actual: actual_entry_hash,
                });
            }
            let operation = match kind {
                1 => MigrationOperation::Record(
                    parse_record(logical_id, entry_payload)?,
                ),
                2 => MigrationOperation::Edge(
                    parse_edge(logical_id, entry_payload)?,
                ),
                value => {
                    return Err(MigrationError::Invalid(format!(
                        "unknown migration entry kind {value}"
                    )))
                }
            };
            operations.push(operation);
            offset = entry_end;
        }
        if offset != payload.len() {
            return Err(MigrationError::Invalid(
                "plan payload has trailing bytes".to_string(),
            ));
        }
        let actual_records = operations
            .iter()
            .filter(|value| matches!(value, MigrationOperation::Record(_)))
            .count() as u64;
        let actual_edges = operations
            .iter()
            .filter(|value| matches!(value, MigrationOperation::Edge(_)))
            .count() as u64;
        if actual_records != record_count || actual_edges != edge_count {
            return Err(MigrationError::Invalid(
                "plan record/edge count mismatch".to_string(),
            ));
        }
        let actual_semantic = semantic_hash(&operations);
        if actual_semantic != semantic_state_sha256 {
            return Err(MigrationError::Integrity {
                context: "cross-format semantic state".to_string(),
                expected: semantic_state_sha256,
                actual: actual_semantic,
            });
        }

        Ok(Self {
            record_count,
            edge_count,
            source_committed_transaction_count,
            source_checkpoint_lsn,
            source_last_valid_lsn,
            source_python_state_sha256,
            semantic_state_sha256,
            payload_sha256,
            operations,
        })
    }
}

fn deterministic_transaction_id(
    semantic_state_sha256: [u8; 32],
    batch_index: u64,
) -> TransactionId {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"UBMIGTX\0");
    preimage.extend_from_slice(&semantic_state_sha256);
    preimage.extend_from_slice(&batch_index.to_le_bytes());
    let digest = sha256(&preimage);
    TransactionId::new(
        digest[0..16].try_into().expect("fixed transaction ID"),
    )
}

pub fn import_plan(
    plan: &MigrationPlan,
    target_root: impl AsRef<Path>,
) -> Result<MigrationReceipt> {
    let target_root = target_root.as_ref().to_path_buf();
    if target_root.exists() {
        return Err(MigrationError::Invalid(format!(
            "target root already exists: {}",
            target_root.display()
        )));
    }

    let mut database = DurableDatabase::create(&target_root)
        .map_err(|error| MigrationError::Lifecycle(error.to_string()))?;
    let mut core = TransactionCore::new(BatchLimits {
        max_operations: DEFAULT_MAX_OPERATIONS_PER_BATCH,
        max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES_PER_BATCH,
    });

    let mut batch_index = 0u64;
    let mut operation_index = 0usize;
    let mut durable_commit_count = 0u64;

    while operation_index < plan.operations.len() {
        batch_index = batch_index
            .checked_add(1)
            .ok_or_else(|| MigrationError::Invalid(
                "batch index overflow".to_string()
            ))?;
        let transaction_id = deterministic_transaction_id(
            plan.semantic_state_sha256,
            batch_index,
        );
        core.begin(transaction_id)
            .map_err(|error| MigrationError::Lifecycle(error.to_string()))?;

        let mut added = 0usize;
        let mut payload_bytes = 0u64;
        while operation_index < plan.operations.len()
            && added < DEFAULT_MAX_OPERATIONS_PER_BATCH
        {
            let operation = &plan.operations[operation_index];
            let next_payload = payload_bytes
                .checked_add(operation.payload_bytes())
                .ok_or_else(|| MigrationError::Invalid(
                    "batch payload overflow".to_string()
                ))?;
            if added > 0
                && next_payload > DEFAULT_MAX_PAYLOAD_BYTES_PER_BATCH
            {
                break;
            }
            match operation {
                MigrationOperation::Record(record) => {
                    core.put_record(
                        record.logical_id,
                        &record.record_id,
                        record.node_id,
                        &record.payload,
                    )
                    .map_err(|error| {
                        MigrationError::Lifecycle(error.to_string())
                    })?;
                }
                MigrationOperation::Edge(edge) => {
                    core.put_edge(
                        edge.logical_id,
                        edge.src,
                        edge.dst,
                        edge.edge_type,
                        edge.weight,
                    )
                    .map_err(|error| {
                        MigrationError::Lifecycle(error.to_string())
                    })?;
                }
            }
            payload_bytes = next_payload;
            operation_index += 1;
            added += 1;
        }
        if added == 0 {
            return Err(MigrationError::Invalid(
                "single migration operation exceeds batch limit".to_string(),
            ));
        }

        core.prepare()
            .map_err(|error| MigrationError::Lifecycle(error.to_string()))?;
        let receipt = core
            .commit_durable(&mut database, batch_index, 0)
            .map_err(|error| MigrationError::Lifecycle(error.to_string()))?;
        if !receipt.durable_commit
            || !receipt.wal_recorded
            || !receipt.wal_fsynced
        {
            return Err(MigrationError::Invalid(
                "canonical durable commit receipt is incomplete".to_string(),
            ));
        }
        core.release_terminal(transaction_id)
            .map_err(|error| MigrationError::Lifecycle(error.to_string()))?;
        durable_commit_count = durable_commit_count
            .checked_add(1)
            .ok_or_else(|| MigrationError::Invalid(
                "durable commit count overflow".to_string()
            ))?;
    }

    let checkpoint_generation = batch_index
        .checked_add(1)
        .ok_or_else(|| MigrationError::Invalid(
            "checkpoint generation overflow".to_string()
        ))?;
    let checkpoint = database
        .checkpoint(checkpoint_generation)
        .map_err(|error| MigrationError::Lifecycle(error.to_string()))?;
    if !checkpoint.head_published || !checkpoint.wal_checkpoint_recorded {
        return Err(MigrationError::Invalid(
            "canonical checkpoint receipt is incomplete".to_string(),
        ));
    }

    let target_state_sha256 = database.state_sha256();
    let counts = database.state_counts();
    let target_wal_path = database.wal_path().to_path_buf();
    if counts != (plan.record_count, plan.edge_count) {
        return Err(MigrationError::Invalid(format!(
            "target state count mismatch: expected=({}, {}) actual=({}, {})",
            plan.record_count,
            plan.edge_count,
            counts.0,
            counts.1,
        )));
    }
    drop(database);

    let reopened = DurableDatabase::open(&target_root, true)
        .map_err(|error| MigrationError::Lifecycle(error.to_string()))?;
    let restart_deterministic = reopened.state_sha256() == target_state_sha256
        && reopened.state_counts() == counts
        && reopened.recovery_receipt().replayed_transaction_count == 0
        && reopened.recovery_receipt().ignored_uncommitted_count == 0
        && reopened.recovery_receipt().repaired_trailing_bytes == 0;
    if !restart_deterministic {
        return Err(MigrationError::Invalid(
            "target restart determinism failed".to_string(),
        ));
    }
    drop(reopened);

    Ok(MigrationReceipt {
        source_python_state_sha256: plan.source_python_state_sha256,
        semantic_state_sha256: plan.semantic_state_sha256,
        target_state_sha256,
        record_count: plan.record_count,
        edge_count: plan.edge_count,
        source_committed_transaction_count:
            plan.source_committed_transaction_count,
        canonical_batch_count: batch_index,
        durable_commit_count,
        checkpoint_generation,
        checkpoint_lsn: checkpoint.checkpoint_lsn,
        target_root,
        target_wal_path,
        target_checkpoint_path: checkpoint.checkpoint_path,
        target_manifest_path: checkpoint.manifest_path,
        target_head_path: checkpoint.head_path,
        restart_deterministic,
        source_overwritten: false,
        active_runtime_changed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_plan_header_size() {
        assert_eq!(PLAN_HEADER_BYTES, 160);
        assert_eq!(ENTRY_FIXED_BYTES, 52);
        assert_eq!(PLAN_MAGIC, *b"UBMIG01\0");
    }

    #[test]
    fn deterministic_transaction_ids_are_stable_and_distinct() {
        let semantic = [7u8; 32];
        let first = deterministic_transaction_id(semantic, 1);
        let same = deterministic_transaction_id(semantic, 1);
        let second = deterministic_transaction_id(semantic, 2);
        assert_eq!(first, same);
        assert_ne!(first, second);
    }
}
