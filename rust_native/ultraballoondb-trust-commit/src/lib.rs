use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use ultraballoondb_lifecycle::{
    BatchLimits, DatabaseRecord, DurableDatabase, TransactionCore,
    TransactionId,
};
use ultraballoondb_storage::{hex_digest, sha256};
use ultraballoondb_trust::{
    EvidenceRef, TransitionAuthority, TransitionIntent, TrustLedger,
    TrustOperation, TrustTransition,
};

pub const POLICY_LEDGER_MAGIC: [u8; 8] = *b"UBPOL01\0";
pub const POLICY_PAYLOAD_MAGIC: [u8; 8] = *b"UBPYP01\0";
pub const COMMIT_LEDGER_MAGIC: [u8; 8] = *b"UBTCJ01\0";
pub const COMMIT_PAYLOAD_MAGIC: [u8; 8] = *b"UBTCP01\0";
pub const BINDING_PAYLOAD_MAGIC: [u8; 8] = *b"UBTBD01\0";
pub const RECORD_DIGEST_DOMAIN: [u8; 8] = *b"UBTRREC1";
pub const POLICY_DIGEST_DOMAIN: [u8; 8] = *b"UBTRPOL1";
pub const REQUEST_DIGEST_DOMAIN: [u8; 8] = *b"UBTRREQ1";
pub const TRANSACTION_ID_DOMAIN: [u8; 8] = *b"UBTRTXN1";
pub const POLICY_FRAME_HEADER_BYTES: usize = 144;
pub const COMMIT_FRAME_HEADER_BYTES: usize = 144;
pub const POLICY_PAYLOAD_FIXED_BYTES: usize = 40;
pub const COMMIT_PAYLOAD_FIXED_BYTES: usize = 320;
pub const MAX_FRAME_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_STRING_BYTES: usize = 1024 * 1024;
pub const BINDING_RECORD_PREFIX: &str = "__ubdb_trust_binding__/";

#[derive(Debug)]
pub enum CommitError {
    Io(io::Error),
    Invalid(String),
    Integrity {
        context: String,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    TruncatedTail {
        context: &'static str,
        offset: usize,
        remaining_bytes: usize,
    },
    Lifecycle(String),
    Trust(String),
}

impl fmt::Display for CommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Invalid(message) => write!(f, "invalid trust co-commit: {message}"),
            Self::Integrity {
                context,
                expected,
                actual,
            } => write!(
                f,
                "trust co-commit integrity mismatch for {context}: expected={} actual={}",
                hex_digest(expected),
                hex_digest(actual),
            ),
            Self::TruncatedTail {
                context,
                offset,
                remaining_bytes,
            } => write!(
                f,
                "truncated {context} tail at offset {offset}: remaining_bytes={remaining_bytes}",
            ),
            Self::Lifecycle(message) => write!(f, "lifecycle error: {message}"),
            Self::Trust(message) => write!(f, "trust error: {message}"),
        }
    }
}

impl std::error::Error for CommitError {}

impl From<io::Error> for CommitError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, CommitError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDefinition {
    pub policy_id: String,
    pub policy_version: String,
    pub allowed_authority: TransitionAuthority,
    pub allowed_operation_mask: u16,
    pub min_evidence_refs: u32,
    pub max_evidence_refs: u32,
    pub required_verifier_id: String,
    pub require_unique_provenance: bool,
}

impl PolicyDefinition {
    pub fn operation_mask(operations: &[TrustOperation]) -> u16 {
        let mut value = 0u16;
        for operation in operations {
            value |= operation_bit(*operation);
        }
        value
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        validate_policy(self)?;
        let payload = encode_policy_payload(self)?;
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&POLICY_DIGEST_DOMAIN);
        preimage.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        preimage.extend_from_slice(&payload);
        Ok(sha256(&preimage))
    }

    pub fn allows(&self, operation: TrustOperation) -> bool {
        self.allowed_operation_mask & operation_bit(operation) != 0
    }
}

#[derive(Debug)]
pub struct PolicyRegistry {
    path: PathBuf,
    policies: BTreeMap<(String, String), PolicyDefinition>,
    digests: BTreeMap<(String, String), [u8; 32]>,
    frame_count: u64,
    head_digest: [u8; 32],
}

impl PolicyRegistry {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(CommitError::Invalid(format!(
                "policy registry already exists: {}",
                path.display(),
            )));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?
            .sync_all()?;
        Ok(Self {
            path,
            policies: BTreeMap::new(),
            digests: BTreeMap::new(),
            frame_count: 0,
            head_digest: [0; 32],
        })
    }

    pub fn open_strict(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.is_file() {
            return Err(CommitError::Invalid(format!(
                "policy registry file missing: {}",
                path.display(),
            )));
        }
        let bytes = fs::read(&path)?;
        let mut registry = Self {
            path,
            policies: BTreeMap::new(),
            digests: BTreeMap::new(),
            frame_count: 0,
            head_digest: [0; 32],
        };
        registry.replay(&bytes)?;
        Ok(registry)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    pub fn frame_count(&self) -> u64 {
        self.frame_count
    }

    pub fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }

    pub fn get(
        &self,
        policy_id: &str,
        policy_version: &str,
    ) -> Option<&PolicyDefinition> {
        self.policies
            .get(&(policy_id.to_string(), policy_version.to_string()))
    }

    pub fn policy_digest(
        &self,
        policy_id: &str,
        policy_version: &str,
    ) -> Option<[u8; 32]> {
        self.digests
            .get(&(policy_id.to_string(), policy_version.to_string()))
            .copied()
    }

    pub fn register(
        &mut self,
        policy: PolicyDefinition,
    ) -> Result<[u8; 32]> {
        validate_policy(&policy)?;
        let key = (
            policy.policy_id.clone(),
            policy.policy_version.clone(),
        );
        if self.policies.contains_key(&key) {
            return Err(CommitError::Invalid(format!(
                "policy version already registered: {}@{}",
                policy.policy_id,
                policy.policy_version,
            )));
        }
        let payload = encode_policy_payload(&policy)?;
        let policy_digest = policy.digest()?;
        let sequence = self
            .frame_count
            .checked_add(1)
            .ok_or_else(|| CommitError::Invalid(
                "policy registry sequence overflow".to_string(),
            ))?;
        let payload_digest = sha256(&payload);
        let frame_digest = compute_chain_digest(
            b"UBPOLFR1",
            sequence,
            self.head_digest,
            payload_digest,
        );
        let frame = encode_chain_frame(
            POLICY_LEDGER_MAGIC,
            POLICY_FRAME_HEADER_BYTES,
            sequence,
            self.head_digest,
            payload_digest,
            frame_digest,
            &payload,
        )?;
        append_fsync(&self.path, &frame)?;
        self.frame_count = sequence;
        self.head_digest = frame_digest;
        self.digests.insert(key.clone(), policy_digest);
        self.policies.insert(key, policy);
        Ok(policy_digest)
    }

    pub fn authorize(&self, request: &TrustCommitRequest) -> Result<[u8; 32]> {
        let key = (
            request.policy_id.clone(),
            request.policy_version.clone(),
        );
        let policy = self.policies.get(&key).ok_or_else(|| {
            CommitError::Invalid(format!(
                "policy is not registered: {}@{}",
                request.policy_id,
                request.policy_version,
            ))
        })?;
        let digest = self.digests.get(&key).copied().ok_or_else(|| {
            CommitError::Invalid(
                "policy digest missing from registry".to_string(),
            )
        })?;
        if policy.allowed_authority != request.authority {
            return Err(CommitError::Invalid(format!(
                "policy authority mismatch: policy={} request={}",
                authority_name(policy.allowed_authority),
                authority_name(request.authority),
            )));
        }
        if !policy.allows(request.operation) {
            return Err(CommitError::Invalid(format!(
                "operation {} is not allowed by policy {}@{}",
                operation_name(request.operation),
                policy.policy_id,
                policy.policy_version,
            )));
        }
        let evidence_count = u32::try_from(request.evidence_refs.len())
            .map_err(|_| CommitError::Invalid(
                "evidence count overflow".to_string(),
            ))?;
        if evidence_count < policy.min_evidence_refs
            || evidence_count > policy.max_evidence_refs
        {
            return Err(CommitError::Invalid(format!(
                "evidence count outside policy range: actual={} min={} max={}",
                evidence_count,
                policy.min_evidence_refs,
                policy.max_evidence_refs,
            )));
        }
        if request.verifier_id != policy.required_verifier_id {
            return Err(CommitError::Invalid(format!(
                "verifier is not authorized by policy: expected={} actual={}",
                policy.required_verifier_id,
                request.verifier_id,
            )));
        }
        if policy.require_unique_provenance {
            let mut values = BTreeSet::new();
            for evidence in &request.evidence_refs {
                if !values.insert(evidence.provenance_id.clone()) {
                    return Err(CommitError::Invalid(format!(
                        "policy requires unique provenance: {}",
                        evidence.provenance_id,
                    )));
                }
            }
        }
        Ok(digest)
    }

    fn replay(&mut self, bytes: &[u8]) -> Result<()> {
        let frames = decode_chain_frames(
            "policy registry",
            POLICY_LEDGER_MAGIC,
            POLICY_FRAME_HEADER_BYTES,
            b"UBPOLFR1",
            bytes,
        )?;
        for frame in frames {
            let policy = decode_policy_payload(&frame.payload)?;
            validate_policy(&policy)?;
            let key = (
                policy.policy_id.clone(),
                policy.policy_version.clone(),
            );
            if self.policies.contains_key(&key) {
                return Err(CommitError::Invalid(format!(
                    "duplicate policy during replay: {}@{}",
                    policy.policy_id,
                    policy.policy_version,
                )));
            }
            let policy_digest = policy.digest()?;
            self.digests.insert(key.clone(), policy_digest);
            self.policies.insert(key, policy);
            self.frame_count = frame.sequence;
            self.head_digest = frame.frame_digest;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustCommitRequest {
    pub record_id: String,
    pub operation: TrustOperation,
    pub authority: TransitionAuthority,
    pub evidence_refs: Vec<EvidenceRef>,
    pub policy_id: String,
    pub policy_version: String,
    pub verifier_id: String,
    pub logical_timestamp: u64,
    pub reason_code: String,
    pub superseding_record_id: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CommitStage {
    Prepared = 1,
    DatabaseCommitted = 2,
    TrustCommitted = 3,
    Finalized = 4,
    Aborted = 5,
}

impl CommitStage {
    fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::DatabaseCommitted),
            3 => Ok(Self::TrustCommitted),
            4 => Ok(Self::Finalized),
            5 => Ok(Self::Aborted),
            _ => Err(CommitError::Invalid(format!(
                "unknown commit stage code {value}",
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "PREPARED",
            Self::DatabaseCommitted => "DATABASE_COMMITTED",
            Self::TrustCommitted => "TRUST_COMMITTED",
            Self::Finalized => "FINALIZED",
            Self::Aborted => "ABORTED",
        }
    }

    fn terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Aborted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitJournalEntry {
    pub journal_sequence: u64,
    pub transaction_id: [u8; 32],
    pub stage: CommitStage,
    pub request: TrustCommitRequest,
    pub record_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub trust_pre_head: [u8; 32],
    pub expected_trust_sequence: u64,
    pub binding_record_id: String,
    pub binding_record_digest: [u8; 32],
    pub database_state_digest: [u8; 32],
    pub trust_transition_id: [u8; 32],
    pub previous_journal_digest: [u8; 32],
    pub journal_digest: [u8; 32],
}

#[derive(Debug)]
pub struct TrustCommitJournal {
    path: PathBuf,
    entries: Vec<CommitJournalEntry>,
    latest: BTreeMap<[u8; 32], CommitJournalEntry>,
    head_digest: [u8; 32],
}

impl TrustCommitJournal {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(CommitError::Invalid(format!(
                "commit journal already exists: {}",
                path.display(),
            )));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?
            .sync_all()?;
        Ok(Self {
            path,
            entries: Vec::new(),
            latest: BTreeMap::new(),
            head_digest: [0; 32],
        })
    }

    pub fn open_strict(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.is_file() {
            return Err(CommitError::Invalid(format!(
                "commit journal file missing: {}",
                path.display(),
            )));
        }
        let bytes = fs::read(&path)?;
        let mut journal = Self {
            path,
            entries: Vec::new(),
            latest: BTreeMap::new(),
            head_digest: [0; 32],
        };
        journal.replay(&bytes)?;
        Ok(journal)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn entries(&self) -> &[CommitJournalEntry] {
        &self.entries
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }

    pub fn latest(
        &self,
        transaction_id: &[u8; 32],
    ) -> Option<&CommitJournalEntry> {
        self.latest.get(transaction_id)
    }

    pub fn pending(&self) -> Vec<CommitJournalEntry> {
        self.latest
            .values()
            .filter(|entry| !entry.stage.terminal())
            .cloned()
            .collect()
    }

    pub fn append(
        &mut self,
        mut entry: CommitJournalEntry,
    ) -> Result<CommitJournalEntry> {
        let previous = self.latest.get(&entry.transaction_id);
        validate_stage_transition(previous.map(|value| value.stage), entry.stage)?;
        if let Some(previous) = previous {
            validate_same_transaction(previous, &entry)?;
        } else {
            validate_stage_payload(&entry)?;
        }
        let sequence = (self.entries.len() as u64)
            .checked_add(1)
            .ok_or_else(|| CommitError::Invalid(
                "commit journal sequence overflow".to_string(),
            ))?;
        entry.journal_sequence = sequence;
        entry.previous_journal_digest = self.head_digest;
        let payload = encode_commit_payload(&entry)?;
        let payload_digest = sha256(&payload);
        let frame_digest = compute_chain_digest(
            b"UBTCJFR1",
            sequence,
            self.head_digest,
            payload_digest,
        );
        entry.journal_digest = frame_digest;
        let frame = encode_chain_frame(
            COMMIT_LEDGER_MAGIC,
            COMMIT_FRAME_HEADER_BYTES,
            sequence,
            self.head_digest,
            payload_digest,
            frame_digest,
            &payload,
        )?;
        append_fsync(&self.path, &frame)?;
        self.head_digest = frame_digest;
        self.entries.push(entry.clone());
        self.latest.insert(entry.transaction_id, entry.clone());
        Ok(entry)
    }

    fn replay(&mut self, bytes: &[u8]) -> Result<()> {
        let frames = decode_chain_frames(
            "commit journal",
            COMMIT_LEDGER_MAGIC,
            COMMIT_FRAME_HEADER_BYTES,
            b"UBTCJFR1",
            bytes,
        )?;
        for frame in frames {
            let mut entry = decode_commit_payload(&frame.payload)?;
            let previous = self.latest.get(&entry.transaction_id);
            validate_stage_transition(previous.map(|value| value.stage), entry.stage)?;
            if let Some(previous) = previous {
                validate_same_transaction(previous, &entry)?;
            } else {
                validate_stage_payload(&entry)?;
            }
            entry.journal_sequence = frame.sequence;
            entry.previous_journal_digest = frame.previous_digest;
            entry.journal_digest = frame.frame_digest;
            self.head_digest = frame.frame_digest;
            self.entries.push(entry.clone());
            self.latest.insert(entry.transaction_id, entry);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeStop {
    None,
    AfterPrepared,
    AfterDatabaseCommitted,
    AfterTrustApplied,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitProbeOutcome {
    Committed(TrustCommitReceipt),
    Stopped {
        transaction_id: [u8; 32],
        stage: CommitStage,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustCommitReceipt {
    pub transaction_id: [u8; 32],
    pub binding_record_id: String,
    pub binding_record_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub record_digest: [u8; 32],
    pub database_state_digest: [u8; 32],
    pub trust_transition_id: [u8; 32],
    pub trust_sequence: u64,
    pub journal_sequence: u64,
    pub finalized: bool,
    pub recovered: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitRecoveryReceipt {
    pub pending_before: u64,
    pub aborted_prepared_count: u64,
    pub database_stage_reconstructed_count: u64,
    pub trust_transition_applied_count: u64,
    pub trust_stage_reconstructed_count: u64,
    pub finalized_count: u64,
}

pub struct TrustCommitCoordinator {
    database_root: PathBuf,
    database: DurableDatabase,
    trust: TrustLedger,
    policies: PolicyRegistry,
    journal: TrustCommitJournal,
    last_recovery: CommitRecoveryReceipt,
}

impl TrustCommitCoordinator {
    pub fn open_strict(
        database_root: impl AsRef<Path>,
        trust_ledger_path: impl AsRef<Path>,
        policy_registry_path: impl AsRef<Path>,
        commit_journal_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let database_root = database_root.as_ref().to_path_buf();
        let database = DurableDatabase::open(&database_root, false)
            .map_err(|error| CommitError::Lifecycle(error.to_string()))?;
        let trust = TrustLedger::open_strict(trust_ledger_path)
            .map_err(|error| CommitError::Trust(error.to_string()))?;
        let policies = PolicyRegistry::open_strict(policy_registry_path)?;
        let journal = TrustCommitJournal::open_strict(commit_journal_path)?;
        let mut coordinator = Self {
            database_root,
            database,
            trust,
            policies,
            journal,
            last_recovery: CommitRecoveryReceipt::default(),
        };
        let receipt = coordinator.recover_pending()?;
        coordinator.last_recovery = receipt;
        Ok(coordinator)
    }

    pub fn database(&self) -> &DurableDatabase {
        &self.database
    }

    pub fn trust_ledger(&self) -> &TrustLedger {
        &self.trust
    }

    pub fn policy_registry(&self) -> &PolicyRegistry {
        &self.policies
    }

    pub fn commit_journal(&self) -> &TrustCommitJournal {
        &self.journal
    }

    pub fn last_recovery_receipt(&self) -> &CommitRecoveryReceipt {
        &self.last_recovery
    }

    pub fn commit(
        &mut self,
        request: TrustCommitRequest,
    ) -> Result<TrustCommitReceipt> {
        match self.commit_for_probe(request, ProbeStop::None)? {
            CommitProbeOutcome::Committed(receipt) => Ok(receipt),
            CommitProbeOutcome::Stopped { .. } => Err(CommitError::Invalid(
                "normal commit unexpectedly stopped".to_string(),
            )),
        }
    }

    #[doc(hidden)]
    pub fn commit_for_probe(
        &mut self,
        request: TrustCommitRequest,
        stop: ProbeStop,
    ) -> Result<CommitProbeOutcome> {
        let recovery = self.recover_pending()?;
        self.last_recovery = recovery;
        let context = self.prepare_context(request)?;
        let prepared = self.journal.append(context.prepared_entry())?;
        if stop == ProbeStop::AfterPrepared {
            return Ok(CommitProbeOutcome::Stopped {
                transaction_id: prepared.transaction_id,
                stage: CommitStage::Prepared,
            });
        }

        let database_state_digest = self.commit_binding_record(&context)?;
        let database_entry = self.journal.append(
            context.stage_entry(
                CommitStage::DatabaseCommitted,
                database_state_digest,
                [0; 32],
            ),
        )?;
        if stop == ProbeStop::AfterDatabaseCommitted {
            return Ok(CommitProbeOutcome::Stopped {
                transaction_id: database_entry.transaction_id,
                stage: CommitStage::DatabaseCommitted,
            });
        }

        let transition = self
            .trust
            .apply(context.transition_intent())
            .map_err(|error| CommitError::Trust(error.to_string()))?;
        validate_transition_matches(
            &transition,
            &context.request,
            context.record_digest,
            context.trust_pre_head,
            context.expected_trust_sequence,
        )?;
        if stop == ProbeStop::AfterTrustApplied {
            return Ok(CommitProbeOutcome::Stopped {
                transaction_id: context.transaction_id,
                stage: CommitStage::DatabaseCommitted,
            });
        }

        let _trust_entry = self.journal.append(
            context.stage_entry(
                CommitStage::TrustCommitted,
                database_state_digest,
                transition.transition_id,
            ),
        )?;
        let finalized = self.journal.append(
            context.stage_entry(
                CommitStage::Finalized,
                database_state_digest,
                transition.transition_id,
            ),
        )?;
        Ok(CommitProbeOutcome::Committed(TrustCommitReceipt {
            transaction_id: context.transaction_id,
            binding_record_id: context.binding_record_id,
            binding_record_digest: context.binding_record_digest,
            policy_digest: context.policy_digest,
            record_digest: context.record_digest,
            database_state_digest,
            trust_transition_id: transition.transition_id,
            trust_sequence: transition.sequence,
            journal_sequence: finalized.journal_sequence,
            finalized: true,
            recovered: false,
        }))
    }

    pub fn recover_pending(&mut self) -> Result<CommitRecoveryReceipt> {
        let mut pending = self.journal.pending();
        pending.sort_by_key(|entry| entry.journal_sequence);
        let mut receipt = CommitRecoveryReceipt {
            pending_before: pending.len() as u64,
            ..CommitRecoveryReceipt::default()
        };
        for latest in pending {
            self.recover_transaction(latest, &mut receipt)?;
        }
        Ok(receipt)
    }

    fn recover_transaction(
        &mut self,
        mut latest: CommitJournalEntry,
        receipt: &mut CommitRecoveryReceipt,
    ) -> Result<()> {
        let policy_digest = self.policies.authorize(&latest.request)?;
        if policy_digest != latest.policy_digest {
            return Err(CommitError::Integrity {
                context: "recovery policy digest".to_string(),
                expected: latest.policy_digest,
                actual: policy_digest,
            });
        }
        let record = self.require_target_record(&latest.request.record_id)?;
        let actual_record_digest = canonical_database_record_digest(&record);
        if actual_record_digest != latest.record_digest {
            return Err(CommitError::Integrity {
                context: "recovery target record digest".to_string(),
                expected: latest.record_digest,
                actual: actual_record_digest,
            });
        }
        self.validate_superseding_binding(&latest.request)?;

        let binding = self.database
            .record(&latest.binding_record_id)
            .map_err(|error| CommitError::Lifecycle(error.to_string()))?;

        if latest.stage == CommitStage::Prepared {
            match binding {
                None => {
                    let aborted = CommitJournalEntry {
                        stage: CommitStage::Aborted,
                        database_state_digest: self.database.state_sha256(),
                        trust_transition_id: [0; 32],
                        ..latest.clone()
                    };
                    self.journal.append(aborted)?;
                    receipt.aborted_prepared_count += 1;
                    return Ok(());
                }
                Some(binding) => {
                    validate_binding_record(&binding, &latest)?;
                    latest = self.journal.append(CommitJournalEntry {
                        stage: CommitStage::DatabaseCommitted,
                        database_state_digest: self.database.state_sha256(),
                        trust_transition_id: [0; 32],
                        ..latest.clone()
                    })?;
                    receipt.database_stage_reconstructed_count += 1;
                }
            }
        }

        if latest.stage == CommitStage::DatabaseCommitted {
            let binding = self.database
                .record(&latest.binding_record_id)
                .map_err(|error| CommitError::Lifecycle(error.to_string()))?
                .ok_or_else(|| CommitError::Invalid(
                    "database binding record disappeared during recovery".to_string(),
                ))?;
            validate_binding_record(&binding, &latest)?;
            let transition = find_matching_transition(
                &self.trust,
                &latest.request,
                latest.record_digest,
                latest.trust_pre_head,
                latest.expected_trust_sequence,
            )?;
            let transition = match transition {
                Some(value) => {
                    receipt.trust_stage_reconstructed_count += 1;
                    value.clone()
                }
                None => {
                    if self.trust.head_digest() != latest.trust_pre_head {
                        return Err(CommitError::Invalid(
                            "trust head changed before pending transaction recovery".to_string(),
                        ));
                    }
                    let expected = (self.trust.transition_count() as u64)
                        .checked_add(1)
                        .ok_or_else(|| CommitError::Invalid(
                            "trust sequence overflow during recovery".to_string(),
                        ))?;
                    if expected != latest.expected_trust_sequence {
                        return Err(CommitError::Invalid(
                            "trust sequence changed before pending recovery".to_string(),
                        ));
                    }
                    let value = self
                        .trust
                        .apply(transition_intent(
                            &latest.request,
                            latest.record_digest,
                        ))
                        .map_err(|error| CommitError::Trust(error.to_string()))?;
                    validate_transition_matches(
                        &value,
                        &latest.request,
                        latest.record_digest,
                        latest.trust_pre_head,
                        latest.expected_trust_sequence,
                    )?;
                    receipt.trust_transition_applied_count += 1;
                    value
                }
            };
            latest = self.journal.append(CommitJournalEntry {
                stage: CommitStage::TrustCommitted,
                trust_transition_id: transition.transition_id,
                ..latest.clone()
            })?;
        }

        if latest.stage == CommitStage::TrustCommitted {
            let transition = find_matching_transition(
                &self.trust,
                &latest.request,
                latest.record_digest,
                latest.trust_pre_head,
                latest.expected_trust_sequence,
            )?
            .ok_or_else(|| CommitError::Invalid(
                "TRUST_COMMITTED journal stage has no matching trust transition".to_string(),
            ))?;
            if transition.transition_id != latest.trust_transition_id {
                return Err(CommitError::Integrity {
                    context: "recovery trust transition ID".to_string(),
                    expected: latest.trust_transition_id,
                    actual: transition.transition_id,
                });
            }
            self.journal.append(CommitJournalEntry {
                stage: CommitStage::Finalized,
                ..latest
            })?;
            receipt.finalized_count += 1;
        }
        Ok(())
    }

    fn prepare_context(
        &self,
        request: TrustCommitRequest,
    ) -> Result<PreparedContext> {
        validate_request(&request)?;
        if request.record_id.starts_with(BINDING_RECORD_PREFIX) {
            return Err(CommitError::Invalid(
                "trust binding records cannot be trust targets".to_string(),
            ));
        }
        let policy_digest = self.policies.authorize(&request)?;
        let record = self.require_target_record(&request.record_id)?;
        let record_digest = canonical_database_record_digest(&record);
        if let Some(snapshot) = self.trust.snapshot(&request.record_id) {
            if snapshot.record_digest != record_digest {
                return Err(CommitError::Invalid(format!(
                    "canonical record changed after trust binding: {}",
                    request.record_id,
                )));
            }
        }
        self.validate_superseding_binding(&request)?;
        let request_digest = compute_request_digest(&request);
        let trust_pre_head = self.trust.head_digest();
        let expected_trust_sequence = (self.trust.transition_count() as u64)
            .checked_add(1)
            .ok_or_else(|| CommitError::Invalid(
                "trust sequence overflow".to_string(),
            ))?;
        let transaction_id = compute_transaction_id(
            self.database.state_sha256(),
            trust_pre_head,
            policy_digest,
            record_digest,
            request_digest,
            expected_trust_sequence,
        );
        let binding_record_id = format!(
            "{}{}",
            BINDING_RECORD_PREFIX,
            hex_digest(&transaction_id),
        );
        if self.database
            .record(&binding_record_id)
            .map_err(|error| CommitError::Lifecycle(error.to_string()))?
            .is_some()
        {
            return Err(CommitError::Invalid(
                "derived binding record already exists".to_string(),
            ));
        }
        let binding_payload = encode_binding_payload(
            transaction_id,
            &request.record_id,
            record_digest,
            policy_digest,
            request_digest,
            trust_pre_head,
            expected_trust_sequence,
            request.logical_timestamp,
        )?;
        let binding_record_digest = sha256(&binding_payload);
        Ok(PreparedContext {
            request,
            transaction_id,
            record_digest,
            policy_digest,
            request_digest,
            trust_pre_head,
            expected_trust_sequence,
            binding_record_id,
            binding_payload,
            binding_record_digest,
        })
    }

    fn require_target_record(&self, record_id: &str) -> Result<DatabaseRecord> {
        self.database
            .record(record_id)
            .map_err(|error| CommitError::Lifecycle(error.to_string()))?
            .ok_or_else(|| CommitError::Invalid(format!(
                "canonical database record not found: {record_id}",
            )))
    }

    fn validate_superseding_binding(
        &self,
        request: &TrustCommitRequest,
    ) -> Result<()> {
        if let Some(record_id) = &request.superseding_record_id {
            if record_id.starts_with(BINDING_RECORD_PREFIX) {
                return Err(CommitError::Invalid(
                    "binding record cannot be a superseding target".to_string(),
                ));
            }
            let record = self.require_target_record(record_id)?;
            let digest = canonical_database_record_digest(&record);
            let snapshot = self.trust.snapshot(record_id).ok_or_else(|| {
                CommitError::Invalid(format!(
                    "superseding canonical record has no trust state: {record_id}",
                ))
            })?;
            if snapshot.record_digest != digest {
                return Err(CommitError::Invalid(format!(
                    "superseding record digest binding mismatch: {record_id}",
                )));
            }
        }
        Ok(())
    }

    fn commit_binding_record(
        &mut self,
        context: &PreparedContext,
    ) -> Result<[u8; 32]> {
        // DurableDatabase caches checkpoint_generation and
        // maximum_valid_wal_lsn at open time. T2 performs multiple durable
        // commits in one coordinator lifetime, so using the same handle would
        // reuse an old generation/segment sequence and collide with an
        // immutable segment. Reopen strictly before every database commit.
        self.database = DurableDatabase::open(
            &self.database_root,
            false,
        )
        .map_err(|error| CommitError::Lifecycle(error.to_string()))?;

        let generation = self.database
            .next_generation()
            .map_err(|error| CommitError::Lifecycle(error.to_string()))?;
        let sequence = self.database
            .next_segment_sequence()
            .map_err(|error| CommitError::Lifecycle(error.to_string()))?;
        let transaction_id = TransactionId::new(
            context.transaction_id[0..16]
                .try_into()
                .expect("fixed transaction ID slice"),
        );
        let logical_id = nonzero_u64(&context.transaction_id[16..24]);
        let node_id = nonzero_u64(&context.transaction_id[24..32]);
        let mut core = TransactionCore::new(BatchLimits::default());
        core.begin(transaction_id)
            .map_err(|error| CommitError::Lifecycle(error.to_string()))?;
        core.put_record(
            logical_id,
            &context.binding_record_id,
            node_id,
            &context.binding_payload,
        )
        .map_err(|error| CommitError::Lifecycle(error.to_string()))?;
        core.prepare()
            .map_err(|error| CommitError::Lifecycle(error.to_string()))?;
        let commit = core
            .commit_durable(&mut self.database, generation, sequence)
            .map_err(|error| CommitError::Lifecycle(error.to_string()))?;
        core.release_terminal(transaction_id)
            .map_err(|error| CommitError::Lifecycle(error.to_string()))?;
        let checkpoint = self.database
            .checkpoint(generation)
            .map_err(|error| CommitError::Lifecycle(error.to_string()))?;
        if !commit.durable_commit
            || !commit.wal_recorded
            || !commit.wal_fsynced
            || !checkpoint.head_published
            || !checkpoint.wal_checkpoint_recorded
            || commit.state_sha256 != checkpoint.state_sha256
        {
            return Err(CommitError::Invalid(
                "database binding commit receipt is incomplete".to_string(),
            ));
        }
        let binding = self.database
            .record(&context.binding_record_id)
            .map_err(|error| CommitError::Lifecycle(error.to_string()))?
            .ok_or_else(|| CommitError::Invalid(
                "binding record missing after durable commit".to_string(),
            ))?;
        if binding.payload != context.binding_payload {
            return Err(CommitError::Invalid(
                "binding record payload mismatch after commit".to_string(),
            ));
        }
        Ok(checkpoint.state_sha256)
    }
}

#[derive(Clone)]
struct PreparedContext {
    request: TrustCommitRequest,
    transaction_id: [u8; 32],
    record_digest: [u8; 32],
    policy_digest: [u8; 32],
    request_digest: [u8; 32],
    trust_pre_head: [u8; 32],
    expected_trust_sequence: u64,
    binding_record_id: String,
    binding_payload: Vec<u8>,
    binding_record_digest: [u8; 32],
}

impl PreparedContext {
    fn prepared_entry(&self) -> CommitJournalEntry {
        self.stage_entry(CommitStage::Prepared, [0; 32], [0; 32])
    }

    fn stage_entry(
        &self,
        stage: CommitStage,
        database_state_digest: [u8; 32],
        trust_transition_id: [u8; 32],
    ) -> CommitJournalEntry {
        CommitJournalEntry {
            journal_sequence: 0,
            transaction_id: self.transaction_id,
            stage,
            request: self.request.clone(),
            record_digest: self.record_digest,
            policy_digest: self.policy_digest,
            request_digest: self.request_digest,
            trust_pre_head: self.trust_pre_head,
            expected_trust_sequence: self.expected_trust_sequence,
            binding_record_id: self.binding_record_id.clone(),
            binding_record_digest: self.binding_record_digest,
            database_state_digest,
            trust_transition_id,
            previous_journal_digest: [0; 32],
            journal_digest: [0; 32],
        }
    }

    fn transition_intent(&self) -> TransitionIntent {
        transition_intent(&self.request, self.record_digest)
    }
}

pub fn canonical_database_record_digest(
    record: &DatabaseRecord,
) -> [u8; 32] {
    let record_id = record.record_id.as_bytes();
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&RECORD_DIGEST_DOMAIN);
    preimage.extend_from_slice(&record.logical_id.to_le_bytes());
    preimage.extend_from_slice(&(record_id.len() as u32).to_le_bytes());
    preimage.extend_from_slice(record_id);
    preimage.extend_from_slice(&record.node_id.to_le_bytes());
    preimage.extend_from_slice(&(record.payload.len() as u64).to_le_bytes());
    preimage.extend_from_slice(&record.payload_sha256);
    preimage.extend_from_slice(&record.payload);
    sha256(&preimage)
}

fn transition_intent(
    request: &TrustCommitRequest,
    record_digest: [u8; 32],
) -> TransitionIntent {
    TransitionIntent {
        record_id: request.record_id.clone(),
        operation: request.operation,
        authority: request.authority,
        evidence_refs: request.evidence_refs.clone(),
        policy_id: request.policy_id.clone(),
        policy_version: request.policy_version.clone(),
        verifier_id: request.verifier_id.clone(),
        record_digest,
        logical_timestamp: request.logical_timestamp,
        reason_code: request.reason_code.clone(),
        superseding_record_id: request.superseding_record_id.clone(),
    }
}

fn validate_request(request: &TrustCommitRequest) -> Result<()> {
    validate_string("record_id", &request.record_id)?;
    validate_string("policy_id", &request.policy_id)?;
    validate_string("policy_version", &request.policy_version)?;
    validate_string("verifier_id", &request.verifier_id)?;
    validate_string("reason_code", &request.reason_code)?;
    if request.logical_timestamp == 0 {
        return Err(CommitError::Invalid(
            "logical_timestamp must be greater than zero".to_string(),
        ));
    }
    if request.evidence_refs.is_empty() {
        return Err(CommitError::Invalid(
            "at least one evidence reference is required".to_string(),
        ));
    }
    let mut evidence_ids = BTreeSet::new();
    for evidence in &request.evidence_refs {
        validate_string("evidence_id", &evidence.evidence_id)?;
        validate_string("provenance_id", &evidence.provenance_id)?;
        if evidence.evidence_digest.iter().all(|byte| *byte == 0) {
            return Err(CommitError::Invalid(
                "evidence digest cannot be zero".to_string(),
            ));
        }
        if !evidence_ids.insert(evidence.evidence_id.clone()) {
            return Err(CommitError::Invalid(format!(
                "duplicate evidence ID: {}",
                evidence.evidence_id,
            )));
        }
    }
    if let Some(value) = &request.superseding_record_id {
        validate_string("superseding_record_id", value)?;
    }
    Ok(())
}

fn validate_policy(policy: &PolicyDefinition) -> Result<()> {
    validate_string("policy_id", &policy.policy_id)?;
    validate_string("policy_version", &policy.policy_version)?;
    validate_string("required_verifier_id", &policy.required_verifier_id)?;
    match policy.allowed_authority {
        TransitionAuthority::EvidencePolicy | TransitionAuthority::Import => {}
        value => {
            return Err(CommitError::Invalid(format!(
                "trust-neutral authority cannot be registered: {}",
                authority_name(value),
            )))
        }
    }
    let all_operations = (1u16 << 6) - 1;
    if policy.allowed_operation_mask == 0
        || policy.allowed_operation_mask & !all_operations != 0
    {
        return Err(CommitError::Invalid(
            "policy operation mask is invalid".to_string(),
        ));
    }
    if policy.min_evidence_refs == 0
        || policy.max_evidence_refs < policy.min_evidence_refs
        || policy.max_evidence_refs > 4096
    {
        return Err(CommitError::Invalid(
            "policy evidence range is invalid".to_string(),
        ));
    }
    if policy.allowed_authority == TransitionAuthority::Import
        && policy.allowed_operation_mask
            != operation_bit(TrustOperation::Propose)
    {
        return Err(CommitError::Invalid(
            "IMPORT policy may allow only PROPOSE".to_string(),
        ));
    }
    Ok(())
}

fn operation_bit(operation: TrustOperation) -> u16 {
    1u16 << ((operation as u8) - 1)
}

fn operation_from_code(value: u8) -> Result<TrustOperation> {
    match value {
        1 => Ok(TrustOperation::Propose),
        2 => Ok(TrustOperation::Promote),
        3 => Ok(TrustOperation::Dispute),
        4 => Ok(TrustOperation::Revoke),
        5 => Ok(TrustOperation::Expire),
        6 => Ok(TrustOperation::Supersede),
        _ => Err(CommitError::Invalid(format!(
            "unknown trust operation code {value}",
        ))),
    }
}

fn authority_from_code(value: u8) -> Result<TransitionAuthority> {
    match value {
        1 => Ok(TransitionAuthority::EvidencePolicy),
        2 => Ok(TransitionAuthority::Import),
        3 => Ok(TransitionAuthority::Ranker),
        4 => Ok(TransitionAuthority::Wave),
        5 => Ok(TransitionAuthority::Similarity),
        6 => Ok(TransitionAuthority::Frequency),
        7 => Ok(TransitionAuthority::Llm),
        8 => Ok(TransitionAuthority::RigorMultiplier),
        _ => Err(CommitError::Invalid(format!(
            "unknown transition authority code {value}",
        ))),
    }
}

fn operation_name(value: TrustOperation) -> &'static str {
    match value {
        TrustOperation::Propose => "PROPOSE",
        TrustOperation::Promote => "PROMOTE",
        TrustOperation::Dispute => "DISPUTE",
        TrustOperation::Revoke => "REVOKE",
        TrustOperation::Expire => "EXPIRE",
        TrustOperation::Supersede => "SUPERSEDE",
    }
}

fn authority_name(value: TransitionAuthority) -> &'static str {
    match value {
        TransitionAuthority::EvidencePolicy => "EVIDENCE_POLICY",
        TransitionAuthority::Import => "IMPORT",
        TransitionAuthority::Ranker => "RANKER",
        TransitionAuthority::Wave => "WAVE",
        TransitionAuthority::Similarity => "SIMILARITY",
        TransitionAuthority::Frequency => "FREQUENCY",
        TransitionAuthority::Llm => "LLM",
        TransitionAuthority::RigorMultiplier => "RIGOR_MULTIPLIER",
    }
}

fn compute_request_digest(request: &TrustCommitRequest) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&REQUEST_DIGEST_DOMAIN);
    preimage.push(request.operation as u8);
    preimage.push(request.authority as u8);
    preimage.extend_from_slice(&[0; 6]);
    push_string(&mut preimage, &request.record_id);
    push_string(&mut preimage, &request.policy_id);
    push_string(&mut preimage, &request.policy_version);
    push_string(&mut preimage, &request.verifier_id);
    push_string(&mut preimage, &request.reason_code);
    push_optional_string(
        &mut preimage,
        request.superseding_record_id.as_deref(),
    );
    preimage.extend_from_slice(&request.logical_timestamp.to_le_bytes());
    preimage.extend_from_slice(
        &(request.evidence_refs.len() as u32).to_le_bytes(),
    );
    for evidence in &request.evidence_refs {
        push_string(&mut preimage, &evidence.evidence_id);
        push_string(&mut preimage, &evidence.provenance_id);
        preimage.extend_from_slice(&evidence.evidence_digest);
    }
    sha256(&preimage)
}

fn compute_transaction_id(
    database_state_digest: [u8; 32],
    trust_pre_head: [u8; 32],
    policy_digest: [u8; 32],
    record_digest: [u8; 32],
    request_digest: [u8; 32],
    expected_trust_sequence: u64,
) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&TRANSACTION_ID_DOMAIN);
    preimage.extend_from_slice(&database_state_digest);
    preimage.extend_from_slice(&trust_pre_head);
    preimage.extend_from_slice(&policy_digest);
    preimage.extend_from_slice(&record_digest);
    preimage.extend_from_slice(&request_digest);
    preimage.extend_from_slice(&expected_trust_sequence.to_le_bytes());
    sha256(&preimage)
}

fn encode_binding_payload(
    transaction_id: [u8; 32],
    record_id: &str,
    record_digest: [u8; 32],
    policy_digest: [u8; 32],
    request_digest: [u8; 32],
    trust_pre_head: [u8; 32],
    expected_trust_sequence: u64,
    logical_timestamp: u64,
) -> Result<Vec<u8>> {
    validate_string("binding target record_id", record_id)?;
    let record_id = record_id.as_bytes();
    let mut output = Vec::new();
    output.extend_from_slice(&BINDING_PAYLOAD_MAGIC);
    output.extend_from_slice(&transaction_id);
    output.extend_from_slice(&record_digest);
    output.extend_from_slice(&policy_digest);
    output.extend_from_slice(&request_digest);
    output.extend_from_slice(&trust_pre_head);
    output.extend_from_slice(&expected_trust_sequence.to_le_bytes());
    output.extend_from_slice(&logical_timestamp.to_le_bytes());
    output.extend_from_slice(&(record_id.len() as u32).to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(record_id);
    Ok(output)
}

fn validate_binding_record(
    binding: &DatabaseRecord,
    entry: &CommitJournalEntry,
) -> Result<()> {
    if binding.record_id != entry.binding_record_id {
        return Err(CommitError::Invalid(
            "binding record ID mismatch".to_string(),
        ));
    }
    let digest = sha256(&binding.payload);
    if digest != entry.binding_record_digest {
        return Err(CommitError::Integrity {
            context: "binding record payload".to_string(),
            expected: entry.binding_record_digest,
            actual: digest,
        });
    }
    let expected = encode_binding_payload(
        entry.transaction_id,
        &entry.request.record_id,
        entry.record_digest,
        entry.policy_digest,
        entry.request_digest,
        entry.trust_pre_head,
        entry.expected_trust_sequence,
        entry.request.logical_timestamp,
    )?;
    if binding.payload != expected {
        return Err(CommitError::Invalid(
            "binding record canonical payload mismatch".to_string(),
        ));
    }
    Ok(())
}

fn validate_transition_matches(
    transition: &TrustTransition,
    request: &TrustCommitRequest,
    record_digest: [u8; 32],
    trust_pre_head: [u8; 32],
    expected_sequence: u64,
) -> Result<()> {
    if transition.sequence != expected_sequence
        || transition.previous_transition_digest != trust_pre_head
        || transition.record_id != request.record_id
        || transition.operation != request.operation
        || transition.authority != request.authority
        || transition.evidence_refs != request.evidence_refs
        || transition.policy_id != request.policy_id
        || transition.policy_version != request.policy_version
        || transition.verifier_id != request.verifier_id
        || transition.record_digest != record_digest
        || transition.logical_timestamp != request.logical_timestamp
        || transition.reason_code != request.reason_code
        || transition.superseding_record_id != request.superseding_record_id
    {
        return Err(CommitError::Invalid(
            "trust transition does not match commit request".to_string(),
        ));
    }
    Ok(())
}

fn find_matching_transition<'a>(
    trust: &'a TrustLedger,
    request: &TrustCommitRequest,
    record_digest: [u8; 32],
    trust_pre_head: [u8; 32],
    expected_sequence: u64,
) -> Result<Option<&'a TrustTransition>> {
    let transition = trust
        .transitions()
        .iter()
        .find(|value| value.sequence == expected_sequence);
    if let Some(value) = transition {
        validate_transition_matches(
            value,
            request,
            record_digest,
            trust_pre_head,
            expected_sequence,
        )?;
    }
    Ok(transition)
}

fn validate_stage_transition(
    previous: Option<CommitStage>,
    next: CommitStage,
) -> Result<()> {
    let allowed = match (previous, next) {
        (None, CommitStage::Prepared) => true,
        (Some(CommitStage::Prepared), CommitStage::DatabaseCommitted) => true,
        (Some(CommitStage::Prepared), CommitStage::Aborted) => true,
        (
            Some(CommitStage::DatabaseCommitted),
            CommitStage::TrustCommitted,
        ) => true,
        (Some(CommitStage::TrustCommitted), CommitStage::Finalized) => true,
        _ => false,
    };
    if !allowed {
        return Err(CommitError::Invalid(format!(
            "invalid commit stage transition: previous={:?} next={:?}",
            previous,
            next,
        )));
    }
    Ok(())
}

fn validate_same_transaction(
    previous: &CommitJournalEntry,
    next: &CommitJournalEntry,
) -> Result<()> {
    if previous.transaction_id != next.transaction_id
        || previous.request != next.request
        || previous.record_digest != next.record_digest
        || previous.policy_digest != next.policy_digest
        || previous.request_digest != next.request_digest
        || previous.trust_pre_head != next.trust_pre_head
        || previous.expected_trust_sequence != next.expected_trust_sequence
        || previous.binding_record_id != next.binding_record_id
        || previous.binding_record_digest != next.binding_record_digest
    {
        return Err(CommitError::Invalid(
            "commit journal transaction fields changed between stages".to_string(),
        ));
    }
    if matches!(
        previous.stage,
        CommitStage::DatabaseCommitted | CommitStage::TrustCommitted
    ) && previous.database_state_digest != next.database_state_digest
    {
        return Err(CommitError::Invalid(
            "database state digest changed after DATABASE_COMMITTED".to_string(),
        ));
    }
    if previous.stage == CommitStage::TrustCommitted
        && previous.trust_transition_id != next.trust_transition_id
    {
        return Err(CommitError::Invalid(
            "trust transition ID changed after TRUST_COMMITTED".to_string(),
        ));
    }
    validate_stage_payload(next)?;
    Ok(())
}

fn validate_stage_payload(entry: &CommitJournalEntry) -> Result<()> {
    let zero = [0u8; 32];
    match entry.stage {
        CommitStage::Prepared => {
            if entry.database_state_digest != zero
                || entry.trust_transition_id != zero
            {
                return Err(CommitError::Invalid(
                    "PREPARED stage contains committed digests".to_string(),
                ));
            }
        }
        CommitStage::DatabaseCommitted => {
            if entry.database_state_digest == zero
                || entry.trust_transition_id != zero
            {
                return Err(CommitError::Invalid(
                    "DATABASE_COMMITTED stage digest contract failed".to_string(),
                ));
            }
        }
        CommitStage::TrustCommitted | CommitStage::Finalized => {
            if entry.database_state_digest == zero
                || entry.trust_transition_id == zero
            {
                return Err(CommitError::Invalid(
                    "trust/final stage digest contract failed".to_string(),
                ));
            }
        }
        CommitStage::Aborted => {
            if entry.trust_transition_id != zero {
                return Err(CommitError::Invalid(
                    "ABORTED stage cannot contain trust transition ID".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn encode_policy_payload(policy: &PolicyDefinition) -> Result<Vec<u8>> {
    validate_policy(policy)?;
    let policy_id = policy.policy_id.as_bytes();
    let version = policy.policy_version.as_bytes();
    let verifier = policy.required_verifier_id.as_bytes();
    let mut output = Vec::new();
    output.extend_from_slice(&POLICY_PAYLOAD_MAGIC);
    output.push(policy.allowed_authority as u8);
    output.push(if policy.require_unique_provenance { 1 } else { 0 });
    output.extend_from_slice(&policy.allowed_operation_mask.to_le_bytes());
    output.extend_from_slice(&policy.min_evidence_refs.to_le_bytes());
    output.extend_from_slice(&policy.max_evidence_refs.to_le_bytes());
    output.extend_from_slice(&(policy_id.len() as u32).to_le_bytes());
    output.extend_from_slice(&(version.len() as u32).to_le_bytes());
    output.extend_from_slice(&(verifier.len() as u32).to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(policy_id);
    output.extend_from_slice(version);
    output.extend_from_slice(verifier);
    Ok(output)
}

fn decode_policy_payload(payload: &[u8]) -> Result<PolicyDefinition> {
    if payload.len() < POLICY_PAYLOAD_FIXED_BYTES {
        return Err(CommitError::Invalid(
            "policy payload shorter than fixed header".to_string(),
        ));
    }
    if payload[0..8] != POLICY_PAYLOAD_MAGIC {
        return Err(CommitError::Invalid(
            "policy payload magic mismatch".to_string(),
        ));
    }
    let authority = authority_from_code(payload[8])?;
    let require_unique_provenance = match payload[9] {
        0 => false,
        1 => true,
        value => {
            return Err(CommitError::Invalid(format!(
                "invalid policy flags byte {value}",
            )))
        }
    };
    let operation_mask = read_u16(payload, 10)?;
    let min_evidence_refs = read_u32(payload, 12)?;
    let max_evidence_refs = read_u32(payload, 16)?;
    let policy_id_bytes = read_u32(payload, 20)? as usize;
    let version_bytes = read_u32(payload, 24)? as usize;
    let verifier_bytes = read_u32(payload, 28)? as usize;
    if read_u32(payload, 32)? != 0 || read_u32(payload, 36)? != 0 {
        return Err(CommitError::Invalid(
            "policy reserved fields are non-zero".to_string(),
        ));
    }
    let mut cursor = POLICY_PAYLOAD_FIXED_BYTES;
    let policy_id = read_string(
        payload,
        &mut cursor,
        policy_id_bytes,
        "policy_id",
    )?;
    let policy_version = read_string(
        payload,
        &mut cursor,
        version_bytes,
        "policy_version",
    )?;
    let required_verifier_id = read_string(
        payload,
        &mut cursor,
        verifier_bytes,
        "required_verifier_id",
    )?;
    if cursor != payload.len() {
        return Err(CommitError::Invalid(
            "policy payload contains trailing bytes".to_string(),
        ));
    }
    Ok(PolicyDefinition {
        policy_id,
        policy_version,
        allowed_authority: authority,
        allowed_operation_mask: operation_mask,
        min_evidence_refs,
        max_evidence_refs,
        required_verifier_id,
        require_unique_provenance,
    })
}

fn encode_commit_payload(entry: &CommitJournalEntry) -> Result<Vec<u8>> {
    validate_request(&entry.request)?;
    let request = &entry.request;
    let record_id = request.record_id.as_bytes();
    let policy_id = request.policy_id.as_bytes();
    let policy_version = request.policy_version.as_bytes();
    let verifier_id = request.verifier_id.as_bytes();
    let reason_code = request.reason_code.as_bytes();
    let superseding = request
        .superseding_record_id
        .as_deref()
        .unwrap_or("")
        .as_bytes();
    let binding_record_id = entry.binding_record_id.as_bytes();

    let mut output = Vec::new();
    output.extend_from_slice(&COMMIT_PAYLOAD_MAGIC);
    output.push(entry.stage as u8);
    output.push(request.operation as u8);
    output.push(request.authority as u8);
    output.push(0);
    output.extend_from_slice(&[0; 4]);
    output.extend_from_slice(&(record_id.len() as u32).to_le_bytes());
    output.extend_from_slice(&(policy_id.len() as u32).to_le_bytes());
    output.extend_from_slice(&(policy_version.len() as u32).to_le_bytes());
    output.extend_from_slice(&(verifier_id.len() as u32).to_le_bytes());
    output.extend_from_slice(&(reason_code.len() as u32).to_le_bytes());
    output.extend_from_slice(&(superseding.len() as u32).to_le_bytes());
    output.extend_from_slice(&(binding_record_id.len() as u32).to_le_bytes());
    output.extend_from_slice(
        &(request.evidence_refs.len() as u32).to_le_bytes(),
    );
    output.extend_from_slice(&entry.expected_trust_sequence.to_le_bytes());
    output.extend_from_slice(&request.logical_timestamp.to_le_bytes());
    output.extend_from_slice(&entry.transaction_id);
    output.extend_from_slice(&entry.record_digest);
    output.extend_from_slice(&entry.policy_digest);
    output.extend_from_slice(&entry.request_digest);
    output.extend_from_slice(&entry.trust_pre_head);
    output.extend_from_slice(&entry.trust_transition_id);
    output.extend_from_slice(&entry.database_state_digest);
    output.extend_from_slice(&entry.binding_record_digest);
    debug_assert_eq!(output.len(), COMMIT_PAYLOAD_FIXED_BYTES);
    output.extend_from_slice(record_id);
    output.extend_from_slice(policy_id);
    output.extend_from_slice(policy_version);
    output.extend_from_slice(verifier_id);
    output.extend_from_slice(reason_code);
    output.extend_from_slice(superseding);
    output.extend_from_slice(binding_record_id);
    for evidence in &request.evidence_refs {
        output.extend_from_slice(
            &(evidence.evidence_id.as_bytes().len() as u32).to_le_bytes(),
        );
        output.extend_from_slice(
            &(evidence.provenance_id.as_bytes().len() as u32).to_le_bytes(),
        );
        output.extend_from_slice(&evidence.evidence_digest);
        output.extend_from_slice(evidence.evidence_id.as_bytes());
        output.extend_from_slice(evidence.provenance_id.as_bytes());
    }
    if output.len() > MAX_FRAME_PAYLOAD_BYTES {
        return Err(CommitError::Invalid(
            "commit journal payload exceeds maximum".to_string(),
        ));
    }
    Ok(output)
}

fn decode_commit_payload(payload: &[u8]) -> Result<CommitJournalEntry> {
    if payload.len() < COMMIT_PAYLOAD_FIXED_BYTES {
        return Err(CommitError::Invalid(
            "commit payload shorter than fixed header".to_string(),
        ));
    }
    if payload[0..8] != COMMIT_PAYLOAD_MAGIC {
        return Err(CommitError::Invalid(
            "commit payload magic mismatch".to_string(),
        ));
    }
    let stage = CommitStage::from_code(payload[8])?;
    let operation = operation_from_code(payload[9])?;
    let authority = authority_from_code(payload[10])?;
    if payload[11] != 0 || payload[12..16] != [0; 4] {
        return Err(CommitError::Invalid(
            "commit payload reserved bytes are non-zero".to_string(),
        ));
    }
    let record_id_bytes = read_u32(payload, 16)? as usize;
    let policy_id_bytes = read_u32(payload, 20)? as usize;
    let policy_version_bytes = read_u32(payload, 24)? as usize;
    let verifier_id_bytes = read_u32(payload, 28)? as usize;
    let reason_code_bytes = read_u32(payload, 32)? as usize;
    let superseding_bytes = read_u32(payload, 36)? as usize;
    let binding_record_id_bytes = read_u32(payload, 40)? as usize;
    let evidence_count = read_u32(payload, 44)? as usize;
    if evidence_count > 4096 {
        return Err(CommitError::Invalid(
            "commit evidence count exceeds maximum".to_string(),
        ));
    }
    let expected_trust_sequence = read_u64(payload, 48)?;
    let logical_timestamp = read_u64(payload, 56)?;
    let transaction_id = read_digest(payload, 64)?;
    let record_digest = read_digest(payload, 96)?;
    let policy_digest = read_digest(payload, 128)?;
    let request_digest = read_digest(payload, 160)?;
    let trust_pre_head = read_digest(payload, 192)?;
    let trust_transition_id = read_digest(payload, 224)?;
    let database_state_digest = read_digest(payload, 256)?;
    let binding_record_digest = read_digest(payload, 288)?;
    let mut cursor = COMMIT_PAYLOAD_FIXED_BYTES;
    let record_id = read_string(
        payload,
        &mut cursor,
        record_id_bytes,
        "record_id",
    )?;
    let policy_id = read_string(
        payload,
        &mut cursor,
        policy_id_bytes,
        "policy_id",
    )?;
    let policy_version = read_string(
        payload,
        &mut cursor,
        policy_version_bytes,
        "policy_version",
    )?;
    let verifier_id = read_string(
        payload,
        &mut cursor,
        verifier_id_bytes,
        "verifier_id",
    )?;
    let reason_code = read_string(
        payload,
        &mut cursor,
        reason_code_bytes,
        "reason_code",
    )?;
    let superseding_value = read_string(
        payload,
        &mut cursor,
        superseding_bytes,
        "superseding_record_id",
    )?;
    let binding_record_id = read_string(
        payload,
        &mut cursor,
        binding_record_id_bytes,
        "binding_record_id",
    )?;
    let superseding_record_id = if superseding_value.is_empty() {
        None
    } else {
        Some(superseding_value)
    };
    let mut evidence_refs = Vec::with_capacity(evidence_count);
    for _ in 0..evidence_count {
        if cursor + 40 > payload.len() {
            return Err(CommitError::Invalid(
                "truncated evidence reference".to_string(),
            ));
        }
        let evidence_id_bytes = read_u32(payload, cursor)? as usize;
        let provenance_id_bytes = read_u32(payload, cursor + 4)? as usize;
        let evidence_digest = read_digest(payload, cursor + 8)?;
        cursor += 40;
        let evidence_id = read_string(
            payload,
            &mut cursor,
            evidence_id_bytes,
            "evidence_id",
        )?;
        let provenance_id = read_string(
            payload,
            &mut cursor,
            provenance_id_bytes,
            "provenance_id",
        )?;
        evidence_refs.push(EvidenceRef {
            evidence_id,
            provenance_id,
            evidence_digest,
        });
    }
    if cursor != payload.len() {
        return Err(CommitError::Invalid(
            "commit payload contains trailing bytes".to_string(),
        ));
    }
    let request = TrustCommitRequest {
        record_id,
        operation,
        authority,
        evidence_refs,
        policy_id,
        policy_version,
        verifier_id,
        logical_timestamp,
        reason_code,
        superseding_record_id,
    };
    validate_request(&request)?;
    if compute_request_digest(&request) != request_digest {
        return Err(CommitError::Invalid(
            "commit request digest mismatch".to_string(),
        ));
    }
    Ok(CommitJournalEntry {
        journal_sequence: 0,
        transaction_id,
        stage,
        request,
        record_digest,
        policy_digest,
        request_digest,
        trust_pre_head,
        expected_trust_sequence,
        binding_record_id,
        binding_record_digest,
        database_state_digest,
        trust_transition_id,
        previous_journal_digest: [0; 32],
        journal_digest: [0; 32],
    })
}

struct ChainFrame {
    sequence: u64,
    previous_digest: [u8; 32],
    frame_digest: [u8; 32],
    payload: Vec<u8>,
}

fn encode_chain_frame(
    magic: [u8; 8],
    header_bytes: usize,
    sequence: u64,
    previous_digest: [u8; 32],
    payload_digest: [u8; 32],
    frame_digest: [u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if header_bytes != 144 {
        return Err(CommitError::Invalid(
            "unsupported chain frame header size".to_string(),
        ));
    }
    if payload.len() > MAX_FRAME_PAYLOAD_BYTES {
        return Err(CommitError::Invalid(
            "chain frame payload exceeds maximum".to_string(),
        ));
    }
    let mut output = Vec::new();
    output.extend_from_slice(&magic);
    output.extend_from_slice(&1u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&(header_bytes as u32).to_le_bytes());
    output.extend_from_slice(&sequence.to_le_bytes());
    output.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    output.extend_from_slice(&previous_digest);
    output.extend_from_slice(&payload_digest);
    output.extend_from_slice(&frame_digest);
    output.extend_from_slice(&[0; 16]);
    debug_assert_eq!(output.len(), header_bytes);
    output.extend_from_slice(payload);
    Ok(output)
}

fn decode_chain_frames(
    context: &'static str,
    magic: [u8; 8],
    header_bytes: usize,
    digest_domain: &[u8; 8],
    bytes: &[u8],
) -> Result<Vec<ChainFrame>> {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    let mut head = [0; 32];
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if remaining < header_bytes {
            return Err(CommitError::TruncatedTail {
                context,
                offset,
                remaining_bytes: remaining,
            });
        }
        let header = &bytes[offset..offset + header_bytes];
        if header[0..8] != magic {
            return Err(CommitError::Invalid(format!(
                "{context} magic mismatch at offset {offset}",
            )));
        }
        if read_u16(header, 8)? != 1
            || read_u16(header, 10)? != 0
            || read_u32(header, 12)? as usize != header_bytes
        {
            return Err(CommitError::Invalid(format!(
                "{context} version/header mismatch at offset {offset}",
            )));
        }
        let sequence = read_u64(header, 16)?;
        let expected_sequence = (frames.len() as u64) + 1;
        if sequence != expected_sequence {
            return Err(CommitError::Invalid(format!(
                "{context} sequence mismatch: expected={expected_sequence} actual={sequence}",
            )));
        }
        let payload_bytes = usize::try_from(read_u64(header, 24)?)
            .map_err(|_| CommitError::Invalid(
                "chain payload length overflow".to_string(),
            ))?;
        if payload_bytes > MAX_FRAME_PAYLOAD_BYTES {
            return Err(CommitError::Invalid(format!(
                "{context} payload exceeds maximum",
            )));
        }
        let previous_digest = read_digest(header, 32)?;
        let expected_payload_digest = read_digest(header, 64)?;
        let expected_frame_digest = read_digest(header, 96)?;
        if header[128..144] != [0; 16] {
            return Err(CommitError::Invalid(format!(
                "{context} reserved bytes are non-zero",
            )));
        }
        if previous_digest != head {
            return Err(CommitError::Integrity {
                context: format!("{context} previous digest"),
                expected: head,
                actual: previous_digest,
            });
        }
        let payload_start = offset + header_bytes;
        let frame_end = payload_start
            .checked_add(payload_bytes)
            .ok_or_else(|| CommitError::Invalid(
                "chain frame length overflow".to_string(),
            ))?;
        if frame_end > bytes.len() {
            return Err(CommitError::TruncatedTail {
                context,
                offset,
                remaining_bytes: bytes.len() - offset,
            });
        }
        let payload = bytes[payload_start..frame_end].to_vec();
        let actual_payload_digest = sha256(&payload);
        if actual_payload_digest != expected_payload_digest {
            return Err(CommitError::Integrity {
                context: format!("{context} payload"),
                expected: expected_payload_digest,
                actual: actual_payload_digest,
            });
        }
        let actual_frame_digest = compute_chain_digest(
            digest_domain,
            sequence,
            previous_digest,
            expected_payload_digest,
        );
        if actual_frame_digest != expected_frame_digest {
            return Err(CommitError::Integrity {
                context: format!("{context} frame"),
                expected: expected_frame_digest,
                actual: actual_frame_digest,
            });
        }
        head = expected_frame_digest;
        frames.push(ChainFrame {
            sequence,
            previous_digest,
            frame_digest: expected_frame_digest,
            payload,
        });
        offset = frame_end;
    }
    Ok(frames)
}

fn compute_chain_digest(
    domain: &[u8; 8],
    sequence: u64,
    previous_digest: [u8; 32],
    payload_digest: [u8; 32],
) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&sequence.to_le_bytes());
    preimage.extend_from_slice(&previous_digest);
    preimage.extend_from_slice(&payload_digest);
    sha256(&preimage)
}

fn append_fsync(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn validate_string(name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(CommitError::Invalid(format!(
            "{name} cannot be empty",
        )));
    }
    if value.as_bytes().len() > MAX_STRING_BYTES {
        return Err(CommitError::Invalid(format!(
            "{name} exceeds maximum length",
        )));
    }
    Ok(())
}

fn push_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.as_bytes().len() as u32).to_le_bytes());
    output.extend_from_slice(value.as_bytes());
}

fn push_optional_string(output: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&[0; 3]);
            push_string(output, value);
        }
        None => {
            output.push(0);
            output.extend_from_slice(&[0; 3]);
            output.extend_from_slice(&0u32.to_le_bytes());
        }
    }
}

fn read_string(
    bytes: &[u8],
    cursor: &mut usize,
    length: usize,
    name: &str,
) -> Result<String> {
    if length > MAX_STRING_BYTES {
        return Err(CommitError::Invalid(format!(
            "{name} exceeds maximum length",
        )));
    }
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| CommitError::Invalid(
            "string length overflow".to_string(),
        ))?;
    let value = bytes.get(*cursor..end).ok_or_else(|| {
        CommitError::Invalid(format!("truncated string {name}"))
    })?;
    *cursor = end;
    String::from_utf8(value.to_vec()).map_err(|_| {
        CommitError::Invalid(format!("{name} is not UTF-8"))
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes.get(offset..offset + 2).ok_or_else(|| {
        CommitError::Invalid("truncated u16".to_string())
    })?;
    Ok(u16::from_le_bytes(value.try_into().expect("checked u16")))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes.get(offset..offset + 4).ok_or_else(|| {
        CommitError::Invalid("truncated u32".to_string())
    })?;
    Ok(u32::from_le_bytes(value.try_into().expect("checked u32")))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let value = bytes.get(offset..offset + 8).ok_or_else(|| {
        CommitError::Invalid("truncated u64".to_string())
    })?;
    Ok(u64::from_le_bytes(value.try_into().expect("checked u64")))
}

fn read_digest(bytes: &[u8], offset: usize) -> Result<[u8; 32]> {
    let value = bytes.get(offset..offset + 32).ok_or_else(|| {
        CommitError::Invalid("truncated digest".to_string())
    })?;
    Ok(value.try_into().expect("checked digest"))
}

fn nonzero_u64(bytes: &[u8]) -> u64 {
    let mut value = u64::from_le_bytes(
        bytes.try_into().expect("fixed u64 slice"),
    );
    if value == 0 {
        value = 1;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(id: &str, provenance: &str) -> EvidenceRef {
        EvidenceRef {
            evidence_id: id.to_string(),
            provenance_id: provenance.to_string(),
            evidence_digest: sha256(id.as_bytes()),
        }
    }

    #[test]
    fn policy_registry_rejects_trust_neutral_authority() {
        let policy = PolicyDefinition {
            policy_id: "bad".to_string(),
            policy_version: "1".to_string(),
            allowed_authority: TransitionAuthority::Ranker,
            allowed_operation_mask: PolicyDefinition::operation_mask(
                &[TrustOperation::Promote],
            ),
            min_evidence_refs: 1,
            max_evidence_refs: 1,
            required_verifier_id: "verifier".to_string(),
            require_unique_provenance: false,
        };
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn request_digest_is_deterministic() {
        let request = TrustCommitRequest {
            record_id: "alpha".to_string(),
            operation: TrustOperation::Promote,
            authority: TransitionAuthority::EvidencePolicy,
            evidence_refs: vec![evidence("e1", "p1")],
            policy_id: "promote".to_string(),
            policy_version: "1".to_string(),
            verifier_id: "v1".to_string(),
            logical_timestamp: 2,
            reason_code: "PASS".to_string(),
            superseding_record_id: None,
        };
        assert_eq!(
            compute_request_digest(&request),
            compute_request_digest(&request),
        );
    }

    #[test]
    fn stage_machine_is_fail_closed() {
        assert!(validate_stage_transition(
            None,
            CommitStage::Prepared,
        )
        .is_ok());
        assert!(validate_stage_transition(
            Some(CommitStage::Prepared),
            CommitStage::DatabaseCommitted,
        )
        .is_ok());
        assert!(validate_stage_transition(
            Some(CommitStage::Prepared),
            CommitStage::TrustCommitted,
        )
        .is_err());
        assert!(validate_stage_transition(
            Some(CommitStage::Finalized),
            CommitStage::Prepared,
        )
        .is_err());
    }
}
