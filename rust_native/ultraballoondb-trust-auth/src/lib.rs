mod crypto;
mod ledger;
mod cli;

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ultraballoondb_lifecycle::DurableDatabase;
use ultraballoondb_storage::sha256;
use ultraballoondb_trust::{
    EvidenceRef, TransitionAuthority, TrustLedger, TrustOperation,
};
use ultraballoondb_trust_commit::{
    CommitStage, PolicyDefinition, PolicyRegistry, TrustCommitCoordinator,
    TrustCommitJournal, TrustCommitReceipt, TrustCommitRequest,
};

pub use cli::{main_entry, run_cli, CliError};
pub use crypto::{
    constant_time_equal, hmac_sha256, key_fingerprint,
    MIN_SECRET_BYTES, MAX_SECRET_BYTES,
};
pub use ledger::{
    domain_name, role_names, AuthorizationLedger, AuthorizationProof,
    AuthorizationRecord, KeyEvent, KeyEventKind, KeyRegistry, KeyState,
    DOMAIN_KEY_BOOTSTRAP, DOMAIN_KEY_REGISTER, DOMAIN_KEY_REVOKE,
    DOMAIN_POLICY_REGISTER, DOMAIN_TRUST_COMMIT, ROLE_ALL, ROLE_AUDITOR,
    ROLE_KEY_ADMIN, ROLE_POLICY_ADMIN, ROLE_TRUST_OPERATOR,
};

pub const TRUST_AUTH_VERSION: &str =
    "V00R3T3_TRUST_POLICY_AUTHORIZATION_SIGNATURES_AND_CLI_SURFACE_R01";
pub const TRUST_COMMAND_SCHEMA: &str =
    "ultraballoondb.trust.command.v1";

#[derive(Debug)]
pub enum AuthError {
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
    Database(String),
    Trust(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Invalid(message) => write!(f, "invalid authorization: {message}"),
            Self::Integrity {
                context,
                expected,
                actual,
            } => write!(
                f,
                "authorization integrity mismatch for {context}: expected={} actual={}",
                hex(expected),
                hex(actual),
            ),
            Self::TruncatedTail {
                context,
                offset,
                remaining_bytes,
            } => write!(
                f,
                "truncated {context} tail at offset {offset}: remaining_bytes={remaining_bytes}",
            ),
            Self::Database(message) => write!(f, "database error: {message}"),
            Self::Trust(message) => write!(f, "trust error: {message}"),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<io::Error> for AuthError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustPaths {
    pub root: PathBuf,
    pub key_registry: PathBuf,
    pub authorization_ledger: PathBuf,
    pub policy_registry: PathBuf,
    pub trust_ledger: PathBuf,
    pub commit_journal: PathBuf,
}

impl TrustPaths {
    pub fn from_root(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        Self {
            key_registry: root.join("keys.ubkey"),
            authorization_ledger: root.join("authorizations.ubauth"),
            policy_registry: root.join("policies.ubpolicy"),
            trust_ledger: root.join("trust.ubtrust"),
            commit_journal: root.join("commit.ubcommit"),
            root,
        }
    }

    pub fn all_files(&self) -> [&Path; 5] {
        [
            &self.key_registry,
            &self.authorization_ledger,
            &self.policy_registry,
            &self.trust_ledger,
            &self.commit_journal,
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedPolicyReceipt {
    pub changed: bool,
    pub policy_digest: [u8; 32],
    pub authorization_event_id: [u8; 32],
    pub authorization_sequence: u64,
    pub policy_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedTrustReceipt {
    pub changed: bool,
    pub authorization_event_id: [u8; 32],
    pub authorization_sequence: u64,
    pub transaction_id: [u8; 32],
    pub trust_transition_id: [u8; 32],
    pub trust_sequence: u64,
    pub journal_sequence: u64,
    pub recovered: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustSurfaceStatus {
    pub key_event_count: usize,
    pub active_key_count: usize,
    pub authorization_count: usize,
    pub policy_count: usize,
    pub trust_transition_count: usize,
    pub commit_journal_entry_count: usize,
    pub database_record_count: u64,
    pub database_edge_count: u64,
    pub key_registry_head: [u8; 32],
    pub authorization_head: [u8; 32],
    pub policy_registry_head: [u8; 32],
    pub trust_ledger_head: [u8; 32],
    pub commit_journal_head: [u8; 32],
    pub database_state_digest: [u8; 32],
}

pub fn create_trust_surface(
    database_root: impl AsRef<Path>,
    paths: &TrustPaths,
) -> Result<()> {
    DurableDatabase::open(database_root.as_ref(), false)
        .map_err(|error| AuthError::Database(error.to_string()))?;
    if paths.root.exists() {
        return Err(AuthError::Invalid(format!(
            "trust root already exists: {}",
            paths.root.display(),
        )));
    }
    fs::create_dir_all(&paths.root)?;
    let result = (|| {
        KeyRegistry::create(&paths.key_registry)?;
        AuthorizationLedger::create(&paths.authorization_ledger)?;
        PolicyRegistry::create(&paths.policy_registry)
            .map_err(|error| AuthError::Trust(error.to_string()))?;
        TrustLedger::create(&paths.trust_ledger)
            .map_err(|error| AuthError::Trust(error.to_string()))?;
        TrustCommitJournal::create(&paths.commit_journal)
            .map_err(|error| AuthError::Trust(error.to_string()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&paths.root);
    }
    result
}

pub fn register_policy_authorized(
    paths: &TrustPaths,
    policy: PolicyDefinition,
    signer_key_id: &str,
    signer_secret: &[u8],
    logical_timestamp: u64,
    nonce: &str,
) -> Result<AuthorizedPolicyReceipt> {
    let registry = KeyRegistry::open_strict(&paths.key_registry)?;
    let mut authorizations =
        AuthorizationLedger::open_strict(&paths.authorization_ledger)?;
    let mut policies = PolicyRegistry::open_strict(&paths.policy_registry)
        .map_err(|error| AuthError::Trust(error.to_string()))?;
    let policy_digest = policy
        .digest()
        .map_err(|error| AuthError::Trust(error.to_string()))?;

    let proof = registry.authorize(
        DOMAIN_POLICY_REGISTER,
        ROLE_POLICY_ADMIN,
        policy_digest,
        signer_key_id,
        signer_secret,
        logical_timestamp,
        nonce,
    )?;
    let (authorization, auth_changed) = authorizations.append_once(
        &registry,
        proof,
        signer_secret,
    )?;

    let existing = policies.get(
        &policy.policy_id,
        &policy.policy_version,
    );
    let changed = match existing {
        Some(value) => {
            let existing_digest = value
                .digest()
                .map_err(|error| AuthError::Trust(error.to_string()))?;
            if existing_digest != policy_digest {
                return Err(AuthError::Invalid(format!(
                    "policy key already exists with different digest: {}@{}",
                    policy.policy_id,
                    policy.policy_version,
                )));
            }
            false
        }
        None => {
            policies
                .register(policy)
                .map_err(|error| AuthError::Trust(error.to_string()))?;
            true
        }
    };

    if !changed && auth_changed {
        // Safe orphan-equivalent authorization: the policy already existed
        // with the exact digest. The signed authorization remains auditable.
    }

    Ok(AuthorizedPolicyReceipt {
        changed,
        policy_digest,
        authorization_event_id: authorization.event_id,
        authorization_sequence: authorization.sequence,
        policy_count: policies.policy_count(),
    })
}

pub fn commit_trust_authorized(
    database_root: impl AsRef<Path>,
    paths: &TrustPaths,
    request: TrustCommitRequest,
    signer_key_id: &str,
    signer_secret: &[u8],
    logical_authorization_timestamp: u64,
    nonce: &str,
) -> Result<AuthorizedTrustReceipt> {
    let subject_digest = signed_trust_request_digest(&request)?;
    let registry = KeyRegistry::open_strict(&paths.key_registry)?;
    let mut authorizations =
        AuthorizationLedger::open_strict(&paths.authorization_ledger)?;
    let proof = registry.authorize(
        DOMAIN_TRUST_COMMIT,
        ROLE_TRUST_OPERATOR,
        subject_digest,
        signer_key_id,
        signer_secret,
        logical_authorization_timestamp,
        nonce,
    )?;
    let (authorization, _auth_changed) = authorizations.append_once(
        &registry,
        proof,
        signer_secret,
    )?;

    let mut coordinator = TrustCommitCoordinator::open_strict(
        database_root,
        &paths.trust_ledger,
        &paths.policy_registry,
        &paths.commit_journal,
    )
    .map_err(|error| AuthError::Trust(error.to_string()))?;

    if let Some(existing) = coordinator
        .commit_journal()
        .entries()
        .iter()
        .find(|entry| {
            entry.stage == CommitStage::Finalized
                && entry.request == request
        })
    {
        return Ok(AuthorizedTrustReceipt {
            changed: false,
            authorization_event_id: authorization.event_id,
            authorization_sequence: authorization.sequence,
            transaction_id: existing.transaction_id,
            trust_transition_id: existing.trust_transition_id,
            trust_sequence: existing.expected_trust_sequence,
            journal_sequence: existing.journal_sequence,
            recovered: false,
        });
    }

    let receipt = coordinator
        .commit(request)
        .map_err(|error| AuthError::Trust(error.to_string()))?;
    Ok(receipt_with_authorization(receipt, authorization))
}

pub fn trust_surface_status(
    database_root: impl AsRef<Path>,
    paths: &TrustPaths,
) -> Result<TrustSurfaceStatus> {
    let database = DurableDatabase::open(database_root.as_ref(), false)
        .map_err(|error| AuthError::Database(error.to_string()))?;
    let keys = KeyRegistry::open_strict(&paths.key_registry)?;
    let authorizations =
        AuthorizationLedger::open_strict(&paths.authorization_ledger)?;
    let policies = PolicyRegistry::open_strict(&paths.policy_registry)
        .map_err(|error| AuthError::Trust(error.to_string()))?;
    let trust = TrustLedger::open_strict(&paths.trust_ledger)
        .map_err(|error| AuthError::Trust(error.to_string()))?;
    let journal = TrustCommitJournal::open_strict(&paths.commit_journal)
        .map_err(|error| AuthError::Trust(error.to_string()))?;
    let (database_record_count, database_edge_count) =
        database.state_counts();
    Ok(TrustSurfaceStatus {
        key_event_count: keys.event_count(),
        active_key_count: keys.active_key_count(),
        authorization_count: authorizations.record_count(),
        policy_count: policies.policy_count(),
        trust_transition_count: trust.transition_count(),
        commit_journal_entry_count: journal.entry_count(),
        database_record_count,
        database_edge_count,
        key_registry_head: keys.head_digest(),
        authorization_head: authorizations.head_digest(),
        policy_registry_head: policies.head_digest(),
        trust_ledger_head: trust.head_digest(),
        commit_journal_head: journal.head_digest(),
        database_state_digest: database.state_sha256(),
    })
}

pub fn signed_trust_request_digest(
    request: &TrustCommitRequest,
) -> Result<[u8; 32]> {
    validate_request_field("record_id", &request.record_id)?;
    validate_request_field("policy_id", &request.policy_id)?;
    validate_request_field("policy_version", &request.policy_version)?;
    validate_request_field("verifier_id", &request.verifier_id)?;
    validate_request_field("reason_code", &request.reason_code)?;
    if request.logical_timestamp == 0 {
        return Err(AuthError::Invalid(
            "trust request logical_timestamp must be non-zero".to_string(),
        ));
    }
    if request.evidence_refs.is_empty() {
        return Err(AuthError::Invalid(
            "trust request requires evidence".to_string(),
        ));
    }
    let mut output = Vec::new();
    output.extend_from_slice(&crypto::TRUST_REQUEST_DOMAIN);
    output.push(request.operation as u8);
    output.push(request.authority as u8);
    output.extend_from_slice(&[0; 6]);
    push_string(&mut output, &request.record_id);
    push_string(&mut output, &request.policy_id);
    push_string(&mut output, &request.policy_version);
    push_string(&mut output, &request.verifier_id);
    push_string(&mut output, &request.reason_code);
    push_optional_string(
        &mut output,
        request.superseding_record_id.as_deref(),
    );
    output.extend_from_slice(&request.logical_timestamp.to_le_bytes());
    output.extend_from_slice(
        &(request.evidence_refs.len() as u32).to_le_bytes(),
    );
    for evidence in &request.evidence_refs {
        validate_evidence(evidence)?;
        push_string(&mut output, &evidence.evidence_id);
        push_string(&mut output, &evidence.provenance_id);
        output.extend_from_slice(&evidence.evidence_digest);
    }
    Ok(sha256(&output))
}

fn receipt_with_authorization(
    receipt: TrustCommitReceipt,
    authorization: AuthorizationRecord,
) -> AuthorizedTrustReceipt {
    AuthorizedTrustReceipt {
        changed: true,
        authorization_event_id: authorization.event_id,
        authorization_sequence: authorization.sequence,
        transaction_id: receipt.transaction_id,
        trust_transition_id: receipt.trust_transition_id,
        trust_sequence: receipt.trust_sequence,
        journal_sequence: receipt.journal_sequence,
        recovered: receipt.recovered,
    }
}

fn validate_request_field(name: &str, value: &str) -> Result<()> {
    crypto::validate_identifier(name, value)
}

fn validate_evidence(evidence: &EvidenceRef) -> Result<()> {
    validate_request_field("evidence_id", &evidence.evidence_id)?;
    validate_request_field("provenance_id", &evidence.provenance_id)?;
    if evidence.evidence_digest == [0; 32] {
        return Err(AuthError::Invalid(
            "evidence digest cannot be zero".to_string(),
        ));
    }
    Ok(())
}

fn push_string(output: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    output.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(bytes);
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

pub fn parse_operation(value: &str) -> Result<TrustOperation> {
    match value {
        "PROPOSE" => Ok(TrustOperation::Propose),
        "PROMOTE" => Ok(TrustOperation::Promote),
        "DISPUTE" => Ok(TrustOperation::Dispute),
        "REVOKE" => Ok(TrustOperation::Revoke),
        "EXPIRE" => Ok(TrustOperation::Expire),
        "SUPERSEDE" => Ok(TrustOperation::Supersede),
        _ => Err(AuthError::Invalid(format!(
            "unknown trust operation: {value}",
        ))),
    }
}

pub fn parse_authority(value: &str) -> Result<TransitionAuthority> {
    match value {
        "EVIDENCE_POLICY" => Ok(TransitionAuthority::EvidencePolicy),
        "IMPORT" => Ok(TransitionAuthority::Import),
        _ => Err(AuthError::Invalid(format!(
            "unsupported trust authority: {value}",
        ))),
    }
}

pub fn operation_name(value: TrustOperation) -> &'static str {
    match value {
        TrustOperation::Propose => "PROPOSE",
        TrustOperation::Promote => "PROMOTE",
        TrustOperation::Dispute => "DISPUTE",
        TrustOperation::Revoke => "REVOKE",
        TrustOperation::Expire => "EXPIRE",
        TrustOperation::Supersede => "SUPERSEDE",
    }
}

pub fn authority_name(value: TransitionAuthority) -> &'static str {
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

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_request_digest_is_deterministic() {
        let request = TrustCommitRequest {
            record_id: "alpha".to_string(),
            operation: TrustOperation::Propose,
            authority: TransitionAuthority::Import,
            evidence_refs: vec![EvidenceRef {
                evidence_id: "e1".to_string(),
                provenance_id: "p1".to_string(),
                evidence_digest: sha256(b"e1"),
            }],
            policy_id: "import-policy".to_string(),
            policy_version: "1".to_string(),
            verifier_id: "import-verifier".to_string(),
            logical_timestamp: 10,
            reason_code: "IMPORTED".to_string(),
            superseding_record_id: None,
        };
        assert_eq!(
            signed_trust_request_digest(&request).unwrap(),
            signed_trust_request_digest(&request).unwrap(),
        );
    }
}
