mod approval;
mod audit;
mod cli;
mod crypto;
mod profile;

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use ultraballoondb_trust_auth::{
    commit_trust_authorized, key_fingerprint, key_rotate_subject,
    register_policy_authorized, revoke_policy_authorized,
    signed_trust_request_digest, AuthorizedPolicyReceipt,
    AuthorizedTrustReceipt, KeyEventKind, KeyRegistry,
    PolicyRevocationReceipt, TrustPaths, DOMAIN_KEY_ROTATE,
    DOMAIN_POLICY_REGISTER, DOMAIN_POLICY_REVOKE,
    DOMAIN_TRUST_COMMIT,
};
use ultraballoondb_trust_commit::{
    PolicyDefinition, TrustCommitRequest,
};

pub use approval::{
    requester_role_for_domain, ApprovalEvent, ApprovalEventKind,
    ApprovalFinalizationReceipt, ApprovalLedger, ApprovalRequestReceipt,
    ApprovalRequestState, ApprovalSignatureReceipt,
    ApprovalValidation,
};
pub use audit::{
    export_enterprise_audit, EnterpriseAuditReceipt,
};
pub use cli::{
    main_entry, run_cli, CliError,
};
pub use crypto::{
    enterprise_audit_root_digest, enterprise_signature_message,
    profile_signature_message, profile_subject_digest,
    request_id, sign_enterprise_event,
};
pub use profile::{
    enable_enterprise_profile, open_enterprise_profile,
    protected_domain_mask, EnterpriseProfile,
    EnterpriseProfileReceipt, ENTERPRISE_APPROVAL_THRESHOLD,
    ENTERPRISE_APPROVER_ROLE_MASK, ENTERPRISE_DISTINCT_APPROVERS,
    ENTERPRISE_MAX_LOGICAL_TTL, ENTERPRISE_ONE_TIME_FINALIZATION,
    ENTERPRISE_PROFILE_ID, ENTERPRISE_REQUESTER_EXCLUDED,
};

pub const ENTERPRISE_VERSION: &str =
    "V00R3T5_TRUST_MULTI_PARTY_APPROVAL_EXPIRY_AND_ENTERPRISE_AUDIT_PROFILE_R01";
pub const ENTERPRISE_COMMAND_SCHEMA: &str =
    "ultraballoondb.trust.enterprise.command.v1";

#[derive(Debug)]
pub enum EnterpriseError {
    Io(io::Error),
    Invalid(String),
    Integrity(String),
    Truncated {
        context: &'static str,
        offset: usize,
        remaining_bytes: usize,
    },
    Trust(String),
    Database(String),
}

impl fmt::Display for EnterpriseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Invalid(message) => {
                write!(f, "invalid enterprise trust operation: {message}")
            }
            Self::Integrity(message) => {
                write!(f, "enterprise integrity error: {message}")
            }
            Self::Truncated {
                context,
                offset,
                remaining_bytes,
            } => write!(
                f,
                "truncated {context} at offset {offset}: remaining_bytes={remaining_bytes}",
            ),
            Self::Trust(message) => write!(f, "trust error: {message}"),
            Self::Database(message) => {
                write!(f, "database error: {message}")
            }
        }
    }
}

impl std::error::Error for EnterpriseError {}

impl From<io::Error> for EnterpriseError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, EnterpriseError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnterprisePaths {
    pub trust_root: PathBuf,
    pub profile: PathBuf,
    pub approvals: PathBuf,
}

impl EnterprisePaths {
    pub fn from_trust_root(
        trust_root: impl AsRef<Path>,
    ) -> Self {
        let trust_root = trust_root.as_ref().to_path_buf();
        Self {
            profile: trust_root.join("enterprise.ubent"),
            approvals: trust_root.join("approvals.ubapproval"),
            trust_root,
        }
    }

    pub fn all_files(&self) -> [&Path; 2] {
        [&self.profile, &self.approvals]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnterpriseEnableReceipt {
    pub changed: bool,
    pub profile_changed: bool,
    pub approval_ledger_changed: bool,
    pub profile_digest: [u8; 32],
    pub profile_frame_digest: [u8; 32],
    pub profile_path: PathBuf,
    pub approval_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedKeyRotationReceipt {
    pub recovered: bool,
    pub key_event_sequence: u64,
    pub key_event_frame_digest: [u8; 32],
    pub old_fingerprint: [u8; 32],
    pub new_fingerprint: [u8; 32],
    pub approval_finalization_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedPolicyReceipt {
    pub operation: AuthorizedPolicyReceipt,
    pub approval_finalization_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedPolicyRevocationReceipt {
    pub operation: PolicyRevocationReceipt,
    pub approval_finalization_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedTrustReceipt {
    pub operation: AuthorizedTrustReceipt,
    pub approval_finalization_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnterpriseStatus {
    pub profile_digest: [u8; 32],
    pub profile_activated_at: u64,
    pub approval_event_count: usize,
    pub approval_request_count: usize,
    pub approval_signature_count: usize,
    pub approval_finalization_count: usize,
    pub expired_request_count: usize,
    pub pending_request_count: usize,
    pub ready_request_count: usize,
    pub finalized_request_count: usize,
    pub approval_ledger_head: [u8; 32],
}

pub fn enable_enterprise(
    trust_root: impl AsRef<Path>,
    signer_key_id: &str,
    signer_secret: &[u8],
    activated_at: u64,
    nonce: &str,
) -> Result<EnterpriseEnableReceipt> {
    let enterprise = EnterprisePaths::from_trust_root(
        trust_root.as_ref(),
    );
    let trust = TrustPaths::from_root(trust_root.as_ref());
    KeyRegistry::open_strict(&trust.key_registry)
        .map_err(|error| EnterpriseError::Trust(error.to_string()))?;

    let profile_receipt = enable_enterprise_profile(
        &enterprise.profile,
        &trust.key_registry,
        signer_key_id,
        signer_secret,
        activated_at,
        nonce,
    )?;
    let approval_ledger_changed = if enterprise.approvals.exists() {
        ApprovalLedger::open_strict(&enterprise.approvals)?;
        false
    } else {
        ApprovalLedger::create(&enterprise.approvals)?;
        true
    };
    Ok(EnterpriseEnableReceipt {
        changed: profile_receipt.changed
            || approval_ledger_changed,
        profile_changed: profile_receipt.changed,
        approval_ledger_changed,
        profile_digest: profile_receipt.profile_digest,
        profile_frame_digest: profile_receipt.frame_digest,
        profile_path: enterprise.profile,
        approval_path: enterprise.approvals,
    })
}

pub fn approved_register_policy(
    trust_root: impl AsRef<Path>,
    request_id: [u8; 32],
    policy: PolicyDefinition,
    signer_key_id: &str,
    signer_secret: &[u8],
    logical_timestamp: u64,
    nonce: &str,
) -> Result<ApprovedPolicyReceipt> {
    let enterprise = EnterprisePaths::from_trust_root(
        trust_root.as_ref(),
    );
    let trust = TrustPaths::from_root(trust_root.as_ref());
    let profile = open_enterprise_profile(&enterprise.profile)?;
    let mut approvals = ApprovalLedger::open_strict(
        &enterprise.approvals,
    )?;
    let policy_digest = policy
        .digest()
        .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    approvals.validate_ready(
        &profile,
        request_id,
        DOMAIN_POLICY_REGISTER,
        policy_digest,
        signer_key_id,
        logical_timestamp,
    )?;
    let operation = register_policy_authorized(
        &trust,
        policy,
        signer_key_id,
        signer_secret,
        logical_timestamp,
        nonce,
    )
    .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    let registry = KeyRegistry::open_strict(&trust.key_registry)
        .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    let finalization = approvals.finalize(
        &profile,
        &registry,
        request_id,
        signer_key_id,
        signer_secret,
        logical_timestamp,
        &format!("{nonce}:approval-finalize"),
        operation.authorization_event_id,
    )?;
    Ok(ApprovedPolicyReceipt {
        operation,
        approval_finalization_sequence: finalization.sequence,
    })
}

pub fn approved_revoke_policy(
    trust_root: impl AsRef<Path>,
    request_id: [u8; 32],
    policy_id: &str,
    policy_version: &str,
    reason_code: &str,
    signer_key_id: &str,
    signer_secret: &[u8],
    logical_timestamp: u64,
    nonce: &str,
) -> Result<ApprovedPolicyRevocationReceipt> {
    let enterprise = EnterprisePaths::from_trust_root(
        trust_root.as_ref(),
    );
    let trust = TrustPaths::from_root(trust_root.as_ref());
    let profile = open_enterprise_profile(&enterprise.profile)?;
    let mut approvals = ApprovalLedger::open_strict(
        &enterprise.approvals,
    )?;
    let policies =
        ultraballoondb_trust_commit::PolicyRegistry::open_strict(
            &trust.policy_registry,
        )
        .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    let policy = policies.get(policy_id, policy_version)
        .ok_or_else(|| EnterpriseError::Invalid(format!(
            "unknown policy version: {policy_id}@{policy_version}",
        )))?;
    let policy_digest = policy
        .digest()
        .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    let subject = ultraballoondb_trust_auth::policy_revoke_subject(
        policy_id,
        policy_version,
        policy_digest,
        reason_code,
    )
    .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    approvals.validate_ready(
        &profile,
        request_id,
        DOMAIN_POLICY_REVOKE,
        subject,
        signer_key_id,
        logical_timestamp,
    )?;
    let operation = revoke_policy_authorized(
        &trust,
        policy_id,
        policy_version,
        reason_code,
        signer_key_id,
        signer_secret,
        logical_timestamp,
        nonce,
    )
    .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    let registry = KeyRegistry::open_strict(&trust.key_registry)
        .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    let finalization = approvals.finalize(
        &profile,
        &registry,
        request_id,
        signer_key_id,
        signer_secret,
        logical_timestamp,
        &format!("{nonce}:approval-finalize"),
        operation.authorization_event_id,
    )?;
    Ok(ApprovedPolicyRevocationReceipt {
        operation,
        approval_finalization_sequence: finalization.sequence,
    })
}

pub fn approved_commit_trust(
    database_root: impl AsRef<Path>,
    trust_root: impl AsRef<Path>,
    request_id: [u8; 32],
    request: TrustCommitRequest,
    signer_key_id: &str,
    signer_secret: &[u8],
    logical_authorization_timestamp: u64,
    nonce: &str,
) -> Result<ApprovedTrustReceipt> {
    let enterprise = EnterprisePaths::from_trust_root(
        trust_root.as_ref(),
    );
    let trust = TrustPaths::from_root(trust_root.as_ref());
    let profile = open_enterprise_profile(&enterprise.profile)?;
    let mut approvals = ApprovalLedger::open_strict(
        &enterprise.approvals,
    )?;
    let subject = signed_trust_request_digest(&request)
        .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    approvals.validate_ready(
        &profile,
        request_id,
        DOMAIN_TRUST_COMMIT,
        subject,
        signer_key_id,
        logical_authorization_timestamp,
    )?;
    let operation = commit_trust_authorized(
        database_root,
        &trust,
        request,
        signer_key_id,
        signer_secret,
        logical_authorization_timestamp,
        nonce,
    )
    .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    let registry = KeyRegistry::open_strict(&trust.key_registry)
        .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    let finalization = approvals.finalize(
        &profile,
        &registry,
        request_id,
        signer_key_id,
        signer_secret,
        logical_authorization_timestamp,
        &format!("{nonce}:approval-finalize"),
        operation.authorization_event_id,
    )?;
    Ok(ApprovedTrustReceipt {
        operation,
        approval_finalization_sequence: finalization.sequence,
    })
}

pub fn approved_rotate_key(
    trust_root: impl AsRef<Path>,
    request_id: [u8; 32],
    target_key_id: &str,
    expected_old_fingerprint: [u8; 32],
    new_secret: &[u8],
    signer_key_id: &str,
    signer_secret: &[u8],
    logical_timestamp: u64,
    nonce: &str,
) -> Result<ApprovedKeyRotationReceipt> {
    let enterprise = EnterprisePaths::from_trust_root(
        trust_root.as_ref(),
    );
    let trust = TrustPaths::from_root(trust_root.as_ref());
    let profile = open_enterprise_profile(&enterprise.profile)?;
    let mut approvals = ApprovalLedger::open_strict(
        &enterprise.approvals,
    )?;
    let mut registry = KeyRegistry::open_strict(&trust.key_registry)
        .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    let current = registry.get(target_key_id)
        .cloned()
        .ok_or_else(|| EnterpriseError::Invalid(format!(
            "rotation target is unknown: {target_key_id}",
        )))?;
    let new_fingerprint = key_fingerprint(new_secret)
        .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    let subject = key_rotate_subject(
        target_key_id,
        expected_old_fingerprint,
        new_fingerprint,
        current.role_mask,
    )
    .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    approvals.validate_ready(
        &profile,
        request_id,
        DOMAIN_KEY_ROTATE,
        subject,
        signer_key_id,
        logical_timestamp,
    )?;

    let (event, recovered) = if current.fingerprint
        == expected_old_fingerprint
    {
        (
            registry.rotate_key(
                target_key_id,
                new_secret,
                signer_key_id,
                signer_secret,
                logical_timestamp,
                nonce,
            )
            .map_err(|error| {
                EnterpriseError::Trust(error.to_string())
            })?,
            false,
        )
    } else if current.fingerprint == new_fingerprint {
        let existing = registry.events().iter().find(|event| {
            event.kind == KeyEventKind::Rotate
                && event.target_key_id == target_key_id
                && event.target_fingerprint == new_fingerprint
                && event.subject_digest == subject
        })
        .cloned()
        .ok_or_else(|| EnterpriseError::Invalid(
            "rotated target state lacks matching rotation event"
                .to_string(),
        ))?;
        (existing, true)
    } else {
        return Err(EnterpriseError::Invalid(
            "rotation target fingerprint matches neither expected old nor new key"
                .to_string(),
        ));
    };

    let registry_after = KeyRegistry::open_strict(
        &trust.key_registry,
    )
    .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    let finalize_secret = if signer_key_id == target_key_id {
        new_secret
    } else {
        signer_secret
    };
    let finalization = approvals.finalize(
        &profile,
        &registry_after,
        request_id,
        signer_key_id,
        finalize_secret,
        logical_timestamp,
        &format!("{nonce}:approval-finalize"),
        event.frame_digest,
    )?;
    Ok(ApprovedKeyRotationReceipt {
        recovered,
        key_event_sequence: event.sequence,
        key_event_frame_digest: event.frame_digest,
        old_fingerprint: expected_old_fingerprint,
        new_fingerprint,
        approval_finalization_sequence: finalization.sequence,
    })
}

pub fn enterprise_status(
    trust_root: impl AsRef<Path>,
    logical_timestamp: u64,
) -> Result<EnterpriseStatus> {
    let enterprise = EnterprisePaths::from_trust_root(
        trust_root.as_ref(),
    );
    let profile = open_enterprise_profile(&enterprise.profile)?;
    let approvals = ApprovalLedger::open_strict(
        &enterprise.approvals,
    )?;
    let mut pending = 0usize;
    let mut ready = 0usize;
    let mut finalized = 0usize;
    for state in approvals.states().values() {
        match state.status_at(logical_timestamp) {
            "PENDING" => pending += 1,
            "READY" => ready += 1,
            "FINALIZED" => finalized += 1,
            "EXPIRED" => {}
            _ => unreachable!("known approval status"),
        }
    }
    Ok(EnterpriseStatus {
        profile_digest: profile.profile_digest,
        profile_activated_at: profile.activated_at,
        approval_event_count: approvals.event_count(),
        approval_request_count: approvals.request_count(),
        approval_signature_count: approvals.approval_count(),
        approval_finalization_count:
            approvals.finalization_count(),
        expired_request_count:
            approvals.expired_count_at(logical_timestamp),
        pending_request_count: pending,
        ready_request_count: ready,
        finalized_request_count: finalized,
        approval_ledger_head: approvals.head_digest(),
    })
}

pub fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02X}")
            .expect("write to String");
    }
    output
}
