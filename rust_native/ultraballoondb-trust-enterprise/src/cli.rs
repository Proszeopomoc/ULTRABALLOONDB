use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use ultraballoondb_trust::EvidenceRef;
use ultraballoondb_trust_auth::{
    authority_name, operation_name, parse_authority,
    parse_operation, KeyRegistry, TrustPaths,
    DOMAIN_KEY_ROTATE, DOMAIN_POLICY_REGISTER,
    DOMAIN_POLICY_REVOKE, DOMAIN_TRUST_COMMIT,
};
use ultraballoondb_trust_commit::{
    PolicyDefinition, TrustCommitRequest,
};

use crate::{
    approved_commit_trust, approved_register_policy,
    approved_revoke_policy, approved_rotate_key,
    enable_enterprise, enterprise_status, export_enterprise_audit,
    hex, open_enterprise_profile, ApprovalLedger,
    EnterpriseError, EnterprisePaths, ENTERPRISE_COMMAND_SCHEMA,
    ENTERPRISE_VERSION,
};

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_INVALID_ARGUMENT: i32 = 2;
pub const EXIT_OPERATION_ERROR: i32 = 3;
pub const EXIT_SEMANTIC_CONDITION: i32 = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliError {
    pub exit_code: i32,
    pub code: &'static str,
    pub message: String,
}

impl CliError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            exit_code: EXIT_INVALID_ARGUMENT,
            code: "INVALID_ARGUMENT",
            message: message.into(),
        }
    }

    fn operation(message: impl Into<String>) -> Self {
        Self {
            exit_code: EXIT_OPERATION_ERROR,
            code: "ENTERPRISE_OPERATION_ERROR",
            message: message.into(),
        }
    }

    fn semantic(
        code: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            exit_code: EXIT_SEMANTIC_CONDITION,
            code,
            message: message.into(),
        }
    }

    pub fn json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"schema\":\"{}\",",
                "\"ok\":false,",
                "\"error\":{{",
                "\"code\":\"{}\",",
                "\"message\":\"{}\"",
                "}},",
                "\"network_enabled\":false,",
                "\"automatic_repair_enabled\":false,",
                "\"active_runtime_changed\":false",
                "}}"
            ),
            ENTERPRISE_COMMAND_SCHEMA,
            self.code,
            json_escape(&self.message),
        )
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for CliError {}

impl From<EnterpriseError> for CliError {
    fn from(value: EnterpriseError) -> Self {
        Self::operation(value.to_string())
    }
}

#[derive(Clone, Debug)]
struct ParsedArgs {
    command: String,
    flags: BTreeMap<String, String>,
}

pub fn main_entry<I>(arguments: I) -> i32
where
    I: IntoIterator<Item = String>,
{
    match run_cli(arguments) {
        Ok(output) => {
            println!("{output}");
            EXIT_SUCCESS
        }
        Err(error) => {
            eprintln!("{}", error.json());
            error.exit_code
        }
    }
}

pub fn run_cli<I>(arguments: I) -> Result<String, CliError>
where
    I: IntoIterator<Item = String>,
{
    let parsed = parse_arguments(arguments)?;
    match parsed.command.as_str() {
        "enterprise-enable" => command_enterprise_enable(parsed.flags),
        "approval-request" => command_approval_request(parsed.flags),
        "approval-sign" => command_approval_sign(parsed.flags),
        "approved-key-rotate" => {
            command_approved_key_rotate(parsed.flags)
        }
        "approved-policy-register" => {
            command_approved_policy_register(parsed.flags)
        }
        "approved-policy-revoke" => {
            command_approved_policy_revoke(parsed.flags)
        }
        "approved-trust-commit" => {
            command_approved_trust_commit(parsed.flags)
        }
        "approval-status" => command_approval_status(parsed.flags),
        "enterprise-status" => command_enterprise_status(parsed.flags),
        "enterprise-audit-export" => {
            command_enterprise_audit_export(parsed.flags)
        }
        "help" => command_help(parsed.flags),
        "version" => command_version(parsed.flags),
        command => Err(CliError::invalid(format!(
            "unknown enterprise trust command: {command}",
        ))),
    }
}

fn parse_arguments<I>(arguments: I) -> Result<ParsedArgs, CliError>
where
    I: IntoIterator<Item = String>,
{
    let mut values = arguments.into_iter();
    let _program = values.next();
    let command = values.next().ok_or_else(|| {
        CliError::invalid(
            "missing command; use `ultraballoondb-trust-enterprise help`",
        )
    })?;
    let remaining: Vec<String> = values.collect();
    if remaining.len() % 2 != 0 {
        return Err(CliError::invalid(
            "flags must be --name value pairs",
        ));
    }
    let mut flags = BTreeMap::new();
    let mut index = 0usize;
    while index < remaining.len() {
        let key = &remaining[index];
        let value = &remaining[index + 1];
        if !key.starts_with("--") || key.len() <= 2 {
            return Err(CliError::invalid(format!(
                "invalid flag name: {key}",
            )));
        }
        if flags.insert(
            key[2..].to_string(),
            value.clone(),
        ).is_some() {
            return Err(CliError::invalid(format!(
                "duplicate flag: {key}",
            )));
        }
        index += 2;
    }
    Ok(ParsedArgs { command, flags })
}

fn required(
    flags: &mut BTreeMap<String, String>,
    name: &str,
) -> Result<String, CliError> {
    flags.remove(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::invalid(format!(
            "missing required flag --{name}",
        )))
}

fn optional(
    flags: &mut BTreeMap<String, String>,
    name: &str,
) -> Option<String> {
    flags.remove(name).filter(|value| !value.is_empty())
}

fn reject_unknown(
    flags: &BTreeMap<String, String>,
) -> Result<(), CliError> {
    if let Some(name) = flags.keys().next() {
        return Err(CliError::invalid(format!(
            "unknown flag --{name}",
        )));
    }
    Ok(())
}

fn parse_u64(name: &str, value: &str) -> Result<u64, CliError> {
    value.parse::<u64>().map_err(|_| {
        CliError::invalid(format!(
            "--{name} must be an unsigned 64-bit integer",
        ))
    })
}

fn parse_u32(name: &str, value: &str) -> Result<u32, CliError> {
    value.parse::<u32>().map_err(|_| {
        CliError::invalid(format!(
            "--{name} must be an unsigned 32-bit integer",
        ))
    })
}

fn parse_u16(name: &str, value: &str) -> Result<u16, CliError> {
    value.parse::<u16>().map_err(|_| {
        CliError::invalid(format!(
            "--{name} must be an unsigned 16-bit integer",
        ))
    })
}

fn parse_bool(name: &str, value: &str) -> Result<bool, CliError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(CliError::invalid(format!(
            "--{name} must be true or false",
        ))),
    }
}

fn read_secret(path: &str) -> Result<Vec<u8>, CliError> {
    fs::read(path).map_err(|error| {
        CliError::operation(format!(
            "cannot read secret file {path}: {error}",
        ))
    })
}

fn enterprise_paths(
    flags: &mut BTreeMap<String, String>,
) -> Result<EnterprisePaths, CliError> {
    Ok(EnterprisePaths::from_trust_root(
        required(flags, "trust-root")?,
    ))
}

fn parse_domain(value: &str) -> Result<u8, CliError> {
    match value {
        "POLICY_REGISTER" => Ok(DOMAIN_POLICY_REGISTER),
        "TRUST_COMMIT" => Ok(DOMAIN_TRUST_COMMIT),
        "KEY_ROTATE" => Ok(DOMAIN_KEY_ROTATE),
        "POLICY_REVOKE" => Ok(DOMAIN_POLICY_REVOKE),
        _ => Err(CliError::invalid(format!(
            "unknown enterprise domain: {value}",
        ))),
    }
}

fn domain_name(value: u8) -> &'static str {
    match value {
        DOMAIN_POLICY_REGISTER => "POLICY_REGISTER",
        DOMAIN_TRUST_COMMIT => "TRUST_COMMIT",
        DOMAIN_KEY_ROTATE => "KEY_ROTATE",
        DOMAIN_POLICY_REVOKE => "POLICY_REVOKE",
        _ => "UNKNOWN",
    }
}

fn command_enterprise_enable(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let trust_root = required(&mut flags, "trust-root")?;
    let signer_key_id = required(&mut flags, "signer-key-id")?;
    let signer_key_file = required(&mut flags, "signer-key-file")?;
    let activated_at = parse_u64(
        "activated-at",
        &required(&mut flags, "activated-at")?,
    )?;
    let nonce = required(&mut flags, "nonce")?;
    reject_unknown(&flags)?;

    let signer_secret = read_secret(&signer_key_file)?;
    let receipt = enable_enterprise(
        &trust_root,
        &signer_key_id,
        &signer_secret,
        activated_at,
        &nonce,
    )?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"enterprise-enable\",",
            "\"trust_root\":\"{}\",",
            "\"changed\":{},",
            "\"profile_changed\":{},",
            "\"approval_ledger_changed\":{},",
            "\"profile_digest\":\"{}\",",
            "\"profile_frame_digest\":\"{}\",",
            "\"profile_path\":\"{}\",",
            "\"approval_path\":\"{}\",",
            "\"approval_threshold\":2,",
            "\"approver_role\":\"AUDITOR\",",
            "\"max_logical_ttl\":1000,",
            "\"raw_secret_persisted\":false,",
            "\"network_enabled\":false,",
            "\"automatic_repair_enabled\":false,",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        ENTERPRISE_COMMAND_SCHEMA,
        json_escape(&trust_root),
        json_bool(receipt.changed),
        json_bool(receipt.profile_changed),
        json_bool(receipt.approval_ledger_changed),
        hex(&receipt.profile_digest),
        hex(&receipt.profile_frame_digest),
        json_escape(&receipt.profile_path.to_string_lossy()),
        json_escape(&receipt.approval_path.to_string_lossy()),
    ))
}

fn command_approval_request(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let paths = enterprise_paths(&mut flags)?;
    let domain = parse_domain(
        &required(&mut flags, "domain")?,
    )?;
    let subject_digest = parse_digest(
        &required(&mut flags, "subject-digest")?,
    )?;
    let requester_key_id = required(
        &mut flags,
        "requester-key-id",
    )?;
    let requester_key_file = required(
        &mut flags,
        "requester-key-file",
    )?;
    let created_at = parse_u64(
        "created-at",
        &required(&mut flags, "created-at")?,
    )?;
    let expires_at = parse_u64(
        "expires-at",
        &required(&mut flags, "expires-at")?,
    )?;
    let nonce = required(&mut flags, "nonce")?;
    reject_unknown(&flags)?;

    let profile = open_enterprise_profile(&paths.profile)?;
    let trust = TrustPaths::from_root(&paths.trust_root);
    let registry = KeyRegistry::open_strict(&trust.key_registry)
        .map_err(|error| CliError::operation(error.to_string()))?;
    let mut approvals = ApprovalLedger::open_strict(
        &paths.approvals,
    )?;
    let secret = read_secret(&requester_key_file)?;
    let receipt = approvals.request(
        &profile,
        &registry,
        domain,
        subject_digest,
        &requester_key_id,
        &secret,
        created_at,
        expires_at,
        &nonce,
    )?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"approval-request\",",
            "\"trust_root\":\"{}\",",
            "\"changed\":{},",
            "\"request_id\":\"{}\",",
            "\"domain\":\"{}\",",
            "\"subject_digest\":\"{}\",",
            "\"sequence\":{},",
            "\"created_at\":{},",
            "\"expires_at\":{},",
            "\"threshold\":{},",
            "\"status\":\"PENDING\",",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        ENTERPRISE_COMMAND_SCHEMA,
        json_escape(&paths.trust_root.to_string_lossy()),
        json_bool(receipt.changed),
        hex(&receipt.request_id),
        domain_name(domain),
        hex(&subject_digest),
        receipt.sequence,
        created_at,
        receipt.expires_at,
        receipt.threshold,
    ))
}

fn command_approval_sign(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let paths = enterprise_paths(&mut flags)?;
    let request_id = parse_digest(
        &required(&mut flags, "request-id")?,
    )?;
    let approver_key_id = required(
        &mut flags,
        "approver-key-id",
    )?;
    let approver_key_file = required(
        &mut flags,
        "approver-key-file",
    )?;
    let logical_timestamp = parse_u64(
        "logical-timestamp",
        &required(&mut flags, "logical-timestamp")?,
    )?;
    let nonce = required(&mut flags, "nonce")?;
    reject_unknown(&flags)?;

    let profile = open_enterprise_profile(&paths.profile)?;
    let trust = TrustPaths::from_root(&paths.trust_root);
    let registry = KeyRegistry::open_strict(&trust.key_registry)
        .map_err(|error| CliError::operation(error.to_string()))?;
    let mut approvals = ApprovalLedger::open_strict(
        &paths.approvals,
    )?;
    let secret = read_secret(&approver_key_file)?;
    let receipt = approvals.approve(
        &profile,
        &registry,
        request_id,
        &approver_key_id,
        &secret,
        logical_timestamp,
        &nonce,
    )?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"approval-sign\",",
            "\"trust_root\":\"{}\",",
            "\"request_id\":\"{}\",",
            "\"approver_key_id\":\"{}\",",
            "\"sequence\":{},",
            "\"approval_count\":{},",
            "\"threshold\":{},",
            "\"ready\":{},",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        ENTERPRISE_COMMAND_SCHEMA,
        json_escape(&paths.trust_root.to_string_lossy()),
        hex(&receipt.request_id),
        json_escape(&approver_key_id),
        receipt.sequence,
        receipt.approval_count,
        receipt.threshold,
        json_bool(receipt.ready),
    ))
}

fn command_approved_key_rotate(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let trust_root = required(&mut flags, "trust-root")?;
    let request_id = parse_digest(
        &required(&mut flags, "request-id")?,
    )?;
    let target_key_id = required(
        &mut flags,
        "target-key-id",
    )?;
    let expected_old_fingerprint = parse_digest(
        &required(&mut flags, "expected-old-fingerprint")?,
    )?;
    let new_key_file = required(
        &mut flags,
        "new-key-file",
    )?;
    let signer_key_id = required(
        &mut flags,
        "signer-key-id",
    )?;
    let signer_key_file = required(
        &mut flags,
        "signer-key-file",
    )?;
    let logical_timestamp = parse_u64(
        "logical-timestamp",
        &required(&mut flags, "logical-timestamp")?,
    )?;
    let nonce = required(&mut flags, "nonce")?;
    reject_unknown(&flags)?;

    let new_secret = read_secret(&new_key_file)?;
    let signer_secret = read_secret(&signer_key_file)?;
    let receipt = approved_rotate_key(
        &trust_root,
        request_id,
        &target_key_id,
        expected_old_fingerprint,
        &new_secret,
        &signer_key_id,
        &signer_secret,
        logical_timestamp,
        &nonce,
    )?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"approved-key-rotate\",",
            "\"trust_root\":\"{}\",",
            "\"request_id\":\"{}\",",
            "\"target_key_id\":\"{}\",",
            "\"recovered\":{},",
            "\"key_event_sequence\":{},",
            "\"key_event_frame_digest\":\"{}\",",
            "\"old_fingerprint\":\"{}\",",
            "\"new_fingerprint\":\"{}\",",
            "\"approval_finalization_sequence\":{},",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        ENTERPRISE_COMMAND_SCHEMA,
        json_escape(&trust_root),
        hex(&request_id),
        json_escape(&target_key_id),
        json_bool(receipt.recovered),
        receipt.key_event_sequence,
        hex(&receipt.key_event_frame_digest),
        hex(&receipt.old_fingerprint),
        hex(&receipt.new_fingerprint),
        receipt.approval_finalization_sequence,
    ))
}

fn command_approved_policy_register(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let trust_root = required(&mut flags, "trust-root")?;
    let request_id = parse_digest(
        &required(&mut flags, "request-id")?,
    )?;
    let policy_id = required(&mut flags, "policy-id")?;
    let policy_version = required(&mut flags, "policy-version")?;
    let authority = parse_authority(
        &required(&mut flags, "authority")?,
    )
    .map_err(|error| CliError::invalid(error.to_string()))?;
    let operation_mask = parse_u16(
        "operation-mask",
        &required(&mut flags, "operation-mask")?,
    )?;
    let min_evidence_refs = parse_u32(
        "min-evidence",
        &required(&mut flags, "min-evidence")?,
    )?;
    let max_evidence_refs = parse_u32(
        "max-evidence",
        &required(&mut flags, "max-evidence")?,
    )?;
    let verifier_id = required(&mut flags, "verifier-id")?;
    let require_unique_provenance = parse_bool(
        "unique-provenance",
        &required(&mut flags, "unique-provenance")?,
    )?;
    let signer_key_id = required(
        &mut flags,
        "signer-key-id",
    )?;
    let signer_key_file = required(
        &mut flags,
        "signer-key-file",
    )?;
    let logical_timestamp = parse_u64(
        "logical-timestamp",
        &required(&mut flags, "logical-timestamp")?,
    )?;
    let nonce = required(&mut flags, "nonce")?;
    reject_unknown(&flags)?;

    let policy = PolicyDefinition {
        policy_id: policy_id.clone(),
        policy_version: policy_version.clone(),
        allowed_authority: authority,
        allowed_operation_mask: operation_mask,
        min_evidence_refs,
        max_evidence_refs,
        required_verifier_id: verifier_id.clone(),
        require_unique_provenance,
    };
    let secret = read_secret(&signer_key_file)?;
    let receipt = approved_register_policy(
        &trust_root,
        request_id,
        policy,
        &signer_key_id,
        &secret,
        logical_timestamp,
        &nonce,
    )?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"approved-policy-register\",",
            "\"trust_root\":\"{}\",",
            "\"request_id\":\"{}\",",
            "\"policy_id\":\"{}\",",
            "\"policy_version\":\"{}\",",
            "\"authority\":\"{}\",",
            "\"changed\":{},",
            "\"policy_digest\":\"{}\",",
            "\"authorization_event_id\":\"{}\",",
            "\"authorization_sequence\":{},",
            "\"approval_finalization_sequence\":{},",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        ENTERPRISE_COMMAND_SCHEMA,
        json_escape(&trust_root),
        hex(&request_id),
        json_escape(&policy_id),
        json_escape(&policy_version),
        authority_name(authority),
        json_bool(receipt.operation.changed),
        hex(&receipt.operation.policy_digest),
        hex(&receipt.operation.authorization_event_id),
        receipt.operation.authorization_sequence,
        receipt.approval_finalization_sequence,
    ))
}

fn command_approved_policy_revoke(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let trust_root = required(&mut flags, "trust-root")?;
    let request_id = parse_digest(
        &required(&mut flags, "request-id")?,
    )?;
    let policy_id = required(&mut flags, "policy-id")?;
    let policy_version = required(&mut flags, "policy-version")?;
    let reason_code = required(&mut flags, "reason-code")?;
    let signer_key_id = required(
        &mut flags,
        "signer-key-id",
    )?;
    let signer_key_file = required(
        &mut flags,
        "signer-key-file",
    )?;
    let logical_timestamp = parse_u64(
        "logical-timestamp",
        &required(&mut flags, "logical-timestamp")?,
    )?;
    let nonce = required(&mut flags, "nonce")?;
    reject_unknown(&flags)?;

    let secret = read_secret(&signer_key_file)?;
    let receipt = approved_revoke_policy(
        &trust_root,
        request_id,
        &policy_id,
        &policy_version,
        &reason_code,
        &signer_key_id,
        &secret,
        logical_timestamp,
        &nonce,
    )?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"approved-policy-revoke\",",
            "\"trust_root\":\"{}\",",
            "\"request_id\":\"{}\",",
            "\"policy_id\":\"{}\",",
            "\"policy_version\":\"{}\",",
            "\"changed\":{},",
            "\"policy_digest\":\"{}\",",
            "\"authorization_event_id\":\"{}\",",
            "\"authorization_sequence\":{},",
            "\"policy_status_sequence\":{},",
            "\"approval_finalization_sequence\":{},",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        ENTERPRISE_COMMAND_SCHEMA,
        json_escape(&trust_root),
        hex(&request_id),
        json_escape(&policy_id),
        json_escape(&policy_version),
        json_bool(receipt.operation.changed),
        hex(&receipt.operation.policy_digest),
        hex(&receipt.operation.authorization_event_id),
        receipt.operation.authorization_sequence,
        receipt.operation.policy_status_sequence,
        receipt.approval_finalization_sequence,
    ))
}

fn command_approved_trust_commit(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let database_root = PathBuf::from(
        required(&mut flags, "db")?,
    );
    let trust_root = required(&mut flags, "trust-root")?;
    let request_id = parse_digest(
        &required(&mut flags, "request-id")?,
    )?;
    let record_id = required(&mut flags, "record-id")?;
    let operation = parse_operation(
        &required(&mut flags, "operation")?,
    )
    .map_err(|error| CliError::invalid(error.to_string()))?;
    let authority = parse_authority(
        &required(&mut flags, "authority")?,
    )
    .map_err(|error| CliError::invalid(error.to_string()))?;
    let evidence_file = required(&mut flags, "evidence-file")?;
    let policy_id = required(&mut flags, "policy-id")?;
    let policy_version = required(&mut flags, "policy-version")?;
    let verifier_id = required(&mut flags, "verifier-id")?;
    let transition_timestamp = parse_u64(
        "transition-timestamp",
        &required(&mut flags, "transition-timestamp")?,
    )?;
    let reason_code = required(&mut flags, "reason-code")?;
    let superseding_record_id = optional(
        &mut flags,
        "superseding-record-id",
    );
    let signer_key_id = required(
        &mut flags,
        "signer-key-id",
    )?;
    let signer_key_file = required(
        &mut flags,
        "signer-key-file",
    )?;
    let authorization_timestamp = parse_u64(
        "authorization-timestamp",
        &required(&mut flags, "authorization-timestamp")?,
    )?;
    let nonce = required(&mut flags, "nonce")?;
    reject_unknown(&flags)?;

    let request = TrustCommitRequest {
        record_id: record_id.clone(),
        operation,
        authority,
        evidence_refs: parse_evidence_file(
            Path::new(&evidence_file),
        )?,
        policy_id: policy_id.clone(),
        policy_version: policy_version.clone(),
        verifier_id: verifier_id.clone(),
        logical_timestamp: transition_timestamp,
        reason_code: reason_code.clone(),
        superseding_record_id: superseding_record_id.clone(),
    };
    let secret = read_secret(&signer_key_file)?;
    let receipt = approved_commit_trust(
        &database_root,
        &trust_root,
        request_id,
        request,
        &signer_key_id,
        &secret,
        authorization_timestamp,
        &nonce,
    )?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"approved-trust-commit\",",
            "\"db\":\"{}\",",
            "\"trust_root\":\"{}\",",
            "\"request_id\":\"{}\",",
            "\"record_id\":\"{}\",",
            "\"operation\":\"{}\",",
            "\"authority\":\"{}\",",
            "\"changed\":{},",
            "\"authorization_event_id\":\"{}\",",
            "\"transaction_id\":\"{}\",",
            "\"trust_transition_id\":\"{}\",",
            "\"trust_sequence\":{},",
            "\"journal_sequence\":{},",
            "\"recovered\":{},",
            "\"approval_finalization_sequence\":{},",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        ENTERPRISE_COMMAND_SCHEMA,
        json_escape(&database_root.to_string_lossy()),
        json_escape(&trust_root),
        hex(&request_id),
        json_escape(&record_id),
        operation_name(operation),
        authority_name(authority),
        json_bool(receipt.operation.changed),
        hex(&receipt.operation.authorization_event_id),
        hex(&receipt.operation.transaction_id),
        hex(&receipt.operation.trust_transition_id),
        receipt.operation.trust_sequence,
        receipt.operation.journal_sequence,
        json_bool(receipt.operation.recovered),
        receipt.approval_finalization_sequence,
    ))
}

fn command_approval_status(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let paths = enterprise_paths(&mut flags)?;
    let request_id = parse_digest(
        &required(&mut flags, "request-id")?,
    )?;
    let logical_timestamp = parse_u64(
        "logical-timestamp",
        &required(&mut flags, "logical-timestamp")?,
    )?;
    reject_unknown(&flags)?;

    let approvals = ApprovalLedger::open_strict(
        &paths.approvals,
    )?;
    let state = approvals.get(&request_id).ok_or_else(|| {
        CliError::semantic(
            "APPROVAL_REQUEST_NOT_FOUND",
            "approval request not found",
        )
    })?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"approval-status\",",
            "\"request_id\":\"{}\",",
            "\"domain\":\"{}\",",
            "\"subject_digest\":\"{}\",",
            "\"requester_key_id\":\"{}\",",
            "\"created_at\":{},",
            "\"expires_at\":{},",
            "\"approval_count\":{},",
            "\"threshold\":{},",
            "\"status\":\"{}\",",
            "\"operation_reference\":{},",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        ENTERPRISE_COMMAND_SCHEMA,
        hex(&request_id),
        domain_name(state.request.domain_code),
        hex(&state.request.subject_digest),
        json_escape(&state.request.requester_key_id),
        state.request.created_at,
        state.request.expires_at,
        state.approval_count(),
        state.request.threshold,
        state.status_at(logical_timestamp),
        state.finalization.as_ref()
            .map(|event| format!(
                "\"{}\"", hex(&event.operation_reference)
            ))
            .unwrap_or_else(|| "null".to_string()),
    ))
}

fn command_enterprise_status(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let trust_root = required(&mut flags, "trust-root")?;
    let logical_timestamp = parse_u64(
        "logical-timestamp",
        &required(&mut flags, "logical-timestamp")?,
    )?;
    reject_unknown(&flags)?;

    let status = enterprise_status(
        &trust_root,
        logical_timestamp,
    )?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"enterprise-status\",",
            "\"trust_root\":\"{}\",",
            "\"profile_digest\":\"{}\",",
            "\"profile_activated_at\":{},",
            "\"approval_event_count\":{},",
            "\"approval_request_count\":{},",
            "\"approval_signature_count\":{},",
            "\"approval_finalization_count\":{},",
            "\"expired_request_count\":{},",
            "\"pending_request_count\":{},",
            "\"ready_request_count\":{},",
            "\"finalized_request_count\":{},",
            "\"approval_ledger_head\":\"{}\",",
            "\"network_enabled\":false,",
            "\"automatic_repair_enabled\":false,",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        ENTERPRISE_COMMAND_SCHEMA,
        json_escape(&trust_root),
        hex(&status.profile_digest),
        status.profile_activated_at,
        status.approval_event_count,
        status.approval_request_count,
        status.approval_signature_count,
        status.approval_finalization_count,
        status.expired_request_count,
        status.pending_request_count,
        status.ready_request_count,
        status.finalized_request_count,
        hex(&status.approval_ledger_head),
    ))
}

fn command_enterprise_audit_export(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let database_root = PathBuf::from(
        required(&mut flags, "db")?,
    );
    let trust_root = required(&mut flags, "trust-root")?;
    let output_dir = PathBuf::from(
        required(&mut flags, "output-dir")?,
    );
    let logical_timestamp = parse_u64(
        "logical-timestamp",
        &required(&mut flags, "logical-timestamp")?,
    )?;
    reject_unknown(&flags)?;

    let receipt = export_enterprise_audit(
        &database_root,
        &trust_root,
        &output_dir,
        logical_timestamp,
    )?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"enterprise-audit-export\",",
            "\"db\":\"{}\",",
            "\"trust_root\":\"{}\",",
            "\"output_dir\":\"{}\",",
            "\"protected_operation_count\":{},",
            "\"covered_operation_count\":{},",
            "\"uncovered_operation_count\":{},",
            "\"expired_request_count\":{},",
            "\"manifest_sha256\":\"{}\",",
            "\"summary_sha256\":\"{}\",",
            "\"core_receipt_sha256\":\"{}\",",
            "\"root_digest\":\"{}\",",
            "\"source_unchanged\":{},",
            "\"deterministic_format\":{},",
            "\"enterprise_compliance_pass\":true,",
            "\"raw_secret_persisted\":false,",
            "\"network_enabled\":false,",
            "\"automatic_repair_enabled\":false,",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        ENTERPRISE_COMMAND_SCHEMA,
        json_escape(&database_root.to_string_lossy()),
        json_escape(&trust_root),
        json_escape(&receipt.output_root.to_string_lossy()),
        receipt.protected_operation_count,
        receipt.covered_operation_count,
        receipt.uncovered_operation_count,
        receipt.expired_request_count,
        hex(&receipt.manifest_sha256),
        hex(&receipt.summary_sha256),
        hex(&receipt.core_receipt_sha256),
        hex(&receipt.root_digest),
        json_bool(receipt.source_unchanged),
        json_bool(receipt.deterministic_format),
    ))
}

fn command_help(
    flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    reject_unknown(&flags)?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"help\",",
            "\"commands\":[",
            "\"enterprise-enable\",",
            "\"approval-request\",",
            "\"approval-sign\",",
            "\"approved-key-rotate\",",
            "\"approved-policy-register\",",
            "\"approved-policy-revoke\",",
            "\"approved-trust-commit\",",
            "\"approval-status\",",
            "\"enterprise-status\",",
            "\"enterprise-audit-export\",",
            "\"help\",",
            "\"version\"",
            "],",
            "\"command_count\":12,",
            "\"profile_id\":\"ENTERPRISE_STRICT_V1\",",
            "\"approval_threshold\":2,",
            "\"approver_role\":\"AUDITOR\",",
            "\"max_logical_ttl\":1000,",
            "\"signature_algorithm\":\"HMAC-SHA256\",",
            "\"asymmetric_signature\":false,",
            "\"raw_secret_persisted\":false,",
            "\"network_enabled\":false,",
            "\"automatic_repair_enabled\":false",
            "}}"
        ),
        ENTERPRISE_COMMAND_SCHEMA,
    ))
}

fn command_version(
    flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    reject_unknown(&flags)?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"version\",",
            "\"version\":\"{}\"",
            "}}"
        ),
        ENTERPRISE_COMMAND_SCHEMA,
        ENTERPRISE_VERSION,
    ))
}

fn parse_evidence_file(
    path: &Path,
) -> Result<Vec<EvidenceRef>, CliError> {
    let text = fs::read_to_string(path).map_err(|error| {
        CliError::operation(format!(
            "cannot read evidence file {}: {error}",
            path.display(),
        ))
    })?;
    let mut values = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() {
            return Err(CliError::invalid(format!(
                "blank evidence line at {}",
                index + 1,
            )));
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 3 {
            return Err(CliError::invalid(format!(
                "evidence line {} must contain 3 TSV fields",
                index + 1,
            )));
        }
        if fields[0].is_empty() || fields[1].is_empty() {
            return Err(CliError::invalid(format!(
                "evidence identifiers cannot be empty at line {}",
                index + 1,
            )));
        }
        if !ids.insert(fields[0].to_string()) {
            return Err(CliError::invalid(format!(
                "duplicate evidence ID: {}",
                fields[0],
            )));
        }
        values.push(EvidenceRef {
            evidence_id: fields[0].to_string(),
            provenance_id: fields[1].to_string(),
            evidence_digest: parse_digest(fields[2])?,
        });
    }
    if values.is_empty() {
        return Err(CliError::invalid(
            "evidence file must contain at least one row",
        ));
    }
    Ok(values)
}

fn parse_digest(value: &str) -> Result<[u8; 32], CliError> {
    if value.len() != 64 {
        return Err(CliError::invalid(
            "digest must contain 64 hexadecimal characters",
        ));
    }
    let mut output = [0u8; 32];
    for index in 0..32 {
        output[index] = u8::from_str_radix(
            &value[index * 2..index * 2 + 2],
            16,
        )
        .map_err(|_| CliError::invalid(
            "digest contains a non-hexadecimal character",
        ))?;
    }
    if output == [0; 32] {
        return Err(CliError::invalid(
            "zero digest is forbidden",
        ));
    }
    Ok(output)
}

fn json_bool(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn json_escape(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                write!(
                    &mut output,
                    "\\u{:04X}",
                    character as u32,
                )
                .expect("write to String");
            }
            character => output.push(character),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_has_twelve_commands() {
        let output = run_cli(vec![
            "ultraballoondb-trust-enterprise".to_string(),
            "help".to_string(),
        ]).unwrap();
        assert!(output.contains("\"command_count\":12"));
    }

    #[test]
    fn digest_parser_rejects_zero() {
        assert!(parse_digest(&"00".repeat(32)).is_err());
        assert_eq!(
            parse_digest(&"11".repeat(32)).unwrap(),
            [0x11; 32],
        );
    }
}
