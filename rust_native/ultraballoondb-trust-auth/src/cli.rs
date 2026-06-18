use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use ultraballoondb_storage::hex_digest;
use ultraballoondb_trust::EvidenceRef;
use ultraballoondb_trust_commit::{
    PolicyDefinition, PolicyRegistry, TrustCommitRequest,
};

use crate::{
    authority_name, commit_trust_authorized, create_trust_surface,
    domain_name, hex, operation_name, parse_authority, parse_operation,
    register_policy_authorized, role_names, trust_surface_status,
    AuthError, AuthorizationLedger, KeyRegistry, TrustPaths,
    TRUST_AUTH_VERSION, TRUST_COMMAND_SCHEMA,
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
            code: "TRUST_OPERATION_ERROR",
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
                "\"automatic_repair_enabled\":false",
                "}}"
            ),
            TRUST_COMMAND_SCHEMA,
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

impl From<AuthError> for CliError {
    fn from(value: AuthError) -> Self {
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
        "trust-init" => command_trust_init(parsed.flags),
        "trust-key-bootstrap" => command_key_bootstrap(parsed.flags),
        "trust-key-register" => command_key_register(parsed.flags),
        "trust-key-revoke" => command_key_revoke(parsed.flags),
        "trust-policy-register" => command_policy_register(parsed.flags),
        "trust-commit" => command_trust_commit(parsed.flags),
        "trust-status" => command_trust_status(parsed.flags),
        "trust-list-keys" => command_list_keys(parsed.flags),
        "trust-list-policies" => command_list_policies(parsed.flags),
        "trust-list-authorizations" => {
            command_list_authorizations(parsed.flags)
        }
        "help" => command_help(parsed.flags),
        "version" => command_version(parsed.flags),
        command => Err(CliError::invalid(format!(
            "unknown trust command: {command}",
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
            "missing command; use `ultraballoondb-trust help`",
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

fn paths(
    flags: &mut BTreeMap<String, String>,
) -> Result<TrustPaths, CliError> {
    Ok(TrustPaths::from_root(required(flags, "trust-root")?))
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

fn command_trust_init(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let db = PathBuf::from(required(&mut flags, "db")?);
    let paths = paths(&mut flags)?;
    reject_unknown(&flags)?;
    create_trust_surface(&db, &paths)?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"trust-init\",",
            "\"db\":\"{}\",",
            "\"trust_root\":\"{}\",",
            "\"key_registry\":\"{}\",",
            "\"authorization_ledger\":\"{}\",",
            "\"policy_registry\":\"{}\",",
            "\"trust_ledger\":\"{}\",",
            "\"commit_journal\":\"{}\",",
            "\"raw_secret_persisted\":false,",
            "\"network_enabled\":false,",
            "\"automatic_repair_enabled\":false,",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        TRUST_COMMAND_SCHEMA,
        json_escape(&db.to_string_lossy()),
        json_escape(&paths.root.to_string_lossy()),
        json_escape(&paths.key_registry.to_string_lossy()),
        json_escape(&paths.authorization_ledger.to_string_lossy()),
        json_escape(&paths.policy_registry.to_string_lossy()),
        json_escape(&paths.trust_ledger.to_string_lossy()),
        json_escape(&paths.commit_journal.to_string_lossy()),
    ))
}

fn command_key_bootstrap(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let paths = paths(&mut flags)?;
    let key_id = required(&mut flags, "key-id")?;
    let role_mask = parse_u16(
        "role-mask",
        &required(&mut flags, "role-mask")?,
    )?;
    let secret_path = required(&mut flags, "key-file")?;
    let timestamp = parse_u64(
        "logical-timestamp",
        &required(&mut flags, "logical-timestamp")?,
    )?;
    let nonce = required(&mut flags, "nonce")?;
    reject_unknown(&flags)?;

    let secret = read_secret(&secret_path)?;
    let mut registry = KeyRegistry::open_strict(&paths.key_registry)?;
    let event = registry.bootstrap(
        &key_id,
        role_mask,
        &secret,
        timestamp,
        &nonce,
    )?;
    Ok(key_event_json(
        "trust-key-bootstrap",
        &paths,
        &event,
        registry.event_count(),
        registry.active_key_count(),
    )?)
}

fn command_key_register(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let paths = paths(&mut flags)?;
    let target_key_id = required(&mut flags, "new-key-id")?;
    let target_role_mask = parse_u16(
        "new-role-mask",
        &required(&mut flags, "new-role-mask")?,
    )?;
    let target_secret_path = required(&mut flags, "new-key-file")?;
    let signer_key_id = required(&mut flags, "signer-key-id")?;
    let signer_secret_path = required(&mut flags, "signer-key-file")?;
    let timestamp = parse_u64(
        "logical-timestamp",
        &required(&mut flags, "logical-timestamp")?,
    )?;
    let nonce = required(&mut flags, "nonce")?;
    reject_unknown(&flags)?;

    let target_secret = read_secret(&target_secret_path)?;
    let signer_secret = read_secret(&signer_secret_path)?;
    let mut registry = KeyRegistry::open_strict(&paths.key_registry)?;
    let event = registry.register_key(
        &target_key_id,
        target_role_mask,
        &target_secret,
        &signer_key_id,
        &signer_secret,
        timestamp,
        &nonce,
    )?;
    Ok(key_event_json(
        "trust-key-register",
        &paths,
        &event,
        registry.event_count(),
        registry.active_key_count(),
    )?)
}

fn command_key_revoke(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let paths = paths(&mut flags)?;
    let target_key_id = required(&mut flags, "target-key-id")?;
    let signer_key_id = required(&mut flags, "signer-key-id")?;
    let signer_secret_path = required(&mut flags, "signer-key-file")?;
    let timestamp = parse_u64(
        "logical-timestamp",
        &required(&mut flags, "logical-timestamp")?,
    )?;
    let nonce = required(&mut flags, "nonce")?;
    reject_unknown(&flags)?;

    let signer_secret = read_secret(&signer_secret_path)?;
    let mut registry = KeyRegistry::open_strict(&paths.key_registry)?;
    let event = registry.revoke_key(
        &target_key_id,
        &signer_key_id,
        &signer_secret,
        timestamp,
        &nonce,
    )?;
    Ok(key_event_json(
        "trust-key-revoke",
        &paths,
        &event,
        registry.event_count(),
        registry.active_key_count(),
    )?)
}

fn command_policy_register(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let paths = paths(&mut flags)?;
    let policy_id = required(&mut flags, "policy-id")?;
    let policy_version = required(&mut flags, "policy-version")?;
    let authority = parse_authority(
        &required(&mut flags, "authority")?,
    )?;
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
    let signer_key_id = required(&mut flags, "signer-key-id")?;
    let signer_secret_path = required(&mut flags, "signer-key-file")?;
    let authorization_timestamp = parse_u64(
        "authorization-timestamp",
        &required(&mut flags, "authorization-timestamp")?,
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
    let signer_secret = read_secret(&signer_secret_path)?;
    let receipt = register_policy_authorized(
        &paths,
        policy,
        &signer_key_id,
        &signer_secret,
        authorization_timestamp,
        &nonce,
    )?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"trust-policy-register\",",
            "\"trust_root\":\"{}\",",
            "\"changed\":{},",
            "\"policy_id\":\"{}\",",
            "\"policy_version\":\"{}\",",
            "\"authority\":\"{}\",",
            "\"operation_mask\":{},",
            "\"min_evidence\":{},",
            "\"max_evidence\":{},",
            "\"verifier_id\":\"{}\",",
            "\"unique_provenance\":{},",
            "\"policy_digest\":\"{}\",",
            "\"authorization_event_id\":\"{}\",",
            "\"authorization_sequence\":{},",
            "\"policy_count\":{},",
            "\"signature_algorithm\":\"HMAC-SHA256\",",
            "\"raw_secret_persisted\":false,",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        TRUST_COMMAND_SCHEMA,
        json_escape(&paths.root.to_string_lossy()),
        json_bool(receipt.changed),
        json_escape(&policy_id),
        json_escape(&policy_version),
        authority_name(authority),
        operation_mask,
        min_evidence_refs,
        max_evidence_refs,
        json_escape(&verifier_id),
        json_bool(require_unique_provenance),
        hex(&receipt.policy_digest),
        hex(&receipt.authorization_event_id),
        receipt.authorization_sequence,
        receipt.policy_count,
    ))
}

fn command_trust_commit(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let db = PathBuf::from(required(&mut flags, "db")?);
    let paths = paths(&mut flags)?;
    let record_id = required(&mut flags, "record-id")?;
    let operation = parse_operation(
        &required(&mut flags, "operation")?,
    )?;
    let authority = parse_authority(
        &required(&mut flags, "authority")?,
    )?;
    let evidence_file = required(&mut flags, "evidence-file")?;
    let policy_id = required(&mut flags, "policy-id")?;
    let policy_version = required(&mut flags, "policy-version")?;
    let verifier_id = required(&mut flags, "verifier-id")?;
    let logical_timestamp = parse_u64(
        "logical-timestamp",
        &required(&mut flags, "logical-timestamp")?,
    )?;
    let reason_code = required(&mut flags, "reason-code")?;
    let superseding_record_id =
        optional(&mut flags, "superseding-record-id");
    let signer_key_id = required(&mut flags, "signer-key-id")?;
    let signer_secret_path = required(&mut flags, "signer-key-file")?;
    let authorization_timestamp = parse_u64(
        "authorization-timestamp",
        &required(&mut flags, "authorization-timestamp")?,
    )?;
    let nonce = required(&mut flags, "nonce")?;
    reject_unknown(&flags)?;

    let evidence_refs = parse_evidence_file(Path::new(&evidence_file))?;
    let request = TrustCommitRequest {
        record_id: record_id.clone(),
        operation,
        authority,
        evidence_refs,
        policy_id: policy_id.clone(),
        policy_version: policy_version.clone(),
        verifier_id: verifier_id.clone(),
        logical_timestamp,
        reason_code: reason_code.clone(),
        superseding_record_id: superseding_record_id.clone(),
    };
    let signer_secret = read_secret(&signer_secret_path)?;
    let receipt = commit_trust_authorized(
        &db,
        &paths,
        request,
        &signer_key_id,
        &signer_secret,
        authorization_timestamp,
        &nonce,
    )?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"trust-commit\",",
            "\"db\":\"{}\",",
            "\"trust_root\":\"{}\",",
            "\"changed\":{},",
            "\"record_id\":\"{}\",",
            "\"operation\":\"{}\",",
            "\"authority\":\"{}\",",
            "\"policy_id\":\"{}\",",
            "\"policy_version\":\"{}\",",
            "\"transaction_id\":\"{}\",",
            "\"trust_transition_id\":\"{}\",",
            "\"trust_sequence\":{},",
            "\"journal_sequence\":{},",
            "\"authorization_event_id\":\"{}\",",
            "\"authorization_sequence\":{},",
            "\"recovered\":{},",
            "\"signature_algorithm\":\"HMAC-SHA256\",",
            "\"raw_secret_persisted\":false,",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        TRUST_COMMAND_SCHEMA,
        json_escape(&db.to_string_lossy()),
        json_escape(&paths.root.to_string_lossy()),
        json_bool(receipt.changed),
        json_escape(&record_id),
        operation_name(operation),
        authority_name(authority),
        json_escape(&policy_id),
        json_escape(&policy_version),
        hex(&receipt.transaction_id),
        hex(&receipt.trust_transition_id),
        receipt.trust_sequence,
        receipt.journal_sequence,
        hex(&receipt.authorization_event_id),
        receipt.authorization_sequence,
        json_bool(receipt.recovered),
    ))
}

fn command_trust_status(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let db = PathBuf::from(required(&mut flags, "db")?);
    let paths = paths(&mut flags)?;
    reject_unknown(&flags)?;
    let status = trust_surface_status(&db, &paths)?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"trust-status\",",
            "\"db\":\"{}\",",
            "\"trust_root\":\"{}\",",
            "\"key_event_count\":{},",
            "\"active_key_count\":{},",
            "\"authorization_count\":{},",
            "\"policy_count\":{},",
            "\"trust_transition_count\":{},",
            "\"commit_journal_entry_count\":{},",
            "\"database_record_count\":{},",
            "\"database_edge_count\":{},",
            "\"key_registry_head\":\"{}\",",
            "\"authorization_head\":\"{}\",",
            "\"policy_registry_head\":\"{}\",",
            "\"trust_ledger_head\":\"{}\",",
            "\"commit_journal_head\":\"{}\",",
            "\"database_state_digest\":\"{}\",",
            "\"signature_algorithm\":\"HMAC-SHA256\",",
            "\"raw_secret_persisted\":false,",
            "\"network_enabled\":false,",
            "\"automatic_repair_enabled\":false,",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        TRUST_COMMAND_SCHEMA,
        json_escape(&db.to_string_lossy()),
        json_escape(&paths.root.to_string_lossy()),
        status.key_event_count,
        status.active_key_count,
        status.authorization_count,
        status.policy_count,
        status.trust_transition_count,
        status.commit_journal_entry_count,
        status.database_record_count,
        status.database_edge_count,
        hex(&status.key_registry_head),
        hex(&status.authorization_head),
        hex(&status.policy_registry_head),
        hex(&status.trust_ledger_head),
        hex(&status.commit_journal_head),
        hex(&status.database_state_digest),
    ))
}

fn command_list_keys(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let paths = paths(&mut flags)?;
    reject_unknown(&flags)?;
    let registry = KeyRegistry::open_strict(&paths.key_registry)?;
    let values = registry.states().values().map(|state| {
        let roles = role_names(state.role_mask)
            .unwrap_or_default()
            .into_iter()
            .map(|value| format!("\"{}\"", value))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            concat!(
                "{{",
                "\"key_id\":\"{}\",",
                "\"fingerprint\":\"{}\",",
                "\"role_mask\":{},",
                "\"roles\":[{}],",
                "\"active\":{},",
                "\"registered_sequence\":{},",
                "\"revoked_sequence\":{}",
                "}}"
            ),
            json_escape(&state.key_id),
            hex(&state.fingerprint),
            state.role_mask,
            roles,
            json_bool(state.active),
            state.registered_sequence,
            optional_u64_json(state.revoked_sequence),
        )
    }).collect::<Vec<_>>().join(",");
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"trust-list-keys\",",
            "\"trust_root\":\"{}\",",
            "\"key_count\":{},",
            "\"active_key_count\":{},",
            "\"keys\":[{}],",
            "\"raw_secret_persisted\":false,",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        TRUST_COMMAND_SCHEMA,
        json_escape(&paths.root.to_string_lossy()),
        registry.states().len(),
        registry.active_key_count(),
        values,
    ))
}

fn command_list_policies(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let paths = paths(&mut flags)?;
    reject_unknown(&flags)?;
    let policies = parse_policy_views(&paths.policy_registry)?;
    let values = policies.iter().map(|policy| {
        format!(
            concat!(
                "{{",
                "\"policy_id\":\"{}\",",
                "\"policy_version\":\"{}\",",
                "\"authority\":\"{}\",",
                "\"operation_mask\":{},",
                "\"min_evidence\":{},",
                "\"max_evidence\":{},",
                "\"verifier_id\":\"{}\",",
                "\"unique_provenance\":{},",
                "\"policy_digest\":\"{}\"",
                "}}"
            ),
            json_escape(&policy.policy_id),
            json_escape(&policy.policy_version),
            json_escape(&policy.authority),
            policy.operation_mask,
            policy.min_evidence,
            policy.max_evidence,
            json_escape(&policy.verifier_id),
            json_bool(policy.unique_provenance),
            hex(&policy.policy_digest),
        )
    }).collect::<Vec<_>>().join(",");
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"trust-list-policies\",",
            "\"trust_root\":\"{}\",",
            "\"policy_count\":{},",
            "\"policies\":[{}],",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        TRUST_COMMAND_SCHEMA,
        json_escape(&paths.root.to_string_lossy()),
        policies.len(),
        values,
    ))
}

fn command_list_authorizations(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let paths = paths(&mut flags)?;
    reject_unknown(&flags)?;
    let ledger =
        AuthorizationLedger::open_strict(&paths.authorization_ledger)?;
    let values = ledger.records().iter().map(|record| {
        let domain = domain_name(record.proof.domain_code)
            .unwrap_or("UNKNOWN");
        format!(
            concat!(
                "{{",
                "\"sequence\":{},",
                "\"event_id\":\"{}\",",
                "\"domain\":\"{}\",",
                "\"required_role\":{},",
                "\"subject_digest\":\"{}\",",
                "\"signer_key_id\":\"{}\",",
                "\"signer_fingerprint\":\"{}\",",
                "\"logical_timestamp\":{},",
                "\"nonce\":\"{}\",",
                "\"signature\":\"{}\"",
                "}}"
            ),
            record.sequence,
            hex(&record.event_id),
            domain,
            record.proof.required_role,
            hex(&record.proof.subject_digest),
            json_escape(&record.proof.signer_key_id),
            hex(&record.proof.signer_fingerprint),
            record.proof.logical_timestamp,
            json_escape(&record.proof.nonce),
            hex(&record.proof.signature),
        )
    }).collect::<Vec<_>>().join(",");
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"trust-list-authorizations\",",
            "\"trust_root\":\"{}\",",
            "\"authorization_count\":{},",
            "\"authorizations\":[{}],",
            "\"raw_secret_persisted\":false,",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        TRUST_COMMAND_SCHEMA,
        json_escape(&paths.root.to_string_lossy()),
        ledger.record_count(),
        values,
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
            "\"trust-init\",",
            "\"trust-key-bootstrap\",",
            "\"trust-key-register\",",
            "\"trust-key-revoke\",",
            "\"trust-policy-register\",",
            "\"trust-commit\",",
            "\"trust-status\",",
            "\"trust-list-keys\",",
            "\"trust-list-policies\",",
            "\"trust-list-authorizations\"",
            "],",
            "\"command_count\":10,",
            "\"signature_algorithm\":\"HMAC-SHA256\",",
            "\"asymmetric_signature\":false,",
            "\"raw_secret_persisted\":false,",
            "\"network_enabled\":false,",
            "\"automatic_repair_enabled\":false",
            "}}"
        ),
        TRUST_COMMAND_SCHEMA,
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
            "\"version\":\"{}\",",
            "\"signature_algorithm\":\"HMAC-SHA256\"",
            "}}"
        ),
        TRUST_COMMAND_SCHEMA,
        TRUST_AUTH_VERSION,
    ))
}

fn parse_evidence_file(path: &Path) -> Result<Vec<EvidenceRef>, CliError> {
    let text = fs::read_to_string(path).map_err(|error| {
        CliError::operation(format!(
            "cannot read evidence file {}: {error}",
            path.display(),
        ))
    })?;
    let mut values = Vec::new();
    let mut ids = BTreeSet::new();
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
        let digest = parse_digest(fields[2]).map_err(|message| {
            CliError::invalid(format!(
                "invalid evidence digest at line {}: {message}",
                index + 1,
            ))
        })?;
        values.push(EvidenceRef {
            evidence_id: fields[0].to_string(),
            provenance_id: fields[1].to_string(),
            evidence_digest: digest,
        });
    }
    if values.is_empty() {
        return Err(CliError::invalid(
            "evidence file must contain at least one row",
        ));
    }
    Ok(values)
}

fn parse_digest(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("expected 64 hexadecimal characters".to_string());
    }
    let mut output = [0u8; 32];
    for index in 0..32 {
        output[index] = u8::from_str_radix(
            &value[index * 2..index * 2 + 2],
            16,
        ).map_err(|_| "non-hexadecimal character".to_string())?;
    }
    if output == [0; 32] {
        return Err("zero digest is forbidden".to_string());
    }
    Ok(output)
}

fn key_event_json(
    command: &str,
    paths: &TrustPaths,
    event: &crate::KeyEvent,
    event_count: usize,
    active_key_count: usize,
) -> Result<String, CliError> {
    let roles = if event.target_role_mask == 0 {
        Vec::new()
    } else {
        role_names(event.target_role_mask)?
    };
    let role_values = roles.into_iter()
        .map(|value| format!("\"{value}\""))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"{}\",",
            "\"trust_root\":\"{}\",",
            "\"event\":\"{}\",",
            "\"sequence\":{},",
            "\"target_key_id\":\"{}\",",
            "\"target_fingerprint\":\"{}\",",
            "\"target_role_mask\":{},",
            "\"target_roles\":[{}],",
            "\"signer_key_id\":\"{}\",",
            "\"signer_fingerprint\":\"{}\",",
            "\"logical_timestamp\":{},",
            "\"nonce\":\"{}\",",
            "\"signature\":\"{}\",",
            "\"key_event_count\":{},",
            "\"active_key_count\":{},",
            "\"signature_algorithm\":\"HMAC-SHA256\",",
            "\"raw_secret_persisted\":false,",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        TRUST_COMMAND_SCHEMA,
        json_escape(command),
        json_escape(&paths.root.to_string_lossy()),
        event.kind.as_str(),
        event.sequence,
        json_escape(&event.target_key_id),
        hex(&event.target_fingerprint),
        event.target_role_mask,
        role_values,
        json_escape(&event.signer_key_id),
        hex(&event.signer_fingerprint),
        event.logical_timestamp,
        json_escape(&event.nonce),
        hex(&event.signature),
        event_count,
        active_key_count,
    ))
}

#[derive(Clone, Debug)]
struct PolicyView {
    policy_id: String,
    policy_version: String,
    authority: String,
    operation_mask: u16,
    min_evidence: u32,
    max_evidence: u32,
    verifier_id: String,
    unique_provenance: bool,
    policy_digest: [u8; 32],
}

fn parse_policy_views(path: &Path) -> Result<Vec<PolicyView>, CliError> {
    let data = fs::read(path).map_err(|error| {
        CliError::operation(format!(
            "cannot read policy registry {}: {error}",
            path.display(),
        ))
    })?;
    let mut offset = 0usize;
    let mut views = Vec::new();
    let mut head = [0u8; 32];
    while offset < data.len() {
        if data.len() - offset < 144 {
            return Err(CliError::operation(
                "truncated policy registry header",
            ));
        }
        let header = &data[offset..offset + 144];
        if &header[0..8] != b"UBPOL01\0" {
            return Err(CliError::operation(
                "policy registry magic mismatch",
            ));
        }
        let sequence = read_u64(header, 16)?;
        if sequence != views.len() as u64 + 1 {
            return Err(CliError::operation(
                "policy registry sequence mismatch",
            ));
        }
        let payload_len = read_u64(header, 24)? as usize;
        let previous = read_digest_at(header, 32)?;
        let payload_digest = read_digest_at(header, 64)?;
        let frame_digest = read_digest_at(header, 96)?;
        if previous != head {
            return Err(CliError::operation(
                "policy registry chain mismatch",
            ));
        }
        let end = offset + 144 + payload_len;
        if end > data.len() {
            return Err(CliError::operation(
                "truncated policy registry payload",
            ));
        }
        let payload = &data[offset + 144..end];
        if ultraballoondb_storage::sha256(payload) != payload_digest {
            return Err(CliError::operation(
                "policy registry payload digest mismatch",
            ));
        }
        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"UBPOLFR1");
        preimage.extend_from_slice(&sequence.to_le_bytes());
        preimage.extend_from_slice(&previous);
        preimage.extend_from_slice(&payload_digest);
        if ultraballoondb_storage::sha256(&preimage) != frame_digest {
            return Err(CliError::operation(
                "policy registry frame digest mismatch",
            ));
        }
        views.push(parse_policy_payload(payload)?);
        head = frame_digest;
        offset = end;
    }
    Ok(views)
}

fn parse_policy_payload(payload: &[u8]) -> Result<PolicyView, CliError> {
    if payload.len() < 40 || &payload[0..8] != b"UBPYP01\0" {
        return Err(CliError::operation(
            "policy payload header mismatch",
        ));
    }
    let authority = match payload[8] {
        1 => "EVIDENCE_POLICY",
        2 => "IMPORT",
        _ => {
            return Err(CliError::operation(
                "unknown policy authority",
            ))
        }
    };
    let unique_provenance = match payload[9] {
        0 => false,
        1 => true,
        _ => {
            return Err(CliError::operation(
                "invalid policy unique provenance flag",
            ))
        }
    };
    let operation_mask = read_u16_at(payload, 10)?;
    let min_evidence = read_u32_at(payload, 12)?;
    let max_evidence = read_u32_at(payload, 16)?;
    let policy_id_len = read_u32_at(payload, 20)? as usize;
    let version_len = read_u32_at(payload, 24)? as usize;
    let verifier_len = read_u32_at(payload, 28)? as usize;
    if read_u32_at(payload, 32)? != 0
        || read_u32_at(payload, 36)? != 0
    {
        return Err(CliError::operation(
            "policy reserved fields non-zero",
        ));
    }
    let mut cursor = 40usize;
    let policy_id = read_string_at(
        payload, &mut cursor, policy_id_len, "policy_id"
    )?;
    let policy_version = read_string_at(
        payload, &mut cursor, version_len, "policy_version"
    )?;
    let verifier_id = read_string_at(
        payload, &mut cursor, verifier_len, "verifier_id"
    )?;
    if cursor != payload.len() {
        return Err(CliError::operation(
            "policy payload trailing bytes",
        ));
    }
    let mut digest_preimage = Vec::new();
    digest_preimage.extend_from_slice(b"UBTRPOL1");
    digest_preimage.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    digest_preimage.extend_from_slice(payload);
    Ok(PolicyView {
        policy_id,
        policy_version,
        authority: authority.to_string(),
        operation_mask,
        min_evidence,
        max_evidence,
        verifier_id,
        unique_provenance,
        policy_digest: ultraballoondb_storage::sha256(
            &digest_preimage
        ),
    })
}

fn read_u16_at(bytes: &[u8], offset: usize) -> Result<u16, CliError> {
    let value = bytes.get(offset..offset + 2).ok_or_else(|| {
        CliError::operation("truncated u16")
    })?;
    Ok(u16::from_le_bytes(value.try_into().expect("checked")))
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32, CliError> {
    let value = bytes.get(offset..offset + 4).ok_or_else(|| {
        CliError::operation("truncated u32")
    })?;
    Ok(u32::from_le_bytes(value.try_into().expect("checked")))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, CliError> {
    let value = bytes.get(offset..offset + 8).ok_or_else(|| {
        CliError::operation("truncated u64")
    })?;
    Ok(u64::from_le_bytes(value.try_into().expect("checked")))
}

fn read_digest_at(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; 32], CliError> {
    let value = bytes.get(offset..offset + 32).ok_or_else(|| {
        CliError::operation("truncated digest")
    })?;
    Ok(value.try_into().expect("checked"))
}

fn read_string_at(
    bytes: &[u8],
    cursor: &mut usize,
    length: usize,
    name: &str,
) -> Result<String, CliError> {
    let end = cursor.checked_add(length).ok_or_else(|| {
        CliError::operation("string length overflow")
    })?;
    let value = bytes.get(*cursor..end).ok_or_else(|| {
        CliError::operation(format!("truncated {name}"))
    })?;
    *cursor = end;
    String::from_utf8(value.to_vec()).map_err(|_| {
        CliError::operation(format!("{name} is not UTF-8"))
    })
}

fn optional_u64_json(value: Option<u64>) -> String {
    value.map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
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
                write!(&mut output, "\\u{:04X}", character as u32)
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
    fn evidence_digest_parser() {
        let value = "11".repeat(32);
        assert_eq!(parse_digest(&value).unwrap(), [0x11; 32]);
        assert!(parse_digest("00").is_err());
    }

    #[test]
    fn help_has_ten_commands() {
        let output = run_cli(vec![
            "ultraballoondb-trust".to_string(),
            "help".to_string(),
        ]).unwrap();
        assert!(output.contains("\"command_count\":10"));
    }
}
