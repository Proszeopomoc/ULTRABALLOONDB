use std::collections::BTreeMap;
use std::fmt;

use crate::{
    delete_persisted_key, hex, init_asymmetric_root,
    parse_hex_digest, provider_key_exists,
    AsymmetricAuthorizationLedger,
    AsymmetricError, AsymmetricKeyRegistry, AsymmetricPaths,
    COMMAND_SCHEMA, SOFTWARE_KSP, VERSION,
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
            code: "ASYMMETRIC_OPERATION_ERROR",
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
                "\"provider\":\"{}\",",
                "\"hardware_bound\":false,",
                "\"network_enabled\":false,",
                "\"automatic_repair_enabled\":false,",
                "\"active_runtime_changed\":false",
                "}}"
            ),
            COMMAND_SCHEMA,
            self.code,
            json_escape(&self.message),
            SOFTWARE_KSP,
        )
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for CliError {}

impl From<AsymmetricError> for CliError {
    fn from(value: AsymmetricError) -> Self {
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
        "asym-init" => command_init(parsed.flags),
        "asym-key-create" => command_key_create(parsed.flags),
        "asym-key-rotate" => command_key_rotate(parsed.flags),
        "asym-key-revoke" => command_key_revoke(parsed.flags),
        "asym-authorize" => command_authorize(parsed.flags),
        "asym-authorization-verify" => {
            command_authorization_verify(parsed.flags)
        }
        "asym-key-delete-provider" => {
            command_key_delete_provider(parsed.flags)
        }
        "asym-status" => command_status(parsed.flags),
        "help" => command_help(parsed.flags),
        "version" => command_version(parsed.flags),
        command => Err(CliError::invalid(format!(
            "unknown asymmetric command: {command}",
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
            "missing command; use `ultraballoondb-trust-asymmetric help`",
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

fn parse_u16(name: &str, value: &str) -> Result<u16, CliError> {
    value.parse::<u16>().map_err(|_| {
        CliError::invalid(format!(
            "--{name} must be an unsigned 16-bit integer",
        ))
    })
}

fn parse_u8(name: &str, value: &str) -> Result<u8, CliError> {
    value.parse::<u8>().map_err(|_| {
        CliError::invalid(format!(
            "--{name} must be an unsigned 8-bit integer",
        ))
    })
}

fn paths(
    flags: &mut BTreeMap<String, String>,
) -> Result<AsymmetricPaths, CliError> {
    Ok(AsymmetricPaths::from_root(
        required(flags, "root")?,
    ))
}

fn command_init(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let root = required(&mut flags, "root")?;
    reject_unknown(&flags)?;
    let receipt = init_asymmetric_root(&root)?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"asym-init\",",
            "\"root\":\"{}\",",
            "\"changed\":{},",
            "\"key_registry_changed\":{},",
            "\"authorization_ledger_changed\":{},",
            "\"key_registry_path\":\"{}\",",
            "\"authorization_ledger_path\":\"{}\",",
            "\"provider\":\"{}\",",
            "\"hardware_bound\":false,",
            "\"private_key_persisted_by_ultraballoondb\":false,",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        COMMAND_SCHEMA,
        json_escape(&root),
        json_bool(receipt.changed),
        json_bool(receipt.key_registry_changed),
        json_bool(receipt.authorization_ledger_changed),
        json_escape(
            &receipt.key_registry_path.to_string_lossy(),
        ),
        json_escape(
            &receipt.authorization_ledger_path
                .to_string_lossy(),
        ),
        SOFTWARE_KSP,
    ))
}

fn command_key_create(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let paths = paths(&mut flags)?;
    let key_id = required(&mut flags, "key-id")?;
    let role_mask = parse_u16(
        "role-mask",
        &required(&mut flags, "role-mask")?,
    )?;
    let provider_key_name = required(
        &mut flags,
        "provider-key-name",
    )?;
    let logical_timestamp = parse_u64(
        "logical-timestamp",
        &required(&mut flags, "logical-timestamp")?,
    )?;
    let nonce = required(&mut flags, "nonce")?;
    reject_unknown(&flags)?;

    let mut registry = AsymmetricKeyRegistry::open_strict(
        &paths.key_registry,
    )?;
    let receipt = registry.enroll_new_provider_key(
        &key_id,
        role_mask,
        &provider_key_name,
        logical_timestamp,
        &nonce,
    )?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"asym-key-create\",",
            "\"root\":\"{}\",",
            "\"key_id\":\"{}\",",
            "\"provider\":\"{}\",",
            "\"provider_key_name\":\"{}\",",
            "\"role_mask\":{},",
            "\"sequence\":{},",
            "\"generation\":{},",
            "\"public_key_digest\":\"{}\",",
            "\"frame_digest\":\"{}\",",
            "\"private_export_rejected\":{},",
            "\"hardware_bound\":false,",
            "\"private_key_persisted_by_ultraballoondb\":false",
            "}}"
        ),
        COMMAND_SCHEMA,
        json_escape(&paths.root.to_string_lossy()),
        json_escape(&key_id),
        SOFTWARE_KSP,
        json_escape(&provider_key_name),
        role_mask,
        receipt.sequence,
        receipt.generation,
        hex(&receipt.public_key_digest),
        hex(&receipt.frame_digest),
        json_bool(receipt.private_export_rejected),
    ))
}

fn command_key_rotate(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let paths = paths(&mut flags)?;
    let key_id = required(&mut flags, "key-id")?;
    let old_provider_key_name = required(
        &mut flags,
        "old-provider-key-name",
    )?;
    let new_provider_key_name = required(
        &mut flags,
        "new-provider-key-name",
    )?;
    let logical_timestamp = parse_u64(
        "logical-timestamp",
        &required(&mut flags, "logical-timestamp")?,
    )?;
    let nonce = required(&mut flags, "nonce")?;
    reject_unknown(&flags)?;

    let mut registry = AsymmetricKeyRegistry::open_strict(
        &paths.key_registry,
    )?;
    let receipt = registry.rotate_to_new_provider_key(
        &key_id,
        &old_provider_key_name,
        &new_provider_key_name,
        logical_timestamp,
        &nonce,
    )?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"asym-key-rotate\",",
            "\"root\":\"{}\",",
            "\"key_id\":\"{}\",",
            "\"old_provider_key_name\":\"{}\",",
            "\"new_provider_key_name\":\"{}\",",
            "\"sequence\":{},",
            "\"generation\":{},",
            "\"public_key_digest\":\"{}\",",
            "\"frame_digest\":\"{}\",",
            "\"private_export_rejected\":{},",
            "\"dual_proof_rotation\":true,",
            "\"role_mask_preserved\":true",
            "}}"
        ),
        COMMAND_SCHEMA,
        json_escape(&paths.root.to_string_lossy()),
        json_escape(&key_id),
        json_escape(&old_provider_key_name),
        json_escape(&new_provider_key_name),
        receipt.sequence,
        receipt.generation,
        hex(&receipt.public_key_digest),
        hex(&receipt.frame_digest),
        json_bool(receipt.private_export_rejected),
    ))
}

fn command_key_revoke(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let paths = paths(&mut flags)?;
    let key_id = required(&mut flags, "key-id")?;
    let provider_key_name = required(
        &mut flags,
        "provider-key-name",
    )?;
    let logical_timestamp = parse_u64(
        "logical-timestamp",
        &required(&mut flags, "logical-timestamp")?,
    )?;
    let nonce = required(&mut flags, "nonce")?;
    reject_unknown(&flags)?;

    let mut registry = AsymmetricKeyRegistry::open_strict(
        &paths.key_registry,
    )?;
    let receipt = registry.revoke(
        &key_id,
        &provider_key_name,
        logical_timestamp,
        &nonce,
    )?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"asym-key-revoke\",",
            "\"root\":\"{}\",",
            "\"key_id\":\"{}\",",
            "\"provider_key_name\":\"{}\",",
            "\"sequence\":{},",
            "\"generation\":{},",
            "\"public_key_digest\":\"{}\",",
            "\"frame_digest\":\"{}\",",
            "\"active\":false",
            "}}"
        ),
        COMMAND_SCHEMA,
        json_escape(&paths.root.to_string_lossy()),
        json_escape(&key_id),
        json_escape(&provider_key_name),
        receipt.sequence,
        receipt.generation,
        hex(&receipt.public_key_digest),
        hex(&receipt.frame_digest),
    ))
}

fn command_authorize(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let paths = paths(&mut flags)?;
    let domain_code = parse_u8(
        "domain-code",
        &required(&mut flags, "domain-code")?,
    )?;
    let required_role_mask = parse_u16(
        "required-role-mask",
        &required(&mut flags, "required-role-mask")?,
    )?;
    let subject_digest = parse_hex_digest(
        &required(&mut flags, "subject-digest")?,
    )?;
    let key_id = required(&mut flags, "key-id")?;
    let provider_key_name = required(
        &mut flags,
        "provider-key-name",
    )?;
    let logical_timestamp = parse_u64(
        "logical-timestamp",
        &required(&mut flags, "logical-timestamp")?,
    )?;
    let nonce = required(&mut flags, "nonce")?;
    reject_unknown(&flags)?;

    let registry = AsymmetricKeyRegistry::open_strict(
        &paths.key_registry,
    )?;
    let mut ledger =
        AsymmetricAuthorizationLedger::open_strict(
            &paths.authorization_ledger,
            &registry,
        )?;
    let receipt = ledger.authorize(
        &registry,
        domain_code,
        required_role_mask,
        subject_digest,
        &key_id,
        &provider_key_name,
        logical_timestamp,
        &nonce,
    )?;
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"asym-authorize\",",
            "\"root\":\"{}\",",
            "\"key_id\":\"{}\",",
            "\"domain_code\":{},",
            "\"required_role_mask\":{},",
            "\"subject_digest\":\"{}\",",
            "\"sequence\":{},",
            "\"authorization_digest\":\"{}\",",
            "\"authorization_event_id\":\"{}\",",
            "\"frame_digest\":\"{}\",",
            "\"signature_algorithm\":\"ECDSA_P256_SHA256\"",
            "}}"
        ),
        COMMAND_SCHEMA,
        json_escape(&paths.root.to_string_lossy()),
        json_escape(&key_id),
        domain_code,
        required_role_mask,
        hex(&subject_digest),
        receipt.sequence,
        hex(&receipt.authorization_digest),
        hex(&receipt.authorization_event_id),
        hex(&receipt.frame_digest),
    ))
}

fn command_authorization_verify(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let paths = paths(&mut flags)?;
    let sequence = parse_u64(
        "sequence",
        &required(&mut flags, "sequence")?,
    )?;
    reject_unknown(&flags)?;
    let registry = AsymmetricKeyRegistry::open_strict(
        &paths.key_registry,
    )?;
    let ledger = AsymmetricAuthorizationLedger::open_strict(
        &paths.authorization_ledger,
        &registry,
    )?;
    let verified = ledger.verify_sequence(
        sequence,
        &registry,
    )?;
    if !verified {
        return Err(CliError::semantic(
            "SIGNATURE_VERIFICATION_FAILED",
            "asymmetric authorization signature is invalid",
        ));
    }
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"asym-authorization-verify\",",
            "\"root\":\"{}\",",
            "\"sequence\":{},",
            "\"verified\":true",
            "}}"
        ),
        COMMAND_SCHEMA,
        json_escape(&paths.root.to_string_lossy()),
        sequence,
    ))
}

fn command_key_delete_provider(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let paths = paths(&mut flags)?;
    let provider_key_name = required(
        &mut flags,
        "provider-key-name",
    )?;
    reject_unknown(&flags)?;
    let registry = AsymmetricKeyRegistry::open_strict(
        &paths.key_registry,
    )?;
    if registry.states().values().any(|state| {
        state.active
            && state.provider_name == SOFTWARE_KSP
            && state.provider_key_name == provider_key_name
    }) {
        return Err(CliError::semantic(
            "ACTIVE_PROVIDER_KEY_DELETE_BLOCKED",
            "cannot delete a provider key used by an active registry state",
        ));
    }
    let existed_before = provider_key_exists(
        SOFTWARE_KSP,
        &provider_key_name,
    );
    if !existed_before {
        return Err(CliError::semantic(
            "PROVIDER_KEY_NOT_FOUND",
            format!(
                "provider key does not exist: {provider_key_name}",
            ),
        ));
    }
    delete_persisted_key(
        SOFTWARE_KSP,
        &provider_key_name,
    )?;
    let exists_after = provider_key_exists(
        SOFTWARE_KSP,
        &provider_key_name,
    );
    if exists_after {
        return Err(CliError::operation(
            "provider key still exists after deletion",
        ));
    }
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"asym-key-delete-provider\",",
            "\"root\":\"{}\",",
            "\"provider\":\"{}\",",
            "\"provider_key_name\":\"{}\",",
            "\"existed_before\":true,",
            "\"exists_after\":false,",
            "\"active_provider_key_delete_blocked\":true",
            "}}"
        ),
        COMMAND_SCHEMA,
        json_escape(&paths.root.to_string_lossy()),
        SOFTWARE_KSP,
        json_escape(&provider_key_name),
    ))
}

fn command_status(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let paths = paths(&mut flags)?;
    reject_unknown(&flags)?;
    let registry = AsymmetricKeyRegistry::open_strict(
        &paths.key_registry,
    )?;
    let ledger = AsymmetricAuthorizationLedger::open_strict(
        &paths.authorization_ledger,
        &registry,
    )?;
    let states = registry.states().values()
        .map(|state| {
            format!(
                concat!(
                    "{{",
                    "\"key_id\":\"{}\",",
                    "\"provider_key_name\":\"{}\",",
                    "\"role_mask\":{},",
                    "\"generation\":{},",
                    "\"public_key_digest\":\"{}\",",
                    "\"active\":{}",
                    "}}"
                ),
                json_escape(&state.key_id),
                json_escape(&state.provider_key_name),
                state.role_mask,
                state.generation,
                hex(&state.public_key_digest),
                json_bool(state.active),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"asym-status\",",
            "\"root\":\"{}\",",
            "\"provider\":\"{}\",",
            "\"hardware_bound\":false,",
            "\"key_event_count\":{},",
            "\"active_key_count\":{},",
            "\"authorization_count\":{},",
            "\"key_registry_head\":\"{}\",",
            "\"authorization_ledger_head\":\"{}\",",
            "\"keys\":[{}],",
            "\"private_key_persisted_by_ultraballoondb\":false,",
            "\"network_enabled\":false,",
            "\"automatic_repair_enabled\":false",
            "}}"
        ),
        COMMAND_SCHEMA,
        json_escape(&paths.root.to_string_lossy()),
        SOFTWARE_KSP,
        registry.event_count(),
        registry.active_key_count(),
        ledger.event_count(),
        hex(&registry.head_digest()),
        hex(&ledger.head_digest()),
        states,
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
            "\"asym-init\",",
            "\"asym-key-create\",",
            "\"asym-key-rotate\",",
            "\"asym-key-revoke\",",
            "\"asym-authorize\",",
            "\"asym-authorization-verify\",",
            "\"asym-key-delete-provider\",",
            "\"asym-status\",",
            "\"help\",",
            "\"version\"",
            "],",
            "\"command_count\":10,",
            "\"provider\":\"{}\",",
            "\"algorithm\":\"ECDSA_P256\",",
            "\"hash\":\"SHA256\",",
            "\"hardware_bound\":false,",
            "\"tpm_required\":false,",
            "\"private_key_persisted_by_ultraballoondb\":false,",
            "\"network_enabled\":false,",
            "\"automatic_repair_enabled\":false",
            "}}"
        ),
        COMMAND_SCHEMA,
        SOFTWARE_KSP,
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
        COMMAND_SCHEMA,
        VERSION,
    ))
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
    fn help_has_ten_commands() {
        let output = run_cli(vec![
            "ultraballoondb-trust-asymmetric".to_string(),
            "help".to_string(),
        ]).unwrap();
        assert!(output.contains("\"command_count\":10"));
        assert!(output.contains("\"hardware_bound\":false"));
    }
}
