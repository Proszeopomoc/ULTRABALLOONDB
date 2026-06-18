use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use ultraballoondb_lifecycle::{
    BatchLimits, DatabaseEdge, DatabaseRecord, DurableDatabase,
    TransactionCore, TransactionId,
};
use ultraballoondb_storage::{hex_digest, sha256};

pub const COMMAND_SCHEMA: &str = "ultraballoondb.command.v1";
pub const COMMAND_SURFACE_VERSION: &str =
    "V00R3B6_NATIVE_EDITION_A_OFFLINE_DATABASE_COMMAND_SURFACE_R05";
pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_INVALID_ARGUMENT: i32 = 2;
pub const EXIT_DATABASE_ERROR: i32 = 3;
pub const EXIT_SEMANTIC_CONDITION: i32 = 4;
pub const MAX_PAYLOAD_BYTES: u64 = 256 * 1024 * 1024;

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

    fn database(message: impl Into<String>) -> Self {
        Self {
            exit_code: EXIT_DATABASE_ERROR,
            code: "DATABASE_ERROR",
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
                "}}",
                "}}"
            ),
            COMMAND_SCHEMA,
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

#[derive(Clone, Debug)]
struct ParsedArgs {
    command: String,
    flags: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
struct MutationReceipt {
    transaction_id: TransactionId,
    generation: u64,
    segment_sequence: u64,
    commit_lsn: u64,
    checkpoint_lsn: u64,
    state_sha256: [u8; 32],
    record_count: u64,
    edge_count: u64,
}

pub fn main_entry<I>(arguments: I) -> i32
where
    I: IntoIterator<Item = String>,
{
    match run(arguments) {
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

pub fn run<I>(arguments: I) -> Result<String, CliError>
where
    I: IntoIterator<Item = String>,
{
    let parsed = parse_arguments(arguments)?;
    match parsed.command.as_str() {
        "create" => command_create(parsed.flags),
        "status" => command_status(parsed.flags),
        "verify" => command_verify(parsed.flags),
        "put-record" => command_put_record(parsed.flags),
        "get-record" => command_get_record(parsed.flags),
        "list-records" => command_list_records(parsed.flags),
        "delete-record" => command_delete_record(parsed.flags),
        "put-edge" => command_put_edge(parsed.flags),
        "list-edges" => command_list_edges(parsed.flags),
        "delete-edge" => command_delete_edge(parsed.flags),
        "checkpoint" => command_checkpoint(parsed.flags),
        "help" => command_help(parsed.flags),
        "version" => command_version(parsed.flags),
        command => Err(CliError::invalid(format!(
            "unknown command: {command}"
        ))),
    }
}

fn parse_arguments<I>(arguments: I) -> Result<ParsedArgs, CliError>
where
    I: IntoIterator<Item = String>,
{
    let mut values = arguments.into_iter();
    let _program = values.next();
    let command = values
        .next()
        .ok_or_else(|| CliError::invalid(
            "missing command; use `ultraballoondb help`",
        ))?;
    let remaining: Vec<String> = values.collect();
    if remaining.len() % 2 != 0 {
        return Err(CliError::invalid(
            "flags must be provided as --name value pairs",
        ));
    }
    let mut flags = BTreeMap::new();
    let mut index = 0usize;
    while index < remaining.len() {
        let key = &remaining[index];
        let value = &remaining[index + 1];
        if !key.starts_with("--") || key.len() <= 2 {
            return Err(CliError::invalid(format!(
                "invalid flag name: {key}"
            )));
        }
        if flags
            .insert(key[2..].to_string(), value.clone())
            .is_some()
        {
            return Err(CliError::invalid(format!(
                "duplicate flag: {key}"
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
    flags
        .remove(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::invalid(format!(
            "missing required flag --{name}"
        )))
}

fn optional(
    flags: &mut BTreeMap<String, String>,
    name: &str,
) -> Option<String> {
    flags.remove(name)
}

fn reject_unknown(
    flags: &BTreeMap<String, String>,
) -> Result<(), CliError> {
    if let Some(name) = flags.keys().next() {
        return Err(CliError::invalid(format!(
            "unknown flag --{name}"
        )));
    }
    Ok(())
}

fn db_path(
    flags: &mut BTreeMap<String, String>,
) -> Result<PathBuf, CliError> {
    Ok(PathBuf::from(required(flags, "db")?))
}

fn parse_u64_value(name: &str, value: &str) -> Result<u64, CliError> {
    value.parse::<u64>().map_err(|_| {
        CliError::invalid(format!(
            "--{name} must be an unsigned 64-bit integer"
        ))
    })
}

fn parse_u32_value(name: &str, value: &str) -> Result<u32, CliError> {
    value.parse::<u32>().map_err(|_| {
        CliError::invalid(format!(
            "--{name} must be an unsigned 32-bit integer"
        ))
    })
}

fn parse_weight_million(value: &str) -> Result<i64, CliError> {
    let parsed = value.parse::<i64>().map_err(|_| {
        CliError::invalid(
            "--weight-million must be an integer",
        )
    })?;
    if !(0..=1_000_000).contains(&parsed) {
        return Err(CliError::invalid(
            "--weight-million must be within 0..1000000",
        ));
    }
    Ok(parsed)
}

fn weight_from_million(value: i64) -> f64 {
    value as f64 / 1_000_000.0
}

fn open_database(path: &Path) -> Result<DurableDatabase, CliError> {
    DurableDatabase::open(path, false)
        .map_err(|error| CliError::database(error.to_string()))
}

fn command_create(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let path = db_path(&mut flags)?;
    reject_unknown(&flags)?;
    if path.exists() {
        return Err(CliError::semantic(
            "ALREADY_EXISTS",
            format!("database path already exists: {}", path.display()),
        ));
    }
    let mut database = DurableDatabase::create(&path)
        .map_err(|error| CliError::database(error.to_string()))?;
    let checkpoint = database
        .checkpoint(1)
        .map_err(|error| CliError::database(error.to_string()))?;
    let state_sha256 = database.state_sha256();
    let (record_count, edge_count) = database.state_counts();
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"create\",",
            "\"db\":\"{}\",",
            "\"record_count\":{},",
            "\"edge_count\":{},",
            "\"state_sha256\":\"{}\",",
            "\"checkpoint_generation\":{},",
            "\"checkpoint_lsn\":{},",
            "\"head_published\":{},",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        COMMAND_SCHEMA,
        json_escape(&path.to_string_lossy()),
        record_count,
        edge_count,
        hex_digest(&state_sha256),
        checkpoint.generation,
        checkpoint.checkpoint_lsn,
        json_bool(checkpoint.head_published),
    ))
}

fn command_status(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let path = db_path(&mut flags)?;
    reject_unknown(&flags)?;
    let database = open_database(&path)?;
    Ok(status_json("status", &path, &database, None))
}

fn command_verify(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let path = db_path(&mut flags)?;
    reject_unknown(&flags)?;
    let first = open_database(&path)?;
    let first_hash = first.state_sha256();
    let first_counts = first.state_counts();
    let first_generation = first.checkpoint_generation();
    let first_maximum_lsn =
        first.recovery_receipt().maximum_valid_wal_lsn;
    drop(first);

    let second = open_database(&path)?;
    let deterministic = second.state_sha256() == first_hash
        && second.state_counts() == first_counts
        && second.checkpoint_generation() == first_generation
        && second.recovery_receipt().maximum_valid_wal_lsn
            == first_maximum_lsn
        && second.recovery_receipt().repaired_trailing_bytes == 0;
    if !deterministic {
        return Err(CliError::database(
            "database restart verification is not deterministic",
        ));
    }
    Ok(status_json(
        "verify",
        &path,
        &second,
        Some(true),
    ))
}

fn command_put_record(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let path = db_path(&mut flags)?;
    let record_id = required(&mut flags, "record-id")?;
    let node_id = parse_u64_value(
        "node-id",
        &required(&mut flags, "node-id")?,
    )?;
    let payload_file = optional(&mut flags, "payload-file");
    let payload_utf8 = optional(&mut flags, "payload-utf8");
    reject_unknown(&flags)?;

    let payload = match (payload_file, payload_utf8) {
        (Some(path_value), None) => fs::read(&path_value).map_err(
            |error| CliError::database(format!(
                "cannot read payload file {path_value}: {error}"
            )),
        )?,
        (None, Some(value)) => value.into_bytes(),
        (Some(_), Some(_)) => {
            return Err(CliError::invalid(
                "provide exactly one of --payload-file or --payload-utf8",
            ))
        }
        (None, None) => {
            return Err(CliError::invalid(
                "provide exactly one of --payload-file or --payload-utf8",
            ))
        }
    };
    if payload.len() as u64 > MAX_PAYLOAD_BYTES {
        return Err(CliError::invalid(format!(
            "payload exceeds maximum {} bytes",
            MAX_PAYLOAD_BYTES
        )));
    }

    let database = open_database(&path)?;
    if let Some(existing) = database
        .record(&record_id)
        .map_err(|error| CliError::database(error.to_string()))?
    {
        if existing.node_id == node_id && existing.payload == payload {
            return Ok(no_change_json(
                "put-record",
                &path,
                &database,
                "record already has identical value",
            ));
        }
    }
    drop(database);

    let material = record_material(
        b"put-record",
        &record_id,
        node_id,
        &payload,
    );
    let logical_id = logical_id(b"record", record_id.as_bytes());
    let receipt = mutate(
        &path,
        &material,
        |core| {
            core.put_record(
                logical_id,
                &record_id,
                node_id,
                &payload,
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
        },
    )?;
    Ok(mutation_json(
        "put-record",
        &path,
        true,
        &receipt,
        Some(format!(
            concat!(
                "\"record_id\":\"{}\",",
                "\"node_id\":{},",
                "\"payload_bytes\":{},",
                "\"payload_sha256\":\"{}\""
            ),
            json_escape(&record_id),
            node_id,
            payload.len(),
            hex_digest(&sha256(&payload)),
        )),
    ))
}

fn command_get_record(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let path = db_path(&mut flags)?;
    let record_id = required(&mut flags, "record-id")?;
    reject_unknown(&flags)?;
    let database = open_database(&path)?;
    let record = database
        .record(&record_id)
        .map_err(|error| CliError::database(error.to_string()))?
        .ok_or_else(|| CliError::semantic(
            "NOT_FOUND",
            format!("record not found: {record_id}"),
        ))?;
    Ok(record_json("get-record", &path, &record, true))
}

fn command_list_records(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let path = db_path(&mut flags)?;
    reject_unknown(&flags)?;
    let database = open_database(&path)?;
    let records = database
        .records()
        .map_err(|error| CliError::database(error.to_string()))?;
    let values = records
        .iter()
        .map(record_summary_json)
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"list-records\",",
            "\"db\":\"{}\",",
            "\"record_count\":{},",
            "\"records\":[{}],",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        COMMAND_SCHEMA,
        json_escape(&path.to_string_lossy()),
        records.len(),
        values,
    ))
}

fn command_delete_record(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let path = db_path(&mut flags)?;
    let record_id = required(&mut flags, "record-id")?;
    reject_unknown(&flags)?;
    let database = open_database(&path)?;
    if database
        .record(&record_id)
        .map_err(|error| CliError::database(error.to_string()))?
        .is_none()
    {
        return Ok(no_change_json(
            "delete-record",
            &path,
            &database,
            "record is already absent",
        ));
    }
    drop(database);

    let material = record_material(
        b"delete-record",
        &record_id,
        0,
        &[],
    );
    let logical_id = logical_id(
        b"record-tombstone",
        record_id.as_bytes(),
    );
    let receipt = mutate(
        &path,
        &material,
        |core| {
            core.delete_record(logical_id, &record_id)
                .map(|_| ())
                .map_err(|error| error.to_string())
        },
    )?;
    Ok(mutation_json(
        "delete-record",
        &path,
        true,
        &receipt,
        Some(format!(
            "\"record_id\":\"{}\"",
            json_escape(&record_id),
        )),
    ))
}

fn command_put_edge(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let path = db_path(&mut flags)?;
    let src = parse_u64_value(
        "src",
        &required(&mut flags, "src")?,
    )?;
    let dst = parse_u64_value(
        "dst",
        &required(&mut flags, "dst")?,
    )?;
    let edge_type = parse_u32_value(
        "edge-type",
        &required(&mut flags, "edge-type")?,
    )?;
    let weight_million = parse_weight_million(
        &required(&mut flags, "weight-million")?,
    )?;
    reject_unknown(&flags)?;
    let weight = weight_from_million(weight_million);

    let database = open_database(&path)?;
    if database
        .edge(src, dst, edge_type, weight)
        .map_err(|error| CliError::database(error.to_string()))?
        .is_some()
    {
        return Ok(no_change_json(
            "put-edge",
            &path,
            &database,
            "edge already exists",
        ));
    }
    drop(database);

    let material = edge_material(
        b"put-edge",
        src,
        dst,
        edge_type,
        weight_million,
    );
    let logical_id = logical_id(b"edge", &material);
    let receipt = mutate(
        &path,
        &material,
        |core| {
            core.put_edge(
                logical_id,
                src,
                dst,
                edge_type,
                weight,
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
        },
    )?;
    Ok(mutation_json(
        "put-edge",
        &path,
        true,
        &receipt,
        Some(edge_fields_json(
            src,
            dst,
            edge_type,
            weight_million,
        )),
    ))
}

fn command_list_edges(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let path = db_path(&mut flags)?;
    reject_unknown(&flags)?;
    let database = open_database(&path)?;
    let edges = database
        .edges()
        .map_err(|error| CliError::database(error.to_string()))?;
    let values = edges
        .iter()
        .map(edge_json)
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"list-edges\",",
            "\"db\":\"{}\",",
            "\"edge_count\":{},",
            "\"edges\":[{}],",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        COMMAND_SCHEMA,
        json_escape(&path.to_string_lossy()),
        edges.len(),
        values,
    ))
}

fn command_delete_edge(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let path = db_path(&mut flags)?;
    let src = parse_u64_value(
        "src",
        &required(&mut flags, "src")?,
    )?;
    let dst = parse_u64_value(
        "dst",
        &required(&mut flags, "dst")?,
    )?;
    let edge_type = parse_u32_value(
        "edge-type",
        &required(&mut flags, "edge-type")?,
    )?;
    let weight_million = parse_weight_million(
        &required(&mut flags, "weight-million")?,
    )?;
    reject_unknown(&flags)?;
    let weight = weight_from_million(weight_million);

    let database = open_database(&path)?;
    if database
        .edge(src, dst, edge_type, weight)
        .map_err(|error| CliError::database(error.to_string()))?
        .is_none()
    {
        return Ok(no_change_json(
            "delete-edge",
            &path,
            &database,
            "edge is already absent",
        ));
    }
    drop(database);

    let material = edge_material(
        b"delete-edge",
        src,
        dst,
        edge_type,
        weight_million,
    );
    let logical_id = logical_id(b"edge-tombstone", &material);
    let receipt = mutate(
        &path,
        &material,
        |core| {
            core.delete_edge(
                logical_id,
                src,
                dst,
                edge_type,
                weight,
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
        },
    )?;
    Ok(mutation_json(
        "delete-edge",
        &path,
        true,
        &receipt,
        Some(edge_fields_json(
            src,
            dst,
            edge_type,
            weight_million,
        )),
    ))
}

fn command_checkpoint(
    mut flags: BTreeMap<String, String>,
) -> Result<String, CliError> {
    let path = db_path(&mut flags)?;
    reject_unknown(&flags)?;
    let mut database = open_database(&path)?;
    let generation = database
        .next_generation()
        .map_err(|error| CliError::database(error.to_string()))?;
    let checkpoint = database
        .checkpoint(generation)
        .map_err(|error| CliError::database(error.to_string()))?;
    let state_sha256 = database.state_sha256();
    let (record_count, edge_count) = database.state_counts();
    Ok(format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"checkpoint\",",
            "\"db\":\"{}\",",
            "\"changed\":false,",
            "\"record_count\":{},",
            "\"edge_count\":{},",
            "\"state_sha256\":\"{}\",",
            "\"checkpoint_generation\":{},",
            "\"checkpoint_lsn\":{},",
            "\"head_published\":{},",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        COMMAND_SCHEMA,
        json_escape(&path.to_string_lossy()),
        record_count,
        edge_count,
        hex_digest(&state_sha256),
        checkpoint.generation,
        checkpoint.checkpoint_lsn,
        json_bool(checkpoint.head_published),
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
            "\"create\",\"status\",\"verify\",",
            "\"put-record\",\"get-record\",\"list-records\",",
            "\"delete-record\",\"put-edge\",\"list-edges\",",
            "\"delete-edge\",\"checkpoint\",\"help\",\"version\"",
            "],",
            "\"network_enabled\":false,",
            "\"automatic_repair_enabled\":false",
            "}}"
        ),
        COMMAND_SCHEMA,
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
        COMMAND_SURFACE_VERSION,
    ))
}

fn mutate<F>(
    path: &Path,
    command_material: &[u8],
    operation: F,
) -> Result<MutationReceipt, CliError>
where
    F: FnOnce(&mut TransactionCore) -> Result<(), String>,
{
    let mut database = open_database(path)?;
    let generation = database
        .next_generation()
        .map_err(|error| CliError::database(error.to_string()))?;
    let segment_sequence = database
        .next_segment_sequence()
        .map_err(|error| CliError::database(error.to_string()))?;
    let transaction_id = derive_transaction_id(
        database.state_sha256(),
        generation,
        segment_sequence,
        command_material,
    );
    let mut core = TransactionCore::new(BatchLimits::default());
    core.begin(transaction_id)
        .map_err(|error| CliError::database(error.to_string()))?;
    operation(&mut core)
        .map_err(|error| CliError::database(error))?;
    core.prepare()
        .map_err(|error| CliError::database(error.to_string()))?;
    let commit = core
        .commit_durable(
            &mut database,
            generation,
            segment_sequence,
        )
        .map_err(|error| CliError::database(error.to_string()))?;
    core.release_terminal(transaction_id)
        .map_err(|error| CliError::database(error.to_string()))?;
    let checkpoint = database
        .checkpoint(generation)
        .map_err(|error| CliError::database(error.to_string()))?;
    if commit.state_sha256 != checkpoint.state_sha256
        || !commit.durable_commit
        || !commit.wal_recorded
        || !commit.wal_fsynced
        || !checkpoint.head_published
        || !checkpoint.wal_checkpoint_recorded
    {
        return Err(CliError::database(
            "mutation receipt is incomplete or inconsistent",
        ));
    }
    let (record_count, edge_count) = database.state_counts();
    Ok(MutationReceipt {
        transaction_id,
        generation,
        segment_sequence,
        commit_lsn: commit.commit_lsn,
        checkpoint_lsn: checkpoint.checkpoint_lsn,
        state_sha256: checkpoint.state_sha256,
        record_count,
        edge_count,
    })
}

fn status_json(
    command: &str,
    path: &Path,
    database: &DurableDatabase,
    restart_deterministic: Option<bool>,
) -> String {
    let recovery = database.recovery_receipt();
    let (record_count, edge_count) = database.state_counts();
    let optional = restart_deterministic
        .map(|value| format!(
            ",\"restart_deterministic\":{}",
            json_bool(value),
        ))
        .unwrap_or_default();
    format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"{}\",",
            "\"db\":\"{}\",",
            "\"record_count\":{},",
            "\"edge_count\":{},",
            "\"committed_transaction_count\":{},",
            "\"state_sha256\":\"{}\",",
            "\"checkpoint_generation\":{},",
            "\"checkpoint_lsn\":{},",
            "\"maximum_valid_wal_lsn\":{},",
            "\"replayed_transaction_count\":{},",
            "\"ignored_uncommitted_count\":{},",
            "\"repaired_trailing_bytes\":{}",
            "{}",
            ",\"active_runtime_changed\":false",
            "}}"
        ),
        COMMAND_SCHEMA,
        json_escape(command),
        json_escape(&path.to_string_lossy()),
        record_count,
        edge_count,
        database.committed_transaction_count(),
        hex_digest(&database.state_sha256()),
        recovery.checkpoint_generation,
        recovery.checkpoint_lsn,
        recovery.maximum_valid_wal_lsn,
        recovery.replayed_transaction_count,
        recovery.ignored_uncommitted_count,
        recovery.repaired_trailing_bytes,
        optional,
    )
}

fn no_change_json(
    command: &str,
    path: &Path,
    database: &DurableDatabase,
    reason: &str,
) -> String {
    let (record_count, edge_count) = database.state_counts();
    format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"{}\",",
            "\"db\":\"{}\",",
            "\"changed\":false,",
            "\"reason\":\"{}\",",
            "\"record_count\":{},",
            "\"edge_count\":{},",
            "\"state_sha256\":\"{}\",",
            "\"checkpoint_generation\":{},",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        COMMAND_SCHEMA,
        json_escape(command),
        json_escape(&path.to_string_lossy()),
        json_escape(reason),
        record_count,
        edge_count,
        hex_digest(&database.state_sha256()),
        database.checkpoint_generation(),
    )
}

fn mutation_json(
    command: &str,
    path: &Path,
    changed: bool,
    receipt: &MutationReceipt,
    fields: Option<String>,
) -> String {
    let additional = fields
        .map(|value| format!(",{value}"))
        .unwrap_or_default();
    format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"{}\",",
            "\"db\":\"{}\",",
            "\"changed\":{},",
            "\"transaction_id\":\"{}\",",
            "\"segment_generation\":{},",
            "\"segment_sequence\":{},",
            "\"commit_lsn\":{},",
            "\"checkpoint_generation\":{},",
            "\"checkpoint_lsn\":{},",
            "\"record_count\":{},",
            "\"edge_count\":{},",
            "\"state_sha256\":\"{}\"",
            "{}",
            ",\"active_runtime_changed\":false",
            "}}"
        ),
        COMMAND_SCHEMA,
        json_escape(command),
        json_escape(&path.to_string_lossy()),
        json_bool(changed),
        receipt.transaction_id.to_hex(),
        receipt.generation,
        receipt.segment_sequence,
        receipt.commit_lsn,
        receipt.generation,
        receipt.checkpoint_lsn,
        receipt.record_count,
        receipt.edge_count,
        hex_digest(&receipt.state_sha256),
        additional,
    )
}

fn record_json(
    command: &str,
    path: &Path,
    record: &DatabaseRecord,
    include_payload: bool,
) -> String {
    let payload = if include_payload {
        format!(
            ",\"payload_hex\":\"{}\"",
            hex_bytes(&record.payload),
        )
    } else {
        String::new()
    };
    format!(
        concat!(
            "{{",
            "\"schema\":\"{}\",",
            "\"ok\":true,",
            "\"command\":\"{}\",",
            "\"db\":\"{}\",",
            "\"record\":{{",
            "\"logical_id\":{},",
            "\"record_id\":\"{}\",",
            "\"node_id\":{},",
            "\"payload_bytes\":{},",
            "\"payload_sha256\":\"{}\"",
            "{}",
            "}},",
            "\"active_runtime_changed\":false",
            "}}"
        ),
        COMMAND_SCHEMA,
        json_escape(command),
        json_escape(&path.to_string_lossy()),
        record.logical_id,
        json_escape(&record.record_id),
        record.node_id,
        record.payload.len(),
        hex_digest(&record.payload_sha256),
        payload,
    )
}

fn record_summary_json(record: &DatabaseRecord) -> String {
    format!(
        concat!(
            "{{",
            "\"logical_id\":{},",
            "\"record_id\":\"{}\",",
            "\"node_id\":{},",
            "\"payload_bytes\":{},",
            "\"payload_sha256\":\"{}\"",
            "}}"
        ),
        record.logical_id,
        json_escape(&record.record_id),
        record.node_id,
        record.payload.len(),
        hex_digest(&record.payload_sha256),
    )
}

fn edge_json(edge: &DatabaseEdge) -> String {
    format!(
        concat!(
            "{{",
            "\"logical_id\":{},",
            "\"src\":{},",
            "\"dst\":{},",
            "\"edge_type\":{},",
            "\"weight_million\":{}",
            "}}"
        ),
        edge.logical_id,
        edge.src,
        edge.dst,
        edge.edge_type,
        edge.weight_million,
    )
}

fn edge_fields_json(
    src: u64,
    dst: u64,
    edge_type: u32,
    weight_million: i64,
) -> String {
    format!(
        concat!(
            "\"src\":{},",
            "\"dst\":{},",
            "\"edge_type\":{},",
            "\"weight_million\":{}"
        ),
        src,
        dst,
        edge_type,
        weight_million,
    )
}

fn derive_transaction_id(
    state_sha256: [u8; 32],
    generation: u64,
    segment_sequence: u64,
    command_material: &[u8],
) -> TransactionId {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"UBCLI01\0");
    preimage.extend_from_slice(&state_sha256);
    preimage.extend_from_slice(&generation.to_le_bytes());
    preimage.extend_from_slice(&segment_sequence.to_le_bytes());
    preimage.extend_from_slice(
        &(command_material.len() as u64).to_le_bytes(),
    );
    preimage.extend_from_slice(command_material);
    let digest = sha256(&preimage);
    TransactionId::new(
        digest[0..16]
            .try_into()
            .expect("fixed transaction ID slice"),
    )
}

fn logical_id(domain: &[u8], material: &[u8]) -> u64 {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"UBCLIID\0");
    preimage.extend_from_slice(
        &(domain.len() as u32).to_le_bytes(),
    );
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(
        &(material.len() as u64).to_le_bytes(),
    );
    preimage.extend_from_slice(material);
    let digest = sha256(&preimage);
    let mut value = u64::from_le_bytes(
        digest[0..8].try_into().expect("fixed logical ID slice"),
    );
    if value == 0 {
        value = 1;
    }
    value
}

fn record_material(
    command: &[u8],
    record_id: &str,
    node_id: u64,
    payload: &[u8],
) -> Vec<u8> {
    let record_id = record_id.as_bytes();
    let mut output = Vec::new();
    output.extend_from_slice(command);
    output.extend_from_slice(
        &(record_id.len() as u32).to_le_bytes(),
    );
    output.extend_from_slice(record_id);
    output.extend_from_slice(&node_id.to_le_bytes());
    output.extend_from_slice(
        &(payload.len() as u64).to_le_bytes(),
    );
    output.extend_from_slice(&sha256(payload));
    output
}

fn edge_material(
    command: &[u8],
    src: u64,
    dst: u64,
    edge_type: u32,
    weight_million: i64,
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(command);
    output.extend_from_slice(&src.to_le_bytes());
    output.extend_from_slice(&dst.to_le_bytes());
    output.extend_from_slice(&edge_type.to_le_bytes());
    output.extend_from_slice(&weight_million.to_le_bytes());
    output
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02X}")
            .expect("writing to String cannot fail");
    }
    output
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
                    .expect("writing to String cannot fail");
            }
            character => output.push(character),
        }
    }
    output
}

fn json_bool(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn root(name: &str) -> PathBuf {
        let value = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "ultraballoondb-cli-{name}-{}-{value}",
            std::process::id()
        ))
    }

    fn invoke(arguments: &[&str]) -> Result<String, CliError> {
        run(
            std::iter::once("ultraballoondb".to_string())
                .chain(arguments.iter().map(|value| value.to_string())),
        )
    }

    #[test]
    fn parser_rejects_duplicate_flags() {
        let error = invoke(&[
            "status",
            "--db",
            "a",
            "--db",
            "b",
        ])
        .unwrap_err();
        assert_eq!(error.exit_code, EXIT_INVALID_ARGUMENT);
    }

    #[test]
    fn logical_ids_are_stable_and_non_zero() {
        let first = logical_id(b"record", b"alpha");
        let second = logical_id(b"record", b"alpha");
        let other = logical_id(b"record", b"beta");
        assert_eq!(first, second);
        assert_ne!(first, 0);
        assert_ne!(first, other);
    }

    #[test]
    fn offline_command_surface_roundtrip() {
        let root = root("roundtrip");
        let _ = fs::remove_dir_all(&root);
        let root_string = root.to_string_lossy().to_string();

        let created = invoke(&[
            "create",
            "--db",
            &root_string,
        ])
        .unwrap();
        assert!(created.contains("\"checkpoint_generation\":1"));

        let put = invoke(&[
            "put-record",
            "--db",
            &root_string,
            "--record-id",
            "alpha",
            "--node-id",
            "1001",
            "--payload-utf8",
            "payload",
        ])
        .unwrap();
        assert!(put.contains("\"changed\":true"));

        let duplicate = invoke(&[
            "put-record",
            "--db",
            &root_string,
            "--record-id",
            "alpha",
            "--node-id",
            "1001",
            "--payload-utf8",
            "payload",
        ])
        .unwrap();
        assert!(duplicate.contains("\"changed\":false"));

        let get = invoke(&[
            "get-record",
            "--db",
            &root_string,
            "--record-id",
            "alpha",
        ])
        .unwrap();
        assert!(get.contains("\"payload_hex\":\"7061796C6F6164\""));

        invoke(&[
            "put-edge",
            "--db",
            &root_string,
            "--src",
            "1001",
            "--dst",
            "2002",
            "--edge-type",
            "7",
            "--weight-million",
            "750000",
        ])
        .unwrap();

        let status = invoke(&[
            "status",
            "--db",
            &root_string,
        ])
        .unwrap();
        assert!(status.contains("\"record_count\":1"));
        assert!(status.contains("\"edge_count\":1"));

        let verify = invoke(&[
            "verify",
            "--db",
            &root_string,
        ])
        .unwrap();
        assert!(verify.contains("\"restart_deterministic\":true"));

        invoke(&[
            "delete-edge",
            "--db",
            &root_string,
            "--src",
            "1001",
            "--dst",
            "2002",
            "--edge-type",
            "7",
            "--weight-million",
            "750000",
        ])
        .unwrap();
        invoke(&[
            "delete-record",
            "--db",
            &root_string,
            "--record-id",
            "alpha",
        ])
        .unwrap();

        let final_status = invoke(&[
            "status",
            "--db",
            &root_string,
        ])
        .unwrap();
        assert!(final_status.contains("\"record_count\":0"));
        assert!(final_status.contains("\"edge_count\":0"));

        fs::remove_dir_all(root).unwrap();
    }
}
