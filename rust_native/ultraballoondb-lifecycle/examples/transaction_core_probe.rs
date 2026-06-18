use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ultraballoondb_lifecycle::{
    AddOutcome, BatchLimits, TransactionCore, TransactionId, TransactionState,
};
use ultraballoondb_storage::{hex_digest, PageStore};

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
                    .expect("writing to String");
            }
            character => output.push(character),
        }
    }
    output
}

fn path_json(path: &Path) -> String {
    json_escape(&path.to_string_lossy())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() != 3 {
        return Err(
            "usage: transaction_core_probe <database-root> <report-json>"
                .into(),
        );
    }

    let root = PathBuf::from(&arguments[1]);
    let report_path = PathBuf::from(&arguments[2]);
    if root.exists() {
        fs::remove_dir_all(&root)?;
    }

    let store = PageStore::create(&root)?;
    let transaction_id = TransactionId::new([
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F,
    ]);
    let mut core = TransactionCore::new(BatchLimits {
        max_operations: 100,
        max_payload_bytes: 1024 * 1024,
    });

    core.begin(transaction_id)?;
    let first = core.put_record(
        1,
        "alpha",
        1001,
        b"alpha-payload",
    )?;
    let duplicate_record = core.put_record(
        1,
        "alpha",
        1001,
        b"alpha-payload",
    )?;
    core.put_record(
        2,
        "beta",
        2002,
        b"beta-payload",
    )?;
    core.put_edge(3, 1001, 2002, 7, 0.75)?;
    let duplicate_edge = core.put_edge(
        3,
        1001,
        2002,
        7,
        0.75,
    )?;
    core.delete_record(4, "obsolete")?;
    core.delete_edge(5, 3003, 4004, 9, -0.0)?;

    if first != AddOutcome::Added
        || duplicate_record != AddOutcome::DuplicateIgnored
        || duplicate_edge != AddOutcome::DuplicateIgnored
    {
        return Err("duplicate/idempotency contract failed".into());
    }

    let prepared = core.prepare()?;
    let mutation_after_prepare_rejected = core
        .put_record(6, "late", 6006, b"late")
        .is_err();
    if !mutation_after_prepare_rejected {
        return Err("mutation after prepare was accepted".into());
    }

    let receipt = core.materialize_shadow(&store, 11, 2)?;
    if receipt.durable_commit
        || receipt.wal_recorded
        || receipt.head_published
        || receipt.active_runtime_changed
    {
        return Err("B2 shadow receipt claimed forbidden durability".into());
    }

    let state_after_materialization = core
        .active_state()
        .ok_or("active state missing")?;
    if state_after_materialization != TransactionState::ShadowMaterialized {
        return Err("unexpected state after shadow materialization".into());
    }
    let released_state = core.release_terminal(transaction_id)?;
    if released_state != TransactionState::ShadowMaterialized {
        return Err("unexpected released terminal state".into());
    }

    let conflict_tx = TransactionId::new([0x22; 16]);
    core.begin(conflict_tx)?;
    core.put_record(20, "conflict", 20, b"one")?;
    let conflict_rejected = core
        .put_record(21, "conflict", 20, b"two")
        .is_err();
    if !conflict_rejected {
        return Err("record conflict was accepted".into());
    }
    core.abort()?;
    core.release_terminal(conflict_tx)?;

    let abort_tx = TransactionId::new([0x33; 16]);
    core.begin(abort_tx)?;
    core.put_record(30, "aborted", 30, b"not-materialized")?;
    core.abort()?;
    let abort_materialization_rejected = core
        .materialize_shadow(&store, 12, 0)
        .is_err();
    if !abort_materialization_rejected {
        return Err("aborted transaction was materialized".into());
    }
    core.release_terminal(abort_tx)?;

    let integrity = PageStore::open(&root)?.verify()?;
    if integrity.segment_count != 1 {
        return Err("unexpected shadow segment count".into());
    }

    let report = format!(
        concat!(
            "{{\n",
            "  \"pass\": true,\n",
            "  \"transaction_id_hex\": \"{}\",\n",
            "  \"batch_digest_sha256\": \"{}\",\n",
            "  \"operation_count\": {},\n",
            "  \"total_payload_bytes\": {},\n",
            "  \"segment_path\": \"{}\",\n",
            "  \"segment_file_sha256\": \"{}\",\n",
            "  \"segment_payload_sha256\": \"{}\",\n",
            "  \"segment_generation\": {},\n",
            "  \"segment_sequence\": {},\n",
            "  \"duplicate_ignored_count\": 2,\n",
            "  \"conflict_rejected\": true,\n",
            "  \"mutation_after_prepare_rejected\": true,\n",
            "  \"abort_materialization_rejected\": true,\n",
            "  \"state_after_materialization\": \"SHADOW_MATERIALIZED\",\n",
            "  \"durable_commit\": false,\n",
            "  \"wal_recorded\": false,\n",
            "  \"head_published\": false,\n",
            "  \"active_runtime_changed\": false,\n",
            "  \"store_segment_count\": {}\n",
            "}}\n"
        ),
        transaction_id.to_hex(),
        prepared.batch_digest_hex(),
        prepared.operation_count(),
        prepared.total_payload_bytes(),
        path_json(&receipt.segment_path),
        receipt.segment_file_sha256_hex(),
        hex_digest(&receipt.segment_payload_sha256),
        receipt.generation,
        receipt.sequence,
        integrity.segment_count,
    );

    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&report_path, report)?;
    println!("PASS_ULTRABALLOONDB_TRANSACTION_CORE_PROBE");
    println!("REPORT={}", report_path.display());
    Ok(())
}
