use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ultraballoondb_lifecycle::{
    BatchLimits, DurableDatabase, TransactionCore, TransactionId,
    TransactionState, WriteBatch,
};
use ultraballoondb_storage::hex_digest;
use ultraballoondb_wal::scan_wal;

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
            "usage: wal_checkpoint_recovery_probe <database-root> <report-json>"
                .into(),
        );
    }
    let root = PathBuf::from(&arguments[1]);
    let report_path = PathBuf::from(&arguments[2]);
    if root.exists() {
        fs::remove_dir_all(&root)?;
    }

    let mut database = DurableDatabase::create(&root)?;
    let mut core = TransactionCore::new(BatchLimits::default());

    let tx1 = TransactionId::new([0x11; 16]);
    core.begin(tx1)?;
    core.put_record(1, "alpha", 1001, b"alpha-payload")?;
    core.put_edge(2, 1001, 2002, 7, 0.75)?;
    core.prepare()?;
    let commit1 = core.commit_durable(&mut database, 1, 0)?;
    if core.active_state() != Some(TransactionState::DurableCommitted) {
        return Err("transaction core did not reach DURABLE_COMMITTED".into());
    }
    core.release_terminal(tx1)?;

    let checkpoint = database.checkpoint(1)?;
    if !checkpoint.head_published || !checkpoint.wal_checkpoint_recorded {
        return Err("checkpoint publication contract failed".into());
    }

    let tx2 = TransactionId::new([0x22; 16]);
    core.begin(tx2)?;
    core.put_record(3, "beta", 2002, b"beta-payload")?;
    core.prepare()?;
    let commit2 = core.commit_durable(&mut database, 2, 0)?;
    core.release_terminal(tx2)?;

    let mut uncommitted = WriteBatch::new(BatchLimits::default());
    uncommitted.put_record(4, "ignored", 3003, b"ignored-payload")?;
    let uncommitted_prepared =
        uncommitted.prepare(TransactionId::new([0x33; 16]));
    database.append_uncommitted_for_probe(&uncommitted_prepared)?;

    let expected_state_hash = database.state_sha256();
    let wal_path = database.wal_path().to_path_buf();
    drop(database);

    let mut wal_file = OpenOptions::new().append(true).open(&wal_path)?;
    wal_file.write_all(b"PARTIAL_TAIL")?;
    wal_file.sync_all()?;
    drop(wal_file);

    let reopened = DurableDatabase::open(&root, true)?;
    let recovery = reopened.recovery_receipt().clone();
    if recovery.replayed_transaction_count != 1
        || recovery.ignored_uncommitted_count != 1
        || recovery.repaired_trailing_bytes != 12
        || reopened.state_counts() != (2, 1)
        || reopened.state_sha256() != expected_state_hash
    {
        return Err("recovery result contract failed".into());
    }
    drop(reopened);

    let reopened_again = DurableDatabase::open(&root, true)?;
    let restart_deterministic =
        reopened_again.state_sha256() == expected_state_hash
            && reopened_again.state_counts() == (2, 1);
    if !restart_deterministic {
        return Err("restart determinism failed".into());
    }
    drop(reopened_again);

    let wal_scan = scan_wal(&wal_path, false)?;
    let report = format!(
        concat!(
            "{{\n",
            "  \"pass\": true,\n",
            "  \"database_root\": \"{}\",\n",
            "  \"wal_path\": \"{}\",\n",
            "  \"wal_frame_count\": {},\n",
            "  \"maximum_valid_wal_lsn\": {},\n",
            "  \"commit1_begin_lsn\": {},\n",
            "  \"commit1_lsn\": {},\n",
            "  \"commit2_begin_lsn\": {},\n",
            "  \"commit2_lsn\": {},\n",
            "  \"durable_commit\": true,\n",
            "  \"wal_recorded\": true,\n",
            "  \"wal_fsynced\": true,\n",
            "  \"checkpoint_path\": \"{}\",\n",
            "  \"checkpoint_file_sha256\": \"{}\",\n",
            "  \"manifest_path\": \"{}\",\n",
            "  \"manifest_file_sha256\": \"{}\",\n",
            "  \"head_path\": \"{}\",\n",
            "  \"checkpoint_generation\": {},\n",
            "  \"checkpoint_lsn\": {},\n",
            "  \"head_published\": true,\n",
            "  \"replayed_transaction_count\": {},\n",
            "  \"ignored_uncommitted_count\": {},\n",
            "  \"repaired_trailing_bytes\": {},\n",
            "  \"record_count\": {},\n",
            "  \"edge_count\": {},\n",
            "  \"state_sha256\": \"{}\",\n",
            "  \"restart_deterministic\": {},\n",
            "  \"active_runtime_changed\": false,\n",
            "  \"segment1_path\": \"{}\",\n",
            "  \"segment2_path\": \"{}\"\n",
            "}}\n"
        ),
        path_json(&root),
        path_json(&wal_path),
        wal_scan.frames.len(),
        wal_scan.maximum_lsn,
        commit1.begin_lsn,
        commit1.commit_lsn,
        commit2.begin_lsn,
        commit2.commit_lsn,
        path_json(&checkpoint.checkpoint_path),
        hex_digest(&checkpoint.checkpoint_file_sha256),
        path_json(&checkpoint.manifest_path),
        hex_digest(&checkpoint.manifest_file_sha256),
        path_json(&checkpoint.head_path),
        checkpoint.generation,
        checkpoint.checkpoint_lsn,
        recovery.replayed_transaction_count,
        recovery.ignored_uncommitted_count,
        recovery.repaired_trailing_bytes,
        recovery.record_count,
        recovery.edge_count,
        hex_digest(&recovery.state_sha256),
        if restart_deterministic { "true" } else { "false" },
        path_json(&commit1.segment_path),
        path_json(&commit2.segment_path),
    );

    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&report_path, report)?;
    println!("PASS_ULTRABALLOONDB_WAL_CHECKPOINT_RECOVERY_PROBE");
    println!("REPORT={}", report_path.display());
    Ok(())
}
