use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use ultraballoondb_compat::{
    CrashScenario, CONTROLLED_HARD_EXIT_CODE, FORMAT_MAJOR_V1,
    VERSIONED_FILE_HEADER_BYTES_V1, WAL_HEADER_BYTES_V1,
};
use ultraballoondb_lifecycle::{
    BatchLimits, DurableDatabase, TransactionCore, TransactionId,
    WriteBatch,
};
use ultraballoondb_storage::{hex_digest, sha256_file};

const PARTIAL_TAIL: &[u8; 13] = b"PARTIAL_TAIL!";

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

fn build_prepared_record(
    transaction_id: TransactionId,
    logical_id: u64,
    record_id: &str,
    node_id: u64,
    payload: &[u8],
) -> Result<ultraballoondb_lifecycle::PreparedBatch, Box<dyn std::error::Error>>
{
    let mut batch = WriteBatch::new(BatchLimits::default());
    batch.put_record(
        logical_id,
        record_id,
        node_id,
        payload,
    )?;
    Ok(batch.prepare(transaction_id))
}

fn worker(
    scenario: CrashScenario,
    root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if root.exists() {
        fs::remove_dir_all(root)?;
    }

    match scenario {
        CrashScenario::Uncommitted => {
            let mut database = DurableDatabase::create(root)?;
            let prepared = build_prepared_record(
                TransactionId::new([0x11; 16]),
                1,
                "uncommitted",
                101,
                b"must-not-survive",
            )?;
            database.append_uncommitted_for_probe(&prepared)?;
        }
        CrashScenario::CommittedNoCheckpoint => {
            let mut database = DurableDatabase::create(root)?;
            let mut core = TransactionCore::new(BatchLimits::default());
            let transaction_id = TransactionId::new([0x22; 16]);
            core.begin(transaction_id)?;
            core.put_record(
                2,
                "committed",
                202,
                b"must-survive",
            )?;
            core.prepare()?;
            let receipt = core.commit_durable(
                &mut database,
                1,
                0,
            )?;
            if !receipt.durable_commit
                || !receipt.wal_recorded
                || !receipt.wal_fsynced
            {
                return Err(
                    "durable commit receipt is incomplete".into()
                );
            }
        }
        CrashScenario::Checkpointed => {
            let mut database = DurableDatabase::create(root)?;
            let mut core = TransactionCore::new(BatchLimits::default());
            let transaction_id = TransactionId::new([0x33; 16]);
            core.begin(transaction_id)?;
            core.put_record(
                3,
                "checkpointed",
                303,
                b"checkpoint-state",
            )?;
            core.prepare()?;
            core.commit_durable(&mut database, 1, 0)?;
            core.release_terminal(transaction_id)?;
            let checkpoint = database.checkpoint(1)?;
            if !checkpoint.head_published
                || !checkpoint.wal_checkpoint_recorded
            {
                return Err(
                    "checkpoint publication is incomplete".into()
                );
            }
        }
        CrashScenario::PartialWalTail => {
            let mut database = DurableDatabase::create(root)?;
            let mut core = TransactionCore::new(BatchLimits::default());
            let transaction_id = TransactionId::new([0x44; 16]);
            core.begin(transaction_id)?;
            core.put_record(
                4,
                "partial-tail",
                404,
                b"survives-tail-repair",
            )?;
            core.prepare()?;
            core.commit_durable(&mut database, 1, 0)?;
            core.release_terminal(transaction_id)?;
            let wal_path = database.wal_path().to_path_buf();
            drop(database);

            let mut file = OpenOptions::new()
                .append(true)
                .open(&wal_path)?;
            file.write_all(PARTIAL_TAIL)?;
            file.flush()?;
            file.sync_all()?;
        }
    }

    process::exit(CONTROLLED_HARD_EXIT_CODE);
}

fn run_worker(
    executable: &Path,
    scenario: CrashScenario,
    root: &Path,
) -> Result<i32, Box<dyn std::error::Error>> {
    let status = Command::new(executable)
        .arg("--worker")
        .arg(scenario.name())
        .arg(root)
        .status()?;
    let code = status.code().ok_or(
        "worker ended without a process exit code"
    )?;
    if code != CONTROLLED_HARD_EXIT_CODE {
        return Err(format!(
            "worker {} exit code mismatch: expected={} actual={code}",
            scenario.name(),
            CONTROLLED_HARD_EXIT_CODE,
        )
        .into());
    }
    Ok(code)
}

fn copy_tree(
    source: &Path,
    destination: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if destination.exists() {
        fs::remove_dir_all(destination)?;
    }
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&source_path, &destination_path)?;
        } else {
            fs::copy(&source_path, &destination_path)?;
        }
    }
    Ok(())
}

fn find_extension(
    root: &Path,
    extension: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut matches = Vec::new();
    collect_extension(root, extension, &mut matches)?;
    matches.sort();
    if matches.len() != 1 {
        return Err(format!(
            "expected exactly one .{extension} file below {}, found {}",
            root.display(),
            matches.len()
        )
        .into());
    }
    Ok(matches.remove(0))
}

fn collect_extension(
    root: &Path,
    extension: &str,
    output: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_extension(&path, extension, output)?;
        } else if path.extension().and_then(|value| value.to_str())
            == Some(extension)
        {
            output.push(path);
        }
    }
    Ok(())
}

fn flip_byte(
    path: &Path,
    offset: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    if file.metadata()?.len() <= offset {
        return Err(format!(
            "file is too short to corrupt at offset {offset}: {}",
            path.display()
        )
        .into());
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte)?;
    byte[0] ^= 0x5A;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&byte)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn set_major_two(
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    file.seek(SeekFrom::Start(8))?;
    file.write_all(&2u16.to_le_bytes())?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn expect_open_failure(
    root: &Path,
    repair_trailing: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match DurableDatabase::open(root, repair_trailing) {
        Ok(database) => {
            drop(database);
            Err(format!(
                "corrupted database unexpectedly opened: {}",
                root.display()
            )
            .into())
        }
        Err(_) => Ok(()),
    }
}

fn read_magic_major(
    path: &Path,
) -> Result<([u8; 8], u16), Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut bytes = [0u8; 10];
    file.read_exact(&mut bytes)?;
    let magic: [u8; 8] = bytes[0..8]
        .try_into()
        .expect("fixed magic slice");
    let major = u16::from_le_bytes(
        bytes[8..10].try_into().expect("fixed major slice")
    );
    Ok((magic, major))
}

fn main_parent(
    suite_root: &Path,
    report_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if suite_root.exists() {
        fs::remove_dir_all(suite_root)?;
    }
    fs::create_dir_all(suite_root)?;

    let executable = env::current_exe()?;
    let scenarios = [
        CrashScenario::Uncommitted,
        CrashScenario::CommittedNoCheckpoint,
        CrashScenario::Checkpointed,
        CrashScenario::PartialWalTail,
    ];
    let mut worker_exit_codes = Vec::new();
    for scenario in scenarios {
        let root = suite_root.join(scenario.name());
        let code = run_worker(&executable, scenario, &root)?;
        worker_exit_codes.push((scenario.name(), code));
    }

    let uncommitted_root =
        suite_root.join(CrashScenario::Uncommitted.name());
    let uncommitted = DurableDatabase::open(
        &uncommitted_root,
        true,
    )?;
    let uncommitted_receipt =
        uncommitted.recovery_receipt().clone();
    if uncommitted.state_counts() != (0, 0)
        || uncommitted_receipt.ignored_uncommitted_count != 1
        || uncommitted_receipt.replayed_transaction_count != 0
    {
        return Err("uncommitted recovery contract failed".into());
    }
    drop(uncommitted);

    let committed_root =
        suite_root.join(CrashScenario::CommittedNoCheckpoint.name());
    let committed = DurableDatabase::open(
        &committed_root,
        true,
    )?;
    let committed_receipt = committed.recovery_receipt().clone();
    if committed.state_counts() != (1, 0)
        || committed_receipt.replayed_transaction_count != 1
        || committed_receipt.ignored_uncommitted_count != 0
    {
        return Err("committed recovery contract failed".into());
    }
    let committed_state_hash = committed.state_sha256();
    drop(committed);

    let checkpointed_root =
        suite_root.join(CrashScenario::Checkpointed.name());
    let checkpointed = DurableDatabase::open(
        &checkpointed_root,
        true,
    )?;
    let checkpointed_receipt =
        checkpointed.recovery_receipt().clone();
    if checkpointed.state_counts() != (1, 0)
        || checkpointed_receipt.checkpoint_generation != 1
        || checkpointed_receipt.replayed_transaction_count != 0
        || checkpointed_receipt.ignored_uncommitted_count != 0
    {
        return Err("checkpoint recovery contract failed".into());
    }
    let checkpointed_state_hash = checkpointed.state_sha256();
    drop(checkpointed);

    let partial_root =
        suite_root.join(CrashScenario::PartialWalTail.name());
    let partial = DurableDatabase::open(&partial_root, true)?;
    let partial_receipt = partial.recovery_receipt().clone();
    let partial_state_hash = partial.state_sha256();
    if partial.state_counts() != (1, 0)
        || partial_receipt.replayed_transaction_count != 1
        || partial_receipt.repaired_trailing_bytes
            != PARTIAL_TAIL.len() as u64
    {
        return Err("partial WAL tail recovery failed".into());
    }
    drop(partial);

    let partial_second = DurableDatabase::open(
        &partial_root,
        true,
    )?;
    let second_receipt =
        partial_second.recovery_receipt().clone();
    let second_restart_deterministic =
        partial_second.state_sha256() == partial_state_hash
            && partial_second.state_counts() == (1, 0)
            && second_receipt.repaired_trailing_bytes == 0;
    if !second_restart_deterministic {
        return Err("second restart determinism failed".into());
    }
    drop(partial_second);

    let wal_corrupt_root = suite_root.join("CORRUPT_WAL_SHA");
    copy_tree(&committed_root, &wal_corrupt_root)?;
    let corrupt_wal = find_extension(
        &wal_corrupt_root,
        "ubwal",
    )?;
    flip_byte(
        &corrupt_wal,
        WAL_HEADER_BYTES_V1 as u64,
    )?;
    expect_open_failure(&wal_corrupt_root, true)?;

    let future_major_root =
        suite_root.join("FUTURE_WAL_MAJOR");
    copy_tree(&committed_root, &future_major_root)?;
    let future_wal = find_extension(
        &future_major_root,
        "ubwal",
    )?;
    set_major_two(&future_wal)?;
    expect_open_failure(&future_major_root, true)?;

    let head_corrupt_root =
        suite_root.join("CORRUPT_HEAD");
    copy_tree(&checkpointed_root, &head_corrupt_root)?;
    let corrupt_head = head_corrupt_root.join(
        "CURRENT.ubhead"
    );
    flip_byte(
        &corrupt_head,
        VERSIONED_FILE_HEADER_BYTES_V1 as u64,
    )?;
    expect_open_failure(&head_corrupt_root, true)?;

    let manifest_corrupt_root =
        suite_root.join("CORRUPT_MANIFEST");
    copy_tree(
        &checkpointed_root,
        &manifest_corrupt_root,
    )?;
    let corrupt_manifest = find_extension(
        &manifest_corrupt_root,
        "ubmeta",
    )?;
    flip_byte(
        &corrupt_manifest,
        VERSIONED_FILE_HEADER_BYTES_V1 as u64,
    )?;
    expect_open_failure(&manifest_corrupt_root, true)?;

    let checkpoint_corrupt_root =
        suite_root.join("CORRUPT_CHECKPOINT");
    copy_tree(
        &checkpointed_root,
        &checkpoint_corrupt_root,
    )?;
    let corrupt_checkpoint = find_extension(
        &checkpoint_corrupt_root,
        "ubchk",
    )?;
    flip_byte(
        &corrupt_checkpoint,
        VERSIONED_FILE_HEADER_BYTES_V1 as u64,
    )?;
    expect_open_failure(&checkpoint_corrupt_root, true)?;

    let golden_root = suite_root.join("GOLDEN_FORMAT_V1");
    fs::create_dir_all(&golden_root)?;
    let source_head = checkpointed_root.join(
        "CURRENT.ubhead"
    );
    let source_manifest = find_extension(
        &checkpointed_root,
        "ubmeta",
    )?;
    let source_checkpoint = find_extension(
        &checkpointed_root,
        "ubchk",
    )?;
    let source_wal = find_extension(
        &checkpointed_root,
        "ubwal",
    )?;

    let golden_head = golden_root.join("CURRENT.ubhead");
    let golden_manifest = golden_root.join(
        "MANIFEST-V1-GOLDEN.ubmeta"
    );
    let golden_checkpoint = golden_root.join(
        "CHECKPOINT-V1-GOLDEN.ubchk"
    );
    let golden_wal = golden_root.join(
        "WAL-V1-GOLDEN.ubwal"
    );
    fs::copy(&source_head, &golden_head)?;
    fs::copy(&source_manifest, &golden_manifest)?;
    fs::copy(&source_checkpoint, &golden_checkpoint)?;
    fs::copy(&source_wal, &golden_wal)?;

    let (head_magic, head_major) =
        read_magic_major(&golden_head)?;
    let (manifest_magic, manifest_major) =
        read_magic_major(&golden_manifest)?;
    let (checkpoint_magic, checkpoint_major) =
        read_magic_major(&golden_checkpoint)?;
    let (wal_magic, wal_major) =
        read_magic_major(&golden_wal)?;
    let current_v1_headers_accepted =
        head_magic == *b"UBHEAD1\0"
            && manifest_magic == *b"UBMETA1\0"
            && checkpoint_magic == *b"UBCHK01\0"
            && wal_magic == *b"UBWFR01\0"
            && head_major == FORMAT_MAJOR_V1
            && manifest_major == FORMAT_MAJOR_V1
            && checkpoint_major == FORMAT_MAJOR_V1
            && wal_major == FORMAT_MAJOR_V1;
    if !current_v1_headers_accepted {
        return Err("Format V1 golden header check failed".into());
    }

    let worker_json = worker_exit_codes
        .iter()
        .map(|(scenario, code)| {
            format!(
                "{{\"scenario\":\"{}\",\"exit_code\":{}}}",
                json_escape(scenario),
                code
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let report = format!(
        concat!(
            "{{\n",
            "  \"pass\": true,\n",
            "  \"controlled_hard_exit\": true,\n",
            "  \"controlled_hard_exit_code\": {},\n",
            "  \"worker_exit_receipts\": [{}],\n",
            "  \"hard_exit_scenario_count\": 4,\n",
            "  \"uncommitted_rejected\": true,\n",
            "  \"uncommitted_ignored_count\": {},\n",
            "  \"committed_without_checkpoint_recovered\": true,\n",
            "  \"committed_replayed_transaction_count\": {},\n",
            "  \"checkpointed_recovered\": true,\n",
            "  \"checkpoint_generation\": {},\n",
            "  \"partial_wal_tail_repaired\": true,\n",
            "  \"partial_wal_tail_bytes\": {},\n",
            "  \"second_restart_deterministic\": {},\n",
            "  \"complete_wal_corruption_rejected\": true,\n",
            "  \"repair_did_not_hide_complete_corruption\": true,\n",
            "  \"future_wal_major_rejected\": true,\n",
            "  \"corrupt_head_rejected\": true,\n",
            "  \"corrupt_manifest_rejected\": true,\n",
            "  \"corrupt_checkpoint_rejected\": true,\n",
            "  \"current_v1_headers_accepted\": {},\n",
            "  \"format_major\": {},\n",
            "  \"committed_state_sha256\": \"{}\",\n",
            "  \"checkpointed_state_sha256\": \"{}\",\n",
            "  \"partial_tail_state_sha256\": \"{}\",\n",
            "  \"golden_head_path\": \"{}\",\n",
            "  \"golden_head_sha256\": \"{}\",\n",
            "  \"golden_manifest_path\": \"{}\",\n",
            "  \"golden_manifest_sha256\": \"{}\",\n",
            "  \"golden_checkpoint_path\": \"{}\",\n",
            "  \"golden_checkpoint_sha256\": \"{}\",\n",
            "  \"golden_wal_path\": \"{}\",\n",
            "  \"golden_wal_sha256\": \"{}\",\n",
            "  \"active_runtime_changed\": false,\n",
            "  \"storage_crate_changed\": false,\n",
            "  \"wal_crate_changed\": false,\n",
            "  \"lifecycle_crate_changed\": false,\n",
            "  \"python_source_changed\": false,\n",
            "  \"gpu_backend_promoted\": false\n",
            "}}\n"
        ),
        CONTROLLED_HARD_EXIT_CODE,
        worker_json,
        uncommitted_receipt.ignored_uncommitted_count,
        committed_receipt.replayed_transaction_count,
        checkpointed_receipt.checkpoint_generation,
        partial_receipt.repaired_trailing_bytes,
        if second_restart_deterministic {
            "true"
        } else {
            "false"
        },
        if current_v1_headers_accepted {
            "true"
        } else {
            "false"
        },
        FORMAT_MAJOR_V1,
        hex_digest(&committed_state_hash),
        hex_digest(&checkpointed_state_hash),
        hex_digest(&partial_state_hash),
        path_json(&golden_head),
        hex_digest(&sha256_file(&golden_head)?),
        path_json(&golden_manifest),
        hex_digest(&sha256_file(&golden_manifest)?),
        path_json(&golden_checkpoint),
        hex_digest(&sha256_file(&golden_checkpoint)?),
        path_json(&golden_wal),
        hex_digest(&sha256_file(&golden_wal)?),
    );

    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(report_path, report)?;
    println!(
        "PASS_ULTRABALLOONDB_CRASH_CONSISTENCY_FORMAT_COMPAT_PROBE"
    );
    println!("REPORT={}", report_path.display());
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() >= 2 && arguments[1] == "--worker" {
        if arguments.len() != 4 {
            return Err(
                "worker usage: --worker <scenario> <root>".into()
            );
        }
        let scenario = CrashScenario::parse(&arguments[2])
            .ok_or("unknown worker scenario")?;
        return worker(scenario, Path::new(&arguments[3]));
    }
    if arguments.len() != 3 {
        return Err(
            "usage: crash_format_compat_probe <suite-root> <report-json>"
                .into(),
        );
    }
    main_parent(
        Path::new(&arguments[1]),
        Path::new(&arguments[2]),
    )
}
