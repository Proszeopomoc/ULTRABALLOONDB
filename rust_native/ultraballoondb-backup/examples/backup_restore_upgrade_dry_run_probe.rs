use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ultraballoondb_backup::{
    create_backup, digest_file, open_backup_strict, restore_dry_run,
    restore_to_new_directory, upgrade_dry_run, BackupRequest,
    BACKUP_MANIFEST_FILE_NAME,
};
use ultraballoondb_storage::sha256;

const PASS: &str = "PASS_ULTRABALLOONDB_V00R3C1_BACKUP_RESTORE_UPGRADE_DRY_RUN_PROBE";

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(H[(byte >> 4) as usize] as char);
        output.push(H[(byte & 0x0f) as usize] as char);
    }
    output
}

fn json_bool(value: bool) -> &'static str { if value { "true" } else { "false" } }

fn write_fixture(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() { fs::create_dir_all(parent).unwrap(); }
    fs::write(path, bytes).unwrap();
}

fn snapshot(paths: &[(&str, PathBuf)]) -> BTreeMap<String, ([u8; 32], u64)> {
    paths.iter().map(|(name, path)| ((*name).to_string(), digest_file(path).unwrap())).collect()
}

fn main() {
    let root = PathBuf::from(env::args().nth(1).expect("probe root argument"));
    if root.exists() { fs::remove_dir_all(&root).unwrap(); }
    fs::create_dir_all(&root).unwrap();
    let source = root.join("source");
    let backup = root.join("backup");
    let restore = root.join("restore");
    let dry_run_destination = root.join("dry-run-destination");

    write_fixture(&source.join("storage/database.ubdb"), b"UBDB-C1-DATABASE-FIXTURE\nrecord=alpha\nrecord=beta\n");
    write_fixture(&source.join("wal/database.ubwal"), b"UBDB-C1-WAL-FIXTURE\ncommit=1\ncommit=2\n");
    write_fixture(&source.join("trust/asymmetric-keys.ubakey"), b"UBDB-C1-KEY-REGISTRY-FIXTURE\n");
    write_fixture(&source.join("provenance/provenance-core.ubprov"), b"UBDB-C1-PROVENANCE-FIXTURE\n");
    let large: Vec<u8> = (0..(2 * 1024 * 1024 + 17)).map(|index| (index % 251) as u8).collect();
    write_fixture(&source.join("storage/large-segment.ubseg"), &large);

    let relative = vec![
        "provenance/provenance-core.ubprov".to_string(),
        "storage/database.ubdb".to_string(),
        "storage/large-segment.ubseg".to_string(),
        "trust/asymmetric-keys.ubakey".to_string(),
        "wal/database.ubwal".to_string(),
    ];
    let source_paths: Vec<_> = relative.iter().map(|path| (path.as_str(), source.join(path.replace('/', std::path::MAIN_SEPARATOR_STR)))).collect();
    let before = snapshot(&source_paths);
    let request = BackupRequest {
        backup_id: "c1-probe-backup-0001".to_string(),
        source_database_id: "c1-probe-database".to_string(),
        logical_timestamp: 1_000_000,
        source_schema_version: 3,
        provenance_head_digest: sha256(b"p0-provenance-head-fixture"),
        relative_files: relative.clone(),
    };
    let created = create_backup(&source, &backup, &request).expect("create backup");
    let opened = open_backup_strict(&backup).expect("strict open");
    assert_eq!(created, opened);
    let after = snapshot(&source_paths);
    let source_unchanged = before == after;

    let upgrade = upgrade_dry_run(&backup, 5).expect("upgrade dry run");
    let dry = restore_dry_run(&backup, &dry_run_destination, 5).expect("restore dry run");
    let upgrade_dry_run_no_write = !upgrade.would_write && !dry.would_write && !dry_run_destination.exists();
    let exact_restore_plan = restore_dry_run(&backup, &restore, 3).expect("exact restore dry run");
    let receipt = restore_to_new_directory(&backup, &restore, exact_restore_plan.plan_digest).expect("staged restore");
    let restored_matches = relative.iter().all(|path| {
        digest_file(source.join(path.replace('/', std::path::MAIN_SEPARATOR_STR))).unwrap()
            == digest_file(restore.join(path.replace('/', std::path::MAIN_SEPARATOR_STR))).unwrap()
    });

    let existing_destination_rejected = restore_to_new_directory(&backup, &restore, exact_restore_plan.plan_digest).is_err();
    let downgrade_rejected = upgrade_dry_run(&backup, 2).is_err();

    let payload_path = backup.join("payload/storage/database.ubdb");
    let original_payload = fs::read(&payload_path).unwrap();
    fs::write(&payload_path, b"tampered-payload").unwrap();
    let tamper_rejected = open_backup_strict(&backup).is_err();
    fs::write(&payload_path, original_payload).unwrap();

    let manifest_path = backup.join(BACKUP_MANIFEST_FILE_NAME);
    let original_manifest = fs::read(&manifest_path).unwrap();
    fs::write(&manifest_path, &original_manifest[..original_manifest.len() - 7]).unwrap();
    let truncation_rejected = open_backup_strict(&backup).is_err();
    fs::write(&manifest_path, original_manifest).unwrap();

    let extra = backup.join("payload/extra-unlisted.bin");
    fs::write(&extra, b"extra").unwrap();
    let extra_payload_rejected = open_backup_strict(&backup).is_err();
    fs::remove_file(&extra).unwrap();
    open_backup_strict(&backup).expect("backup must be valid after negative probes");

    let total_bytes: u64 = opened.files.iter().map(|entry| entry.size_bytes).sum();
    let pass = source_unchanged
        && upgrade_dry_run_no_write
        && restored_matches
        && existing_destination_rejected
        && downgrade_rejected
        && tamper_rejected
        && truncation_rejected
        && extra_payload_rejected
        && receipt.file_count == opened.files.len()
        && receipt.total_bytes == total_bytes
        && dry.conflict_count == 0;

    let report = format!(
        concat!(
            "{{\n",
            "  \"pass\": {},\n",
            "  \"source_unchanged\": {},\n",
            "  \"backup_strict_replay\": true,\n",
            "  \"upgrade_dry_run_no_write\": {},\n",
            "  \"restore_dry_run_no_write\": {},\n",
            "  \"restored_matches_source\": {},\n",
            "  \"existing_destination_rejected\": {},\n",
            "  \"downgrade_rejected\": {},\n",
            "  \"tamper_rejected\": {},\n",
            "  \"truncation_rejected\": {},\n",
            "  \"extra_payload_rejected\": {},\n",
            "  \"source_schema_version\": 3,\n",
            "  \"target_schema_version\": 5,\n",
            "  \"upgrade_step_count\": {},\n",
            "  \"file_count\": {},\n",
            "  \"total_bytes\": {},\n",
            "  \"manifest_digest\": \"{}\",\n",
            "  \"upgrade_plan_digest\": \"{}\",\n",
            "  \"restore_plan_digest\": \"{}\",\n",
            "  \"restore_receipt_digest\": \"{}\",\n",
            "  \"active_runtime_changed\": false,\n",
            "  \"storage_format_changed\": false,\n",
            "  \"wal_changed\": false,\n",
            "  \"upgrade_executed\": false\n",
            "}}\n"
        ),
        json_bool(pass), json_bool(source_unchanged), json_bool(upgrade_dry_run_no_write),
        json_bool(!dry.would_write && !dry_run_destination.exists()), json_bool(restored_matches),
        json_bool(existing_destination_rejected), json_bool(downgrade_rejected),
        json_bool(tamper_rejected), json_bool(truncation_rejected), json_bool(extra_payload_rejected),
        upgrade.step_count, opened.files.len(), total_bytes, hex(&opened.manifest_digest),
        hex(&upgrade.plan_digest), hex(&exact_restore_plan.plan_digest), hex(&receipt.receipt_digest),
    );
    fs::write(root.join("backup_restore_upgrade_probe_report.json"), report).unwrap();
    if !pass { panic!("C1 probe failed"); }
    println!("{PASS}");
}
