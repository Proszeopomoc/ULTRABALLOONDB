use std::fs;
use std::path::{Path, PathBuf};

use ultraballoondb_lifecycle::{
    BatchLimits, DerivedArtifactInventory, DerivedArtifactKind, DurableDatabase, RegisterOutcome,
    TransactionCore, TransactionId, TransactionState,
};
use ultraballoondb_storage::hex_digest;

fn json_string(value: &str) -> String {
    format!("{value:?}")
}

fn commit_record(
    database: &mut DurableDatabase,
    seed: u8,
    logical_id: u64,
    record_id: &str,
    node_id: u64,
    generation: u64,
    sequence: u64,
) {
    let transaction_id = TransactionId::new([seed; 16]);
    let mut transaction = TransactionCore::new(BatchLimits::default());
    transaction.begin(transaction_id).unwrap();
    transaction
        .put_record(logical_id, record_id, node_id, record_id.as_bytes())
        .unwrap();
    transaction.prepare().unwrap();
    let receipt = transaction
        .commit_durable(database, generation, sequence)
        .unwrap();
    assert!(receipt.durable_commit);
    assert_eq!(
        transaction.release_terminal(transaction_id).unwrap(),
        TransactionState::DurableCommitted
    );
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    assert_eq!(
        arguments.len(),
        3,
        "usage: r4_1b_snapshot_inventory_probe ROOT REPORT"
    );
    let root = PathBuf::from(&arguments[1]);
    let report_path = PathBuf::from(&arguments[2]);
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();

    let database_root = root.join("database");
    let mut database = DurableDatabase::create(&database_root).unwrap();

    commit_record(&mut database, 1, 1, "alpha", 10, 1, 1);
    let first_snapshot = {
        let snapshot = database.read_snapshot();
        assert!(snapshot.record("alpha").unwrap().is_some());
        snapshot.descriptor().clone()
    };

    let artifact_relative = Path::new("artifacts/crystallization-v1.bin");
    let artifact_absolute = database_root.join(artifact_relative);
    fs::create_dir_all(artifact_absolute.parent().unwrap()).unwrap();
    fs::write(
        &artifact_absolute,
        b"R4.1B deterministic crystallization artifact",
    )
    .unwrap();

    let mut inventory = DerivedArtifactInventory::create(&database_root).unwrap();
    let register_outcome = inventory
        .register_complete_file(
            DerivedArtifactKind::Crystallization,
            1,
            &first_snapshot,
            artifact_relative,
            1,
        )
        .unwrap();
    assert_eq!(register_outcome, RegisterOutcome::Registered);
    let first_verification = inventory.verify_files().unwrap();
    assert_eq!(first_verification.complete_records, 1);
    assert_eq!(first_verification.verified_files, 1);
    let inventory_path = inventory.path().to_path_buf();
    drop(inventory);

    let mut reopened_inventory = DerivedArtifactInventory::open(&database_root).unwrap();
    let restart_persisted = reopened_inventory.records().count() == 1;

    commit_record(&mut database, 2, 2, "beta", 20, 2, 2);
    let second_snapshot = database.read_snapshot().descriptor().clone();
    let snapshot_changed = first_snapshot.snapshot_sha256 != second_snapshot.snapshot_sha256;
    let invalidated_count = reopened_inventory
        .invalidate_stale(&second_snapshot)
        .unwrap();
    let final_verification = reopened_inventory.verify_files().unwrap();
    let inventory_sha256 = reopened_inventory.inventory_sha256().unwrap();

    database.checkpoint(3).unwrap();
    drop(database);
    let reopened_database = DurableDatabase::open(&database_root, false).unwrap();
    let restart_snapshot = reopened_database.read_snapshot().descriptor().clone();
    let restart_snapshot_deterministic = restart_snapshot.snapshot_sha256
        == second_snapshot.snapshot_sha256
        && restart_snapshot.state_sha256 == second_snapshot.state_sha256;

    let pass = snapshot_changed
        && restart_persisted
        && invalidated_count == 1
        && final_verification.invalidated_records == 1
        && final_verification.complete_records == 0
        && restart_snapshot_deterministic;

    let report = format!(
        concat!(
            "{{\n",
            "  \"schema\": \"ultraballoondb.r4_1b.snapshot_inventory_probe.v1\",\n",
            "  \"pass\": {},\n",
            "  \"read_snapshot_format_version\": {},\n",
            "  \"first_snapshot_sha256\": {},\n",
            "  \"second_snapshot_sha256\": {},\n",
            "  \"first_state_sha256\": {},\n",
            "  \"second_state_sha256\": {},\n",
            "  \"first_record_count\": {},\n",
            "  \"second_record_count\": {},\n",
            "  \"restart_checkpoint_generation\": {},\n",
            "  \"snapshot_changed_after_commit\": {},\n",
            "  \"restart_snapshot_deterministic\": {},\n",
            "  \"inventory_restart_persisted\": {},\n",
            "  \"registered_artifact_count\": {},\n",
            "  \"invalidated_stale_count\": {},\n",
            "  \"final_complete_count\": {},\n",
            "  \"final_invalidated_count\": {},\n",
            "  \"inventory_path\": {},\n",
            "  \"inventory_sha256\": {},\n",
            "  \"record_id_identity_changed\": false,\n",
            "  \"trust_changed\": false,\n",
            "  \"semantic_implemented\": false,\n",
            "  \"gpu_promoted\": false\n",
            "}}\n"
        ),
        pass,
        first_snapshot.format_version,
        json_string(&first_snapshot.snapshot_sha256_hex()),
        json_string(&second_snapshot.snapshot_sha256_hex()),
        json_string(&first_snapshot.state_sha256_hex()),
        json_string(&second_snapshot.state_sha256_hex()),
        first_snapshot.record_count,
        second_snapshot.record_count,
        restart_snapshot.checkpoint_generation,
        snapshot_changed,
        restart_snapshot_deterministic,
        restart_persisted,
        first_verification.total_records,
        invalidated_count,
        final_verification.complete_records,
        final_verification.invalidated_records,
        json_string(&inventory_path.to_string_lossy()),
        json_string(&hex_digest(&inventory_sha256)),
    );

    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&report_path, report).unwrap();

    assert!(pass);
    println!("PASS_R4_1B_READ_SNAPSHOT_DERIVED_ARTIFACT_INVENTORY_PROBE");
    println!("REPORT={}", report_path.display());
}
