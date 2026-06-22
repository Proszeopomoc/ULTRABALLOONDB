use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use ultraballoondb_lifecycle::{
    BatchLimits, DurableDatabase, TransactionCore, TransactionId, TransactionState,
};
use ultraballoondb_semantic::{
    BackupFileEntry, CreateSpaceOutcome, ImportOutcome, PutVectorOutcome, SpaceId, VectorHit,
    VectorInput, VectorNormalization, VectorSpaceDescriptor, VectorStore, VectorStoreError,
};
use ultraballoondb_storage::{hex_digest, sha256};

fn json_string(value: &str) -> String {
    format!("{value:?}")
}

fn json_f32_array(values: &[f32]) -> String {
    let body = values
        .iter()
        .map(|value| format!("{value:.9}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{body}]")
}

fn json_hits(hits: &[VectorHit]) -> String {
    let body = hits
        .iter()
        .map(|hit| {
            format!(
                concat!(
                    "{{",
                    "\"record_id\":{},",
                    "\"cosine_score\":{:.17},",
                    "\"rank\":{},",
                    "\"exact\":{},",
                    "\"space_id\":{},",
                    "\"column_generation\":{},",
                    "\"database_snapshot_sha256\":{}",
                    "}}"
                ),
                json_string(&hit.record_id),
                hit.cosine_score,
                hit.rank,
                hit.exact,
                json_string(&hit.space_id.to_hex()),
                hit.column_generation,
                json_string(&hex_digest(&hit.database_snapshot_sha256)),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{body}]")
}

fn json_backup_entries(entries: &[BackupFileEntry]) -> String {
    let body = entries
        .iter()
        .map(|entry| {
            format!(
                concat!(
                    "{{",
                    "\"relative_path\":{},",
                    "\"byte_count\":{},",
                    "\"sha256\":{}",
                    "}}"
                ),
                json_string(&entry.relative_path),
                entry.byte_count,
                json_string(&entry.sha256_hex()),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{body}]")
}

fn record_id(payload: &[u8]) -> String {
    hex_digest(&sha256(payload))
}

fn commit_record(
    database: &mut DurableDatabase,
    seed: u8,
    logical_id: u64,
    record_id: &str,
    node_id: u64,
    payload: &[u8],
    generation: u64,
    sequence: u64,
) {
    let transaction_id = TransactionId::new([seed; 16]);
    let mut transaction = TransactionCore::new(BatchLimits::default());
    transaction.begin(transaction_id).unwrap();
    transaction
        .put_record(logical_id, record_id, node_id, payload)
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

fn copy_backup_set(source_root: &Path, destination_root: &Path, entries: &[BackupFileEntry]) {
    for entry in entries {
        let source = source_root.join(&entry.relative_path);
        let destination = destination_root.join(&entry.relative_path);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::copy(source, destination).unwrap();
    }
}

fn first_column_path(root: &Path, entries: &[BackupFileEntry]) -> PathBuf {
    root.join(
        &entries
            .iter()
            .find(|entry| entry.relative_path.ends_with(".ubvc"))
            .unwrap()
            .relative_path,
    )
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    assert_eq!(
        arguments.len(),
        3,
        "usage: vector_store_v1_probe ROOT REPORT"
    );
    let root = PathBuf::from(&arguments[1]);
    let report_path = PathBuf::from(&arguments[2]);
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();

    let database_root = root.join("database");
    let mut database = DurableDatabase::create(&database_root).unwrap();

    let payloads = [
        ("alpha", &b"alpha knowledge payload"[..]),
        ("zeta", &b"zeta knowledge payload"[..]),
        ("beta", &b"beta knowledge payload"[..]),
        ("gamma", &b"gamma knowledge payload"[..]),
        ("delta", &b"delta knowledge payload"[..]),
    ];
    let mut record_ids = BTreeMap::new();
    for (index, (name, payload)) in payloads.iter().enumerate() {
        let id = record_id(payload);
        commit_record(
            &mut database,
            (index + 1) as u8,
            (index + 1) as u64,
            &id,
            ((index + 1) * 10) as u64,
            payload,
            (index + 1) as u64,
            (index + 1) as u64,
        );
        record_ids.insert((*name).to_string(), id);
    }
    database.checkpoint(6).unwrap();

    let canonical_before = {
        let snapshot = database.read_snapshot();
        snapshot.descriptor().clone()
    };

    let snapshot = database.read_snapshot();
    let mut store = VectorStore::create(&database_root).unwrap();

    let descriptor = VectorSpaceDescriptor::external(
        "customer",
        "migration-model",
        "revision-1",
        "utf8-normalize-v1",
        4,
        VectorNormalization::None,
    );
    let descriptor_revision_2 = VectorSpaceDescriptor::external(
        "customer",
        "migration-model",
        "revision-2",
        "utf8-normalize-v1",
        4,
        VectorNormalization::None,
    );

    let (space_id, create_outcome) = store.create_space(descriptor.clone()).unwrap();
    assert_eq!(create_outcome, CreateSpaceOutcome::Created);
    let (same_space_id, existing_outcome) = store.create_space(descriptor).unwrap();
    assert_eq!(space_id, same_space_id);
    assert_eq!(existing_outcome, CreateSpaceOutcome::Existing);
    let (revision_2_space_id, _) = store.create_space(descriptor_revision_2).unwrap();
    assert_ne!(space_id, revision_2_space_id);

    let alpha = [1.0f32, 0.0, 0.0, 0.0];
    let zeta = [1.0f32, 0.0, 0.0, 0.0];
    let beta = [0.8f32, 0.2, 0.0, 0.0];
    let gamma = [0.0f32, 1.0, 0.0, 0.0];
    let delta = [0.6f32, 0.4, 0.0, 0.0];
    let query = [1.0f32, 0.0, 0.0, 0.0];

    let put_outcome = store
        .put_vector(&snapshot, space_id, &record_ids["alpha"], &alpha)
        .unwrap();
    assert_eq!(put_outcome, PutVectorOutcome::Inserted);
    assert_eq!(
        store
            .put_vector(&snapshot, space_id, &record_ids["alpha"], &alpha,)
            .unwrap(),
        PutVectorOutcome::Unchanged
    );

    let batch = vec![
        VectorInput::new(record_ids["zeta"].clone(), zeta.to_vec()),
        VectorInput::new(record_ids["beta"].clone(), beta.to_vec()),
        VectorInput::new(record_ids["gamma"].clone(), gamma.to_vec()),
    ];
    assert_eq!(
        store
            .import_vectors(&snapshot, space_id, "migration-batch-001", &batch,)
            .unwrap(),
        ImportOutcome::Applied
    );
    assert_eq!(
        store
            .import_vectors(&snapshot, space_id, "migration-batch-001", &batch,)
            .unwrap(),
        ImportOutcome::DuplicateIgnored
    );

    let conflicting_batch = vec![VectorInput::new(
        record_ids["zeta"].clone(),
        vec![0.5, 0.5, 0.0, 0.0],
    )];
    let idempotency_conflict_rejected = matches!(
        store.import_vectors(
            &snapshot,
            space_id,
            "migration-batch-001",
            &conflicting_batch,
        ),
        Err(VectorStoreError::Conflict(_))
    );
    assert!(idempotency_conflict_rejected);

    let unknown_record_rejected = matches!(
        store.put_vector(&snapshot, space_id, "missing-record", &[1.0, 0.0, 0.0, 0.0],),
        Err(VectorStoreError::NotFound(_))
    );
    assert!(unknown_record_rejected);

    let zero_vector_rejected = matches!(
        store.put_vector(
            &snapshot,
            space_id,
            &record_ids["delta"],
            &[0.0, 0.0, 0.0, 0.0],
        ),
        Err(VectorStoreError::Invalid(_))
    );
    assert!(zero_vector_rejected);

    store
        .put_vector(
            &snapshot,
            revision_2_space_id,
            &record_ids["alpha"],
            &[0.0, 1.0, 0.0, 0.0],
        )
        .unwrap();
    let revision_2_hits = store
        .find_exact(&snapshot, revision_2_space_id, &query, 10)
        .unwrap();
    assert_eq!(revision_2_hits.len(), 1);
    assert_eq!(revision_2_hits[0].record_id, record_ids["alpha"]);

    let before_journal_hits = store.find_exact(&snapshot, space_id, &query, 10).unwrap();
    assert_eq!(before_journal_hits.len(), 4);

    let staged_generation = store
        .stage_put_vector_journal_for_probe(&snapshot, space_id, &record_ids["delta"], &delta)
        .unwrap();
    drop(store);

    let reopened = VectorStore::open(&database_root).unwrap();
    let journal_recovery_applied = reopened.column_generation(space_id) == Some(staged_generation);
    assert!(journal_recovery_applied);

    let hits = reopened
        .find_exact(&snapshot, space_id, &query, 10)
        .unwrap();
    assert_eq!(hits.len(), 5);
    assert!(hits.iter().all(|hit| hit.exact));

    let mut tied = vec![record_ids["alpha"].clone(), record_ids["zeta"].clone()];
    tied.sort();
    let actual_tied = vec![hits[0].record_id.clone(), hits[1].record_id.clone()];
    assert_eq!(actual_tied, tied);

    let verification = reopened.verify().unwrap();
    assert_eq!(verification.space_count, 2);
    assert_eq!(verification.vector_count, 6);
    assert_eq!(verification.import_receipt_count, 1);

    let backup_entries = reopened.backup_file_set().unwrap();
    assert_eq!(backup_entries.len(), 3);
    let backup_root = root.join("backup-roundtrip");
    copy_backup_set(&database_root, &backup_root, &backup_entries);
    let backup_store = VectorStore::open(&backup_root).unwrap();
    let backup_hits = backup_store
        .find_exact(&snapshot, space_id, &query, 10)
        .unwrap();
    let backup_roundtrip_equal = backup_hits == hits;
    assert!(backup_roundtrip_equal);

    let corruption_root = root.join("corruption-test");
    copy_backup_set(&database_root, &corruption_root, &backup_entries);
    let corruption_column = first_column_path(&corruption_root, &backup_entries);
    let mut corrupted = fs::read(&corruption_column).unwrap();
    corrupted[0] ^= 0xFF;
    fs::write(&corruption_column, corrupted).unwrap();
    let corruption_rejected = VectorStore::open(&corruption_root).is_err();
    assert!(corruption_rejected);

    let orphan_root = root.join("orphan-test");
    copy_backup_set(&database_root, &orphan_root, &backup_entries);
    let orphan_path = orphan_root
        .join("vectors")
        .join("COLUMNS")
        .join(format!("{}.ubvc", "AA".repeat(32)));
    fs::write(&orphan_path, b"orphan").unwrap();
    let orphan_rejected = VectorStore::open(&orphan_root).is_err();
    assert!(orphan_rejected);

    drop(backup_store);
    drop(reopened);
    drop(snapshot);

    let canonical_after = {
        let snapshot = database.read_snapshot();
        snapshot.descriptor().clone()
    };
    let record_identity_invariant = canonical_before.state_sha256 == canonical_after.state_sha256
        && canonical_before.record_count == canonical_after.record_count
        && canonical_before.edge_count == canonical_after.edge_count;
    assert!(record_identity_invariant);

    let mut source_vectors = BTreeMap::new();
    source_vectors.insert(record_ids["alpha"].clone(), alpha.to_vec());
    source_vectors.insert(record_ids["zeta"].clone(), zeta.to_vec());
    source_vectors.insert(record_ids["beta"].clone(), beta.to_vec());
    source_vectors.insert(record_ids["gamma"].clone(), gamma.to_vec());
    source_vectors.insert(record_ids["delta"].clone(), delta.to_vec());
    let source_vectors_json = source_vectors
        .iter()
        .map(
            |(record_id, vector)| format!("{}:{}", json_string(record_id), json_f32_array(vector),),
        )
        .collect::<Vec<_>>()
        .join(",");

    let pass = journal_recovery_applied
        && backup_roundtrip_equal
        && corruption_rejected
        && orphan_rejected
        && record_identity_invariant
        && idempotency_conflict_rejected
        && unknown_record_rejected
        && zero_vector_rejected
        && actual_tied == tied;

    let report = format!(
        concat!(
            "{{\n",
            "  \"schema\": \"ultraballoondb.r4_2.vector_store_probe.v1\",\n",
            "  \"pass\": {},\n",
            "  \"database_root\": {},\n",
            "  \"space_id\": {},\n",
            "  \"revision_2_space_id\": {},\n",
            "  \"space_ids_differ_by_revision\": {},\n",
            "  \"dimension\": 4,\n",
            "  \"query_vector\": {},\n",
            "  \"source_vectors\": {{{}}},\n",
            "  \"hits\": {},\n",
            "  \"revision_2_hits\": {},\n",
            "  \"tie_expected_record_ids\": [{},{}],\n",
            "  \"tie_actual_record_ids\": [{},{}],\n",
            "  \"column_generation\": {},\n",
            "  \"journal_recovery_applied\": {},\n",
            "  \"import_idempotency_duplicate_ignored\": true,\n",
            "  \"idempotency_conflict_rejected\": {},\n",
            "  \"unknown_record_rejected\": {},\n",
            "  \"zero_vector_rejected\": {},\n",
            "  \"backup_roundtrip_equal\": {},\n",
            "  \"backup_file_set\": {},\n",
            "  \"corruption_rejected\": {},\n",
            "  \"orphan_column_rejected\": {},\n",
            "  \"record_identity_invariant\": {},\n",
            "  \"canonical_state_sha256_before\": {},\n",
            "  \"canonical_state_sha256_after\": {},\n",
            "  \"record_count_before\": {},\n",
            "  \"record_count_after\": {},\n",
            "  \"vector_store_space_count\": {},\n",
            "  \"vector_store_vector_count\": {},\n",
            "  \"vector_store_import_receipt_count\": {},\n",
            "  \"registry_sha256\": {},\n",
            "  \"exact_cpu\": true,\n",
            "  \"ann_used\": false,\n",
            "  \"gpu_used\": false,\n",
            "  \"trust_crate_dependency\": false,\n",
            "  \"trust_changed\": false,\n",
            "  \"graph_narrowing_used\": false,\n",
            "  \"native_structural_semantics_used\": false\n",
            "}}\n"
        ),
        pass,
        json_string(&database_root.to_string_lossy()),
        json_string(&space_id.to_hex()),
        json_string(&revision_2_space_id.to_hex()),
        space_id != revision_2_space_id,
        json_f32_array(&query),
        source_vectors_json,
        json_hits(&hits),
        json_hits(&revision_2_hits),
        json_string(&tied[0]),
        json_string(&tied[1]),
        json_string(&actual_tied[0]),
        json_string(&actual_tied[1]),
        reopened_generation(&database_root, space_id),
        journal_recovery_applied,
        idempotency_conflict_rejected,
        unknown_record_rejected,
        zero_vector_rejected,
        backup_roundtrip_equal,
        json_backup_entries(&backup_entries),
        corruption_rejected,
        orphan_rejected,
        record_identity_invariant,
        json_string(&hex_digest(&canonical_before.state_sha256)),
        json_string(&hex_digest(&canonical_after.state_sha256)),
        canonical_before.record_count,
        canonical_after.record_count,
        verification.space_count,
        verification.vector_count,
        verification.import_receipt_count,
        json_string(&verification.registry_sha256_hex()),
    );

    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&report_path, report).unwrap();
    assert!(pass);

    println!("PASS_R4_2_VECTOR_STORE_EXACT_MIGRATION_PROBE");
    println!("REPORT={}", report_path.display());
}

fn reopened_generation(database_root: &Path, space_id: SpaceId) -> u64 {
    VectorStore::open(database_root)
        .unwrap()
        .column_generation(space_id)
        .unwrap()
}
