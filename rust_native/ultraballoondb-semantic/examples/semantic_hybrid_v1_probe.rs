use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use ultraballoondb_lifecycle::{
    BatchLimits, DerivedArtifactInventory, DurableDatabase, TransactionCore, TransactionId,
    TransactionState,
};
use ultraballoondb_semantic::{
    build_native_structural_space, build_wave_scope, query_hybrid, query_semantic_exact,
    query_topological, CreateSpaceOutcome, GraphScopeConfig, GraphSnapshotIndex, HybridHit,
    HybridWeights, ImportOutcome, NativeStructuralConfig, SemanticEvidenceHit, TopologicalHit,
    TrustFilter, UnknownTrustPolicy, VectorInput, VectorNormalization, VectorSpaceDescriptor,
    VectorStore,
};
use ultraballoondb_storage::{hex_digest, sha256};
use ultraballoondb_trust::{
    EvidenceRef, MaturityState, TransitionAuthority, TransitionIntent, TrustLedger, TrustOperation,
};

fn json_string(value: &str) -> String {
    format!("{value:?}")
}

fn json_u32_array(values: &[u32]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn record_id(payload: &[u8]) -> String {
    hex_digest(&sha256(payload))
}

fn evidence(id: &str) -> EvidenceRef {
    EvidenceRef {
        evidence_id: id.to_string(),
        provenance_id: format!("provenance-{id}"),
        evidence_digest: sha256(id.as_bytes()),
    }
}

fn trust_intent(
    record_id: &str,
    record_digest: [u8; 32],
    operation: TrustOperation,
    authority: TransitionAuthority,
    timestamp: u64,
    label: &str,
) -> TransitionIntent {
    TransitionIntent {
        record_id: record_id.to_string(),
        operation,
        authority,
        evidence_refs: vec![evidence(label)],
        policy_id: "r4-3-query-trust-policy".to_string(),
        policy_version: "1.0.0".to_string(),
        verifier_id: "r4-3-probe".to_string(),
        record_digest,
        logical_timestamp: timestamp,
        reason_code: format!("{}-{label}", operation.as_str()),
        superseding_record_id: None,
    }
}

fn promote_verified(
    ledger: &mut TrustLedger,
    record_id: &str,
    record_digest: [u8; 32],
    timestamp: &mut u64,
) {
    ledger
        .apply(trust_intent(
            record_id,
            record_digest,
            TrustOperation::Propose,
            TransitionAuthority::Import,
            *timestamp,
            "propose",
        ))
        .unwrap();
    *timestamp += 1;
    for label in ["hypothesis", "candidate", "verified"] {
        ledger
            .apply(trust_intent(
                record_id,
                record_digest,
                TrustOperation::Promote,
                TransitionAuthority::EvidencePolicy,
                *timestamp,
                label,
            ))
            .unwrap();
        *timestamp += 1;
    }
}

fn commit_graph(
    database: &mut DurableDatabase,
    records: &[(u64, String, u64, Vec<u8>)],
    edges: &[(u64, u64, u64, u32, f64)],
) {
    let transaction_id = TransactionId::new([41u8; 16]);
    let mut transaction = TransactionCore::new(BatchLimits::default());
    transaction.begin(transaction_id).unwrap();
    for (logical_id, id, node_id, payload) in records {
        transaction
            .put_record(*logical_id, id, *node_id, payload)
            .unwrap();
    }
    for (logical_id, src, dst, edge_type, weight) in edges {
        transaction
            .put_edge(*logical_id, *src, *dst, *edge_type, *weight)
            .unwrap();
    }
    transaction.prepare().unwrap();
    let receipt = transaction.commit_durable(database, 1, 1).unwrap();
    assert!(receipt.durable_commit);
    assert_eq!(
        transaction.release_terminal(transaction_id).unwrap(),
        TransactionState::DurableCommitted
    );
}

fn topological_json(rows: &[TopologicalHit]) -> String {
    format!(
        "[{}]",
        rows.iter()
            .map(|row| {
                format!(
                    concat!(
                        "{{",
                        "\"record_id\":{},",
                        "\"node_id\":{},",
                        "\"rank\":{},",
                        "\"wave_energy\":{:.17},",
                        "\"path_edge_types\":{},",
                        "\"direct_outgoing_edge_types\":{},",
                        "\"direct_incoming_edge_types\":{},",
                        "\"trust_maturity\":{},",
                        "\"trust_validity\":{},",
                        "\"trust_explicit\":{}",
                        "}}"
                    ),
                    json_string(&row.record_id),
                    row.node_id,
                    row.rank,
                    row.wave.energy,
                    json_u32_array(&row.wave.path_edge_types),
                    json_u32_array(&row.wave.direct_outgoing_edge_types),
                    json_u32_array(&row.wave.direct_incoming_edge_types),
                    json_string(row.trust.state.maturity.as_str()),
                    json_string(row.trust.state.validity.as_str()),
                    row.trust.explicit,
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn semantic_json(rows: &[SemanticEvidenceHit]) -> String {
    format!(
        "[{}]",
        rows.iter()
            .map(|row| {
                let wave_energy = row
                    .wave
                    .as_ref()
                    .map(|wave| wave.energy.to_string())
                    .unwrap_or_else(|| "null".to_string());
                format!(
                    concat!(
                        "{{",
                        "\"record_id\":{},",
                        "\"rank\":{},",
                        "\"cosine_score\":{:.17},",
                        "\"exact\":{},",
                        "\"wave_energy\":{},",
                        "\"trust_maturity\":{},",
                        "\"trust_validity\":{}",
                        "}}"
                    ),
                    json_string(&row.vector.record_id),
                    row.vector.rank,
                    row.vector.cosine_score,
                    row.vector.exact,
                    wave_energy,
                    json_string(row.trust.state.maturity.as_str()),
                    json_string(row.trust.state.validity.as_str()),
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn hybrid_json(rows: &[HybridHit]) -> String {
    format!(
        "[{}]",
        rows.iter()
            .map(|row| {
                let external = row
                    .external_similarity
                    .map(|value| format!("{value:.17}"))
                    .unwrap_or_else(|| "null".to_string());
                let native = row
                    .native_similarity
                    .map(|value| format!("{value:.17}"))
                    .unwrap_or_else(|| "null".to_string());
                format!(
                    concat!(
                        "{{",
                        "\"record_id\":{},",
                        "\"node_id\":{},",
                        "\"rank\":{},",
                        "\"hybrid_score\":{:.17},",
                        "\"external_similarity\":{},",
                        "\"native_similarity\":{},",
                        "\"wave_energy\":{:.17},",
                        "\"path_edge_types\":{},",
                        "\"direct_outgoing_edge_types\":{},",
                        "\"trust_maturity\":{},",
                        "\"trust_validity\":{},",
                        "\"external_exact\":{},",
                        "\"native_exact\":{}",
                        "}}"
                    ),
                    json_string(&row.record_id),
                    row.node_id,
                    row.rank,
                    row.hybrid_score,
                    external,
                    native,
                    row.wave_energy,
                    json_u32_array(&row.wave.path_edge_types),
                    json_u32_array(&row.wave.direct_outgoing_edge_types),
                    json_string(row.trust.state.maturity.as_str()),
                    json_string(row.trust.state.validity.as_str()),
                    row.external_exact,
                    row.native_exact,
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn ids_json(rows: &[SemanticEvidenceHit]) -> String {
    format!(
        "[{}]",
        rows.iter()
            .map(|row| json_string(&row.vector.record_id))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    assert_eq!(
        arguments.len(),
        3,
        "usage: semantic_hybrid_v1_probe ROOT REPORT"
    );
    let root = PathBuf::from(&arguments[1]);
    let report_path = PathBuf::from(&arguments[2]);
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();

    let database_root = root.join("database");
    let mut database = DurableDatabase::create(&database_root).unwrap();

    let payloads = [
        ("anchor", b"anchor root knowledge".to_vec()),
        ("b", b"direct verified solution".to_vec()),
        ("c", b"direct hypothesis branch".to_vec()),
        ("d", b"revoked downstream solution".to_vec()),
        ("e", b"raw downstream alternative".to_vec()),
        ("f", b"verified deep evidence".to_vec()),
        ("g", b"isolated semantically similar".to_vec()),
    ];
    let mut ids = BTreeMap::new();
    let mut records = Vec::new();
    for (index, (name, payload)) in payloads.iter().enumerate() {
        let id = record_id(payload);
        let logical_id = (index + 1) as u64;
        let node_id = (index + 1) as u64;
        ids.insert((*name).to_string(), id.clone());
        records.push((logical_id, id, node_id, payload.clone()));
    }
    let edges = vec![
        (101, 1, 2, 1, 0.95),
        (102, 1, 3, 2, 0.90),
        (103, 2, 4, 3, 0.90),
        (104, 3, 5, 4, 0.85),
        (105, 4, 6, 5, 0.80),
        (106, 3, 2, 6, 0.70),
        (107, 2, 1, 1, 0.50),
    ];
    commit_graph(&mut database, &records, &edges);
    database.checkpoint(2).unwrap();

    let canonical_before = database.read_snapshot().descriptor().clone();
    let snapshot = database.read_snapshot();

    let mut inventory = DerivedArtifactInventory::open_or_create(&database_root).unwrap();
    let (graph_index, graph_receipt) =
        GraphSnapshotIndex::materialize(&database_root, &snapshot, &mut inventory).unwrap();
    let reopened_graph = GraphSnapshotIndex::open_verified(&database_root, &snapshot).unwrap();
    assert_eq!(
        graph_index.database_snapshot_sha256(),
        reopened_graph.database_snapshot_sha256()
    );
    assert_eq!(graph_index.record_to_node(&ids["anchor"]), Some(1));

    let mut store = VectorStore::create(&database_root).unwrap();
    let external_descriptor = VectorSpaceDescriptor::external(
        "customer",
        "agent-embedding-model",
        "revision-1",
        "utf8-v1",
        4,
        VectorNormalization::None,
    );
    let (external_space_id, create_outcome) = store.create_space(external_descriptor).unwrap();
    assert_eq!(create_outcome, CreateSpaceOutcome::Created);

    let external_vectors = [
        ("anchor", vec![1.0, 0.0, 0.0, 0.0]),
        ("b", vec![0.95, 0.05, 0.0, 0.0]),
        ("c", vec![0.80, 0.20, 0.0, 0.0]),
        ("d", vec![0.70, 0.30, 0.0, 0.0]),
        ("e", vec![0.0, 1.0, 0.0, 0.0]),
        ("f", vec![0.60, 0.40, 0.0, 0.0]),
        ("g", vec![0.99, 0.01, 0.0, 0.0]),
    ];
    let external_batch = external_vectors
        .iter()
        .map(|(name, vector)| VectorInput::new(ids[*name].clone(), vector.clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        store
            .import_vectors(
                &snapshot,
                external_space_id,
                "external-migration-r4-3",
                &external_batch,
            )
            .unwrap(),
        ImportOutcome::Applied
    );

    let native_config = NativeStructuralConfig::default();
    let first_native = build_native_structural_space(
        &snapshot,
        &graph_index,
        &mut store,
        &mut inventory,
        native_config,
    )
    .unwrap();
    let second_native = build_native_structural_space(
        &snapshot,
        &reopened_graph,
        &mut store,
        &mut inventory,
        native_config,
    )
    .unwrap();
    assert_eq!(first_native.space_id, second_native.space_id);
    assert_eq!(
        second_native.import_outcome,
        ImportOutcome::DuplicateIgnored
    );
    assert_eq!(
        first_native.column_generation,
        second_native.column_generation
    );
    assert_eq!(first_native.column_sha256, second_native.column_sha256);

    let trust_path = root.join("trust.ubtrust");
    let mut trust = TrustLedger::create(&trust_path).unwrap();
    let mut timestamp = 100u64;
    for name in ["anchor", "b", "f", "g"] {
        promote_verified(
            &mut trust,
            &ids[name],
            sha256(
                payloads
                    .iter()
                    .find(|(candidate, _)| candidate == &name)
                    .unwrap()
                    .1
                    .as_slice(),
            ),
            &mut timestamp,
        );
    }
    trust
        .apply(trust_intent(
            &ids["c"],
            sha256(
                payloads
                    .iter()
                    .find(|(name, _)| *name == "c")
                    .unwrap()
                    .1
                    .as_slice(),
            ),
            TrustOperation::Propose,
            TransitionAuthority::Import,
            timestamp,
            "c-propose",
        ))
        .unwrap();
    timestamp += 1;
    trust
        .apply(trust_intent(
            &ids["c"],
            sha256(
                payloads
                    .iter()
                    .find(|(name, _)| *name == "c")
                    .unwrap()
                    .1
                    .as_slice(),
            ),
            TrustOperation::Promote,
            TransitionAuthority::EvidencePolicy,
            timestamp,
            "c-hypothesis",
        ))
        .unwrap();
    timestamp += 1;
    promote_verified(
        &mut trust,
        &ids["d"],
        sha256(
            payloads
                .iter()
                .find(|(name, _)| *name == "d")
                .unwrap()
                .1
                .as_slice(),
        ),
        &mut timestamp,
    );
    trust
        .apply(trust_intent(
            &ids["d"],
            sha256(
                payloads
                    .iter()
                    .find(|(name, _)| *name == "d")
                    .unwrap()
                    .1
                    .as_slice(),
            ),
            TrustOperation::Revoke,
            TransitionAuthority::EvidencePolicy,
            timestamp,
            "d-revoke",
        ))
        .unwrap();
    timestamp += 1;
    trust
        .apply(trust_intent(
            &ids["e"],
            sha256(
                payloads
                    .iter()
                    .find(|(name, _)| *name == "e")
                    .unwrap()
                    .1
                    .as_slice(),
            ),
            TrustOperation::Propose,
            TransitionAuthority::Import,
            timestamp,
            "e-propose",
        ))
        .unwrap();

    let trust_count_before = trust.transition_count();
    let trust_head_before = trust.head_digest();

    let graph_config = GraphScopeConfig {
        max_steps: 3,
        energy_threshold: 0.001,
        candidate_limit: 32,
        edge_mask: u32::MAX,
        rigor_multiplier: 1.0,
    };
    let scope = build_wave_scope(&snapshot, &graph_index, &ids["anchor"], graph_config).unwrap();
    assert!(!scope.candidates.contains_key(&ids["g"]));
    assert!(scope.candidates.contains_key(&ids["b"]));
    assert!(scope.candidates.contains_key(&ids["f"]));

    let query = [1.0f32, 0.0, 0.0, 0.0];
    let topological = query_topological(
        &snapshot,
        &graph_index,
        &ids["anchor"],
        graph_config,
        Some(&trust),
        TrustFilter::Any,
        UnknownTrustPolicy::IncludeAsRawActive,
        16,
    )
    .unwrap();
    let semantic_global = query_semantic_exact(
        &snapshot,
        &store,
        external_space_id,
        &query,
        16,
        None,
        Some(&trust),
        TrustFilter::Any,
        UnknownTrustPolicy::IncludeAsRawActive,
    )
    .unwrap();
    let semantic_scoped = query_semantic_exact(
        &snapshot,
        &store,
        external_space_id,
        &query,
        16,
        Some(&scope),
        Some(&trust),
        TrustFilter::Any,
        UnknownTrustPolicy::IncludeAsRawActive,
    )
    .unwrap();
    let semantic_active = query_semantic_exact(
        &snapshot,
        &store,
        external_space_id,
        &query,
        16,
        Some(&scope),
        Some(&trust),
        TrustFilter::ActiveOnly,
        UnknownTrustPolicy::IncludeAsRawActive,
    )
    .unwrap();

    let weights = HybridWeights {
        external: 1.0,
        native: 1.0,
        wave: 1.0,
    };
    let hybrid_all = query_hybrid(
        &snapshot,
        &store,
        &graph_index,
        &ids["anchor"],
        external_space_id,
        &query,
        first_native.space_id,
        graph_config,
        weights,
        Some(&trust),
        TrustFilter::Any,
        UnknownTrustPolicy::IncludeAsRawActive,
        16,
    )
    .unwrap();
    let hybrid_verified = query_hybrid(
        &snapshot,
        &store,
        &graph_index,
        &ids["anchor"],
        external_space_id,
        &query,
        first_native.space_id,
        graph_config,
        weights,
        Some(&trust),
        TrustFilter::VerifiedActiveOnly,
        UnknownTrustPolicy::IncludeAsRawActive,
        16,
    )
    .unwrap();

    assert!(semantic_global
        .iter()
        .any(|row| row.vector.record_id == ids["g"]));
    assert!(semantic_scoped
        .iter()
        .all(|row| row.vector.record_id != ids["g"]));
    assert!(semantic_active
        .iter()
        .all(|row| row.vector.record_id != ids["d"]));
    assert!(hybrid_verified.iter().all(|row| {
        row.trust.state.maturity == MaturityState::Verified
            && row.trust.state.validity.as_str() == "ACTIVE"
    }));
    assert!(hybrid_verified.iter().any(|row| row.record_id == ids["b"]));
    assert!(hybrid_verified.iter().all(|row| row.record_id != ids["d"]));
    let b_hit = hybrid_all
        .iter()
        .find(|row| row.record_id == ids["b"])
        .unwrap();
    assert!(b_hit.wave.direct_outgoing_edge_types.contains(&1));
    assert!(b_hit.external_similarity.is_some());
    assert!(b_hit.native_similarity.is_some());

    let trust_count_after = trust.transition_count();
    let trust_head_after = trust.head_digest();
    assert_eq!(trust_count_before, trust_count_after);
    assert_eq!(trust_head_before, trust_head_after);

    drop(snapshot);
    let canonical_after = database.read_snapshot().descriptor().clone();
    assert_eq!(canonical_before.state_sha256, canonical_after.state_sha256);
    assert_eq!(
        canonical_before.snapshot_sha256,
        canonical_after.snapshot_sha256
    );

    let inventory_verification = inventory.verify_files().unwrap();
    assert!(inventory_verification.complete_records >= 2);
    assert!(store.verify().unwrap().vector_count >= 14);

    let pass = graph_receipt.record_count == 7
        && graph_receipt.edge_count == 7
        && first_native.record_count == 7
        && second_native.import_outcome == ImportOutcome::DuplicateIgnored
        && trust_count_before == trust_count_after
        && trust_head_before == trust_head_after
        && canonical_before.state_sha256 == canonical_after.state_sha256
        && semantic_global
            .iter()
            .any(|row| row.vector.record_id == ids["g"])
        && semantic_scoped
            .iter()
            .all(|row| row.vector.record_id != ids["g"])
        && hybrid_verified.iter().all(|row| {
            row.trust.state.maturity == MaturityState::Verified
                && row.trust.state.validity.as_str() == "ACTIVE"
        });

    let report = format!(
        concat!(
            "{{\n",
            "  \"schema\": \"ultraballoondb.r4_3.semantic_hybrid_probe.v1\",\n",
            "  \"pass\": {},\n",
            "  \"database_root\": {},\n",
            "  \"database_snapshot_sha256\": {},\n",
            "  \"graph_layout_path\": {},\n",
            "  \"graph_manifest_path\": {},\n",
            "  \"graph_record_count\": {},\n",
            "  \"graph_edge_count\": {},\n",
            "  \"graph_nodes_sha256\": {},\n",
            "  \"graph_edges_sha256\": {},\n",
            "  \"anchor_record_id\": {},\n",
            "  \"node_to_record\": {{",
            "    \"1\": {}, \"2\": {}, \"3\": {}, \"4\": {}, \"5\": {}, \"6\": {}, \"7\": {}",
            "  }},\n",
            "  \"graph_config\": {{",
            "    \"max_steps\": {},",
            "    \"energy_threshold\": {:.17},",
            "    \"candidate_limit\": {},",
            "    \"edge_mask\": {},",
            "    \"rigor_multiplier\": {:.17}",
            "  }},\n",
            "  \"external_space_id\": {},\n",
            "  \"native_space_id\": {},\n",
            "  \"native_config_digest\": {},\n",
            "  \"native_column_generation\": {},\n",
            "  \"native_column_sha256\": {},\n",
            "  \"native_rebuild_duplicate_ignored\": true,\n",
            "  \"query_vector\": [1.0,0.0,0.0,0.0],\n",
            "  \"weights\": {{\"external\":1.0,\"native\":1.0,\"wave\":1.0}},\n",
            "  \"topological_hits\": {},\n",
            "  \"semantic_global_hits\": {},\n",
            "  \"semantic_global_ids\": {},\n",
            "  \"semantic_scoped_hits\": {},\n",
            "  \"semantic_scoped_ids\": {},\n",
            "  \"semantic_active_ids\": {},\n",
            "  \"hybrid_all_hits\": {},\n",
            "  \"hybrid_verified_hits\": {},\n",
            "  \"isolated_record_id\": {},\n",
            "  \"revoked_record_id\": {},\n",
            "  \"verified_direct_record_id\": {},\n",
            "  \"trust_transition_count_before\": {},\n",
            "  \"trust_transition_count_after\": {},\n",
            "  \"trust_head_before\": {},\n",
            "  \"trust_head_after\": {},\n",
            "  \"trust_unchanged\": {},\n",
            "  \"canonical_state_sha256_before\": {},\n",
            "  \"canonical_state_sha256_after\": {},\n",
            "  \"canonical_state_unchanged\": {},\n",
            "  \"inventory_complete_records\": {},\n",
            "  \"canonical_wave_crate_used\": true,\n",
            "  \"duplicate_wave_implementation\": false,\n",
            "  \"trust_in_hybrid_score\": false,\n",
            "  \"trust_transition_from_query\": false,\n",
            "  \"ann_used\": false,\n",
            "  \"gpu_used\": false\n",
            "}}\n"
        ),
        pass,
        json_string(&database_root.to_string_lossy()),
        json_string(&hex_digest(&canonical_before.snapshot_sha256)),
        json_string(&graph_receipt.layout_path.to_string_lossy()),
        json_string(&graph_receipt.manifest_path.to_string_lossy()),
        graph_receipt.record_count,
        graph_receipt.edge_count,
        json_string(&hex_digest(&graph_receipt.nodes_sha256)),
        json_string(&hex_digest(&graph_receipt.edges_sha256)),
        json_string(&ids["anchor"]),
        json_string(&ids["anchor"]),
        json_string(&ids["b"]),
        json_string(&ids["c"]),
        json_string(&ids["d"]),
        json_string(&ids["e"]),
        json_string(&ids["f"]),
        json_string(&ids["g"]),
        graph_config.max_steps,
        graph_config.energy_threshold,
        graph_config.candidate_limit,
        graph_config.edge_mask,
        graph_config.rigor_multiplier,
        json_string(&external_space_id.to_hex()),
        json_string(&first_native.space_id.to_hex()),
        json_string(&hex_digest(&first_native.config_digest)),
        first_native.column_generation,
        json_string(&hex_digest(&first_native.column_sha256)),
        topological_json(&topological),
        semantic_json(&semantic_global),
        ids_json(&semantic_global),
        semantic_json(&semantic_scoped),
        ids_json(&semantic_scoped),
        ids_json(&semantic_active),
        hybrid_json(&hybrid_all),
        hybrid_json(&hybrid_verified),
        json_string(&ids["g"]),
        json_string(&ids["d"]),
        json_string(&ids["b"]),
        trust_count_before,
        trust_count_after,
        json_string(&hex_digest(&trust_head_before)),
        json_string(&hex_digest(&trust_head_after)),
        trust_count_before == trust_count_after && trust_head_before == trust_head_after,
        json_string(&hex_digest(&canonical_before.state_sha256)),
        json_string(&hex_digest(&canonical_after.state_sha256)),
        canonical_before.state_sha256 == canonical_after.state_sha256,
        inventory_verification.complete_records,
    );

    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&report_path, report).unwrap();
    assert!(pass);

    println!("PASS_R4_3_NATIVE_EXTERNAL_SEMANTIC_HYBRID_PROBE");
    println!("REPORT={}", report_path.display());
}
