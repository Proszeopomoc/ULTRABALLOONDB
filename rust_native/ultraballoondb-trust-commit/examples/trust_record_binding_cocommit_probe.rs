use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ultraballoondb_lifecycle::{
    BatchLimits, DurableDatabase, TransactionCore, TransactionId,
};
use ultraballoondb_storage::{hex_digest, sha256};
use ultraballoondb_trust::{
    EvidenceRef, TransitionAuthority, TrustLedger, TrustOperation,
};
use ultraballoondb_trust_commit::{
    CommitProbeOutcome, PolicyDefinition, PolicyRegistry, ProbeStop,
    TrustCommitCoordinator, TrustCommitJournal, TrustCommitRequest,
    BINDING_RECORD_PREFIX,
};

fn evidence(id: &str, provenance: &str) -> EvidenceRef {
    EvidenceRef {
        evidence_id: id.to_string(),
        provenance_id: provenance.to_string(),
        evidence_digest: sha256(
            format!("{id}:{provenance}").as_bytes(),
        ),
    }
}

fn request(
    record_id: &str,
    operation: TrustOperation,
    authority: TransitionAuthority,
    evidence_refs: Vec<EvidenceRef>,
    policy_id: &str,
    policy_version: &str,
    verifier_id: &str,
    logical_timestamp: u64,
    reason_code: &str,
    superseding_record_id: Option<&str>,
) -> TrustCommitRequest {
    TrustCommitRequest {
        record_id: record_id.to_string(),
        operation,
        authority,
        evidence_refs,
        policy_id: policy_id.to_string(),
        policy_version: policy_version.to_string(),
        verifier_id: verifier_id.to_string(),
        logical_timestamp,
        reason_code: reason_code.to_string(),
        superseding_record_id: superseding_record_id.map(str::to_string),
    }
}

fn put_records(
    database_root: &Path,
    values: &[(&str, u64, &[u8])],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut database = if database_root.exists() {
        DurableDatabase::open(database_root, false)?
    } else {
        DurableDatabase::create(database_root)?
    };
    let generation = database.next_generation()?;
    let sequence = database.next_segment_sequence()?;
    let mut transaction_bytes = [0u8; 16];
    transaction_bytes[0..8].copy_from_slice(
        &generation.to_le_bytes(),
    );
    transaction_bytes[8..16].copy_from_slice(
        &sequence.to_le_bytes(),
    );
    let transaction_id = TransactionId::new(transaction_bytes);
    let mut core = TransactionCore::new(BatchLimits::default());
    core.begin(transaction_id)?;
    for (index, (record_id, node_id, payload)) in
        values.iter().enumerate()
    {
        let logical_id = sha256(record_id.as_bytes());
        let mut id = u64::from_le_bytes(
            logical_id[0..8].try_into().expect("fixed slice"),
        );
        if id == 0 {
            id = (index as u64) + 1;
        }
        core.put_record(id, record_id, *node_id, payload)?;
    }
    core.prepare()?;
    core.commit_durable(&mut database, generation, sequence)?;
    core.release_terminal(transaction_id)?;
    database.checkpoint(generation)?;
    Ok(())
}

fn file_sha(path: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(sha256(&fs::read(path)?))
}

fn corrupt_copy(
    source: &Path,
    destination: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = fs::read(source)?;
    if bytes.len() < 180 {
        return Err("source too short for corruption test".into());
    }
    let corrupt_index = bytes.len() / 2;
    bytes[corrupt_index] ^= 0x5A;
    fs::write(destination, bytes)?;
    Ok(())
}

fn truncate_copy(
    source: &Path,
    destination: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = fs::read(source)?;
    if bytes.len() < 17 {
        return Err("source too short for truncation test".into());
    }
    bytes.truncate(bytes.len() - 7);
    fs::write(destination, bytes)?;
    Ok(())
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
                    .expect("writing to String");
            }
            character => output.push(character),
        }
    }
    output
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() != 3 {
        return Err(
            "usage: trust_record_binding_cocommit_probe <root> <report-json>"
                .into(),
        );
    }
    let root = PathBuf::from(&arguments[1]);
    let report_path = PathBuf::from(&arguments[2]);
    if root.exists() {
        fs::remove_dir_all(&root)?;
    }
    fs::create_dir_all(&root)?;

    let database_root = root.join("database");
    let trust_path = root.join("trust").join("trust.ubtrust");
    let policy_path = root.join("trust").join("policies.ubpolicy");
    let journal_path = root.join("trust").join("commit.ubcommit");

    put_records(
        &database_root,
        &[
            ("alpha-record", 1001, b"alpha-payload-v1"),
            ("beta-record", 2002, b"beta-payload-v1"),
            ("gamma-record", 3003, b"gamma-payload-v1"),
        ],
    )?;

    TrustLedger::create(&trust_path)?;
    TrustCommitJournal::create(&journal_path)?;
    let mut policies = PolicyRegistry::create(&policy_path)?;

    let import_digest = policies.register(PolicyDefinition {
        policy_id: "import-policy".to_string(),
        policy_version: "1".to_string(),
        allowed_authority: TransitionAuthority::Import,
        allowed_operation_mask: PolicyDefinition::operation_mask(
            &[TrustOperation::Propose],
        ),
        min_evidence_refs: 1,
        max_evidence_refs: 2,
        required_verifier_id: "import-verifier".to_string(),
        require_unique_provenance: false,
    })?;
    let promote_digest = policies.register(PolicyDefinition {
        policy_id: "promotion-policy".to_string(),
        policy_version: "1".to_string(),
        allowed_authority: TransitionAuthority::EvidencePolicy,
        allowed_operation_mask: PolicyDefinition::operation_mask(
            &[TrustOperation::Promote],
        ),
        min_evidence_refs: 2,
        max_evidence_refs: 4,
        required_verifier_id: "promotion-verifier".to_string(),
        require_unique_provenance: true,
    })?;
    let validity_digest = policies.register(PolicyDefinition {
        policy_id: "validity-policy".to_string(),
        policy_version: "1".to_string(),
        allowed_authority: TransitionAuthority::EvidencePolicy,
        allowed_operation_mask: PolicyDefinition::operation_mask(&[
            TrustOperation::Dispute,
            TrustOperation::Revoke,
            TrustOperation::Expire,
        ]),
        min_evidence_refs: 1,
        max_evidence_refs: 4,
        required_verifier_id: "validity-verifier".to_string(),
        require_unique_provenance: false,
    })?;
    let supersede_digest = policies.register(PolicyDefinition {
        policy_id: "supersede-policy".to_string(),
        policy_version: "1".to_string(),
        allowed_authority: TransitionAuthority::EvidencePolicy,
        allowed_operation_mask: PolicyDefinition::operation_mask(
            &[TrustOperation::Supersede],
        ),
        min_evidence_refs: 2,
        max_evidence_refs: 4,
        required_verifier_id: "supersede-verifier".to_string(),
        require_unique_provenance: true,
    })?;

    let neutral_policy_rejected = policies
        .register(PolicyDefinition {
            policy_id: "ranker-policy".to_string(),
            policy_version: "1".to_string(),
            allowed_authority: TransitionAuthority::Ranker,
            allowed_operation_mask: PolicyDefinition::operation_mask(
                &[TrustOperation::Promote],
            ),
            min_evidence_refs: 1,
            max_evidence_refs: 1,
            required_verifier_id: "ranker".to_string(),
            require_unique_provenance: false,
        })
        .is_err();
    if !neutral_policy_rejected {
        return Err("trust-neutral policy registration was accepted".into());
    }

    let policy_prefix = fs::read(&policy_path)?;
    drop(policies);

    let mut coordinator = TrustCommitCoordinator::open_strict(
        &database_root,
        &trust_path,
        &policy_path,
        &journal_path,
    )?;

    coordinator.commit(request(
        "alpha-record",
        TrustOperation::Propose,
        TransitionAuthority::Import,
        vec![evidence("alpha-import", "source-A")],
        "import-policy",
        "1",
        "import-verifier",
        10,
        "IMPORTED",
        None,
    ))?;
    coordinator.commit(request(
        "beta-record",
        TrustOperation::Propose,
        TransitionAuthority::Import,
        vec![evidence("beta-import", "source-B")],
        "import-policy",
        "1",
        "import-verifier",
        20,
        "IMPORTED",
        None,
    ))?;
    coordinator.commit(request(
        "alpha-record",
        TrustOperation::Promote,
        TransitionAuthority::EvidencePolicy,
        vec![
            evidence("alpha-h1", "lab-A"),
            evidence("alpha-h2", "lab-B"),
        ],
        "promotion-policy",
        "1",
        "promotion-verifier",
        30,
        "RAW_TO_HYPOTHESIS",
        None,
    ))?;

    let journal_prefix = fs::read(&journal_path)?;

    let stopped_prepared = coordinator.commit_for_probe(
        request(
            "beta-record",
            TrustOperation::Promote,
            TransitionAuthority::EvidencePolicy,
            vec![
                evidence("beta-p1", "lab-A"),
                evidence("beta-p2", "lab-B"),
            ],
            "promotion-policy",
            "1",
            "promotion-verifier",
            40,
            "PROBE_ABORT",
            None,
        ),
        ProbeStop::AfterPrepared,
    )?;
    if !matches!(
        stopped_prepared,
        CommitProbeOutcome::Stopped { .. }
    ) {
        return Err("AfterPrepared probe did not stop".into());
    }
    drop(coordinator);

    let mut coordinator = TrustCommitCoordinator::open_strict(
        &database_root,
        &trust_path,
        &policy_path,
        &journal_path,
    )?;
    if coordinator
        .last_recovery_receipt()
        .aborted_prepared_count
        != 1
    {
        return Err("PREPARED-only recovery did not abort".into());
    }

    let stopped_database = coordinator.commit_for_probe(
        request(
            "alpha-record",
            TrustOperation::Promote,
            TransitionAuthority::EvidencePolicy,
            vec![
                evidence("alpha-c1", "lab-C"),
                evidence("alpha-c2", "lab-D"),
            ],
            "promotion-policy",
            "1",
            "promotion-verifier",
            50,
            "HYPOTHESIS_TO_CANDIDATE",
            None,
        ),
        ProbeStop::AfterDatabaseCommitted,
    )?;
    if !matches!(
        stopped_database,
        CommitProbeOutcome::Stopped { .. }
    ) {
        return Err("AfterDatabaseCommitted probe did not stop".into());
    }
    drop(coordinator);

    let mut coordinator = TrustCommitCoordinator::open_strict(
        &database_root,
        &trust_path,
        &policy_path,
        &journal_path,
    )?;
    if coordinator
        .last_recovery_receipt()
        .trust_transition_applied_count
        != 1
        || coordinator
            .last_recovery_receipt()
            .finalized_count
            != 1
    {
        return Err("database-committed recovery did not finish".into());
    }

    let stopped_trust = coordinator.commit_for_probe(
        request(
            "alpha-record",
            TrustOperation::Promote,
            TransitionAuthority::EvidencePolicy,
            vec![
                evidence("alpha-v1", "lab-E"),
                evidence("alpha-v2", "lab-F"),
            ],
            "promotion-policy",
            "1",
            "promotion-verifier",
            60,
            "CANDIDATE_TO_VERIFIED",
            None,
        ),
        ProbeStop::AfterTrustApplied,
    )?;
    if !matches!(
        stopped_trust,
        CommitProbeOutcome::Stopped { .. }
    ) {
        return Err("AfterTrustApplied probe did not stop".into());
    }
    drop(coordinator);

    let mut coordinator = TrustCommitCoordinator::open_strict(
        &database_root,
        &trust_path,
        &policy_path,
        &journal_path,
    )?;
    if coordinator
        .last_recovery_receipt()
        .trust_stage_reconstructed_count
        != 1
        || coordinator
            .last_recovery_receipt()
            .finalized_count
            != 1
    {
        return Err("trust-applied recovery did not finish".into());
    }

    coordinator.commit(request(
        "beta-record",
        TrustOperation::Dispute,
        TransitionAuthority::EvidencePolicy,
        vec![evidence("beta-dispute", "review-A")],
        "validity-policy",
        "1",
        "validity-verifier",
        70,
        "CONTRADICTION",
        None,
    ))?;
    coordinator.commit(request(
        "beta-record",
        TrustOperation::Supersede,
        TransitionAuthority::EvidencePolicy,
        vec![
            evidence("beta-super-1", "review-B"),
            evidence("beta-super-2", "review-C"),
        ],
        "supersede-policy",
        "1",
        "supersede-verifier",
        80,
        "SUPERSEDED_BY_ALPHA",
        Some("alpha-record"),
    ))?;
    coordinator.commit(request(
        "gamma-record",
        TrustOperation::Propose,
        TransitionAuthority::Import,
        vec![evidence("gamma-import", "source-C")],
        "import-policy",
        "1",
        "import-verifier",
        90,
        "IMPORTED",
        None,
    ))?;

    let unknown_policy_rejected = coordinator
        .commit(request(
            "gamma-record",
            TrustOperation::Promote,
            TransitionAuthority::EvidencePolicy,
            vec![
                evidence("gamma-x1", "lab-G"),
                evidence("gamma-x2", "lab-H"),
            ],
            "missing-policy",
            "1",
            "promotion-verifier",
            100,
            "UNKNOWN_POLICY",
            None,
        ))
        .is_err();
    let wrong_verifier_rejected = coordinator
        .commit(request(
            "gamma-record",
            TrustOperation::Promote,
            TransitionAuthority::EvidencePolicy,
            vec![
                evidence("gamma-v1", "lab-G"),
                evidence("gamma-v2", "lab-H"),
            ],
            "promotion-policy",
            "1",
            "wrong-verifier",
            100,
            "WRONG_VERIFIER",
            None,
        ))
        .is_err();
    let insufficient_evidence_rejected = coordinator
        .commit(request(
            "gamma-record",
            TrustOperation::Promote,
            TransitionAuthority::EvidencePolicy,
            vec![evidence("gamma-e1", "lab-G")],
            "promotion-policy",
            "1",
            "promotion-verifier",
            100,
            "INSUFFICIENT_EVIDENCE",
            None,
        ))
        .is_err();
    let duplicate_provenance_rejected = coordinator
        .commit(request(
            "gamma-record",
            TrustOperation::Promote,
            TransitionAuthority::EvidencePolicy,
            vec![
                evidence("gamma-p1", "same-provenance"),
                evidence("gamma-p2", "same-provenance"),
            ],
            "promotion-policy",
            "1",
            "promotion-verifier",
            100,
            "DUPLICATE_PROVENANCE",
            None,
        ))
        .is_err();

    if !unknown_policy_rejected
        || !wrong_verifier_rejected
        || !insufficient_evidence_rejected
        || !duplicate_provenance_rejected
    {
        return Err("policy rejection matrix failed".into());
    }

    let alpha = coordinator
        .trust_ledger()
        .snapshot("alpha-record")
        .ok_or("alpha trust snapshot missing")?
        .clone();
    let beta = coordinator
        .trust_ledger()
        .snapshot("beta-record")
        .ok_or("beta trust snapshot missing")?
        .clone();
    if alpha.state.maturity.as_str() != "VERIFIED"
        || alpha.state.validity.as_str() != "ACTIVE"
        || beta.state.validity.as_str() != "SUPERSEDED"
    {
        return Err("final alpha/beta trust states mismatch".into());
    }

    drop(coordinator);
    put_records(
        &database_root,
        &[("gamma-record", 3333, b"gamma-payload-v2")],
    )?;
    let mut coordinator = TrustCommitCoordinator::open_strict(
        &database_root,
        &trust_path,
        &policy_path,
        &journal_path,
    )?;
    let record_drift_rejected = coordinator
        .commit(request(
            "gamma-record",
            TrustOperation::Promote,
            TransitionAuthority::EvidencePolicy,
            vec![
                evidence("gamma-d1", "lab-I"),
                evidence("gamma-d2", "lab-J"),
            ],
            "promotion-policy",
            "1",
            "promotion-verifier",
            100,
            "RECORD_DRIFT",
            None,
        ))
        .is_err();
    if !record_drift_rejected {
        return Err("record digest drift was accepted".into());
    }

    let transitions = coordinator.trust_ledger().transition_count();
    let journal_entries = coordinator.commit_journal().entry_count();
    let policy_count = coordinator.policy_registry().policy_count();
    let database_records = coordinator.database().records()?;
    let binding_count = database_records
        .iter()
        .filter(|record| {
            record.record_id.starts_with(BINDING_RECORD_PREFIX)
        })
        .count();

    if transitions != 8
        || journal_entries != 34
        || policy_count != 4
        || binding_count != 8
    {
        return Err(format!(
            "final counts mismatch: transitions={transitions} journal={journal_entries} policies={policy_count} bindings={binding_count}",
        )
        .into());
    }

    let policy_bytes = fs::read(&policy_path)?;
    let journal_bytes = fs::read(&journal_path)?;
    if !policy_bytes.starts_with(&policy_prefix)
        || !journal_bytes.starts_with(&journal_prefix)
    {
        return Err("append-only prefix was not preserved".into());
    }

    let corrupt_policy = root.join("corrupt-policy.ubpolicy");
    let truncated_policy = root.join("truncated-policy.ubpolicy");
    let corrupt_journal = root.join("corrupt-journal.ubcommit");
    let truncated_journal = root.join("truncated-journal.ubcommit");
    corrupt_copy(&policy_path, &corrupt_policy)?;
    truncate_copy(&policy_path, &truncated_policy)?;
    corrupt_copy(&journal_path, &corrupt_journal)?;
    truncate_copy(&journal_path, &truncated_journal)?;

    let policy_corruption_rejected =
        PolicyRegistry::open_strict(&corrupt_policy).is_err();
    let policy_truncation_rejected =
        PolicyRegistry::open_strict(&truncated_policy).is_err();
    let journal_corruption_rejected =
        TrustCommitJournal::open_strict(&corrupt_journal).is_err();
    let journal_truncation_rejected =
        TrustCommitJournal::open_strict(&truncated_journal).is_err();
    if !policy_corruption_rejected
        || !policy_truncation_rejected
        || !journal_corruption_rejected
        || !journal_truncation_rejected
    {
        return Err("strict corruption/truncation rejection failed".into());
    }

    let trust_sha = file_sha(&trust_path)?;
    let policy_sha = file_sha(&policy_path)?;
    let journal_sha = file_sha(&journal_path)?;
    let database_state_sha = coordinator.database().state_sha256();
    let report = format!(
        concat!(
            "{{\n",
            "  \"pass\": true,\n",
            "  \"database_root\": \"{}\",\n",
            "  \"trust_ledger_path\": \"{}\",\n",
            "  \"policy_registry_path\": \"{}\",\n",
            "  \"commit_journal_path\": \"{}\",\n",
            "  \"policy_count\": {},\n",
            "  \"policy_frame_count\": {},\n",
            "  \"trust_transition_count\": {},\n",
            "  \"commit_journal_entry_count\": {},\n",
            "  \"finalized_transaction_count\": 8,\n",
            "  \"aborted_transaction_count\": 1,\n",
            "  \"database_binding_record_count\": {},\n",
            "  \"import_policy_digest\": \"{}\",\n",
            "  \"promotion_policy_digest\": \"{}\",\n",
            "  \"validity_policy_digest\": \"{}\",\n",
            "  \"supersede_policy_digest\": \"{}\",\n",
            "  \"policy_registry_sha256\": \"{}\",\n",
            "  \"policy_registry_head_digest\": \"{}\",\n",
            "  \"trust_ledger_sha256\": \"{}\",\n",
            "  \"trust_ledger_head_digest\": \"{}\",\n",
            "  \"commit_journal_sha256\": \"{}\",\n",
            "  \"commit_journal_head_digest\": \"{}\",\n",
            "  \"database_state_sha256\": \"{}\",\n",
            "  \"alpha_maturity\": \"{}\",\n",
            "  \"alpha_validity\": \"{}\",\n",
            "  \"beta_validity\": \"{}\",\n",
            "  \"prepared_only_aborted\": true,\n",
            "  \"database_committed_recovered\": true,\n",
            "  \"trust_applied_marker_recovered\": true,\n",
            "  \"unknown_policy_rejected\": {},\n",
            "  \"wrong_verifier_rejected\": {},\n",
            "  \"insufficient_evidence_rejected\": {},\n",
            "  \"duplicate_provenance_rejected\": {},\n",
            "  \"trust_neutral_policy_rejected\": {},\n",
            "  \"record_digest_drift_rejected\": {},\n",
            "  \"append_only_prefix_preserved\": true,\n",
            "  \"policy_corruption_rejected\": {},\n",
            "  \"policy_truncation_rejected\": {},\n",
            "  \"journal_corruption_rejected\": {},\n",
            "  \"journal_truncation_rejected\": {},\n",
            "  \"automatic_repair_enabled\": false,\n",
            "  \"network_enabled\": false,\n",
            "  \"active_runtime_changed\": false\n",
            "}}\n"
        ),
        json_escape(&database_root.to_string_lossy()),
        json_escape(&trust_path.to_string_lossy()),
        json_escape(&policy_path.to_string_lossy()),
        json_escape(&journal_path.to_string_lossy()),
        policy_count,
        coordinator.policy_registry().frame_count(),
        transitions,
        journal_entries,
        binding_count,
        hex_digest(&import_digest),
        hex_digest(&promote_digest),
        hex_digest(&validity_digest),
        hex_digest(&supersede_digest),
        hex_digest(&policy_sha),
        hex_digest(&coordinator.policy_registry().head_digest()),
        hex_digest(&trust_sha),
        hex_digest(&coordinator.trust_ledger().head_digest()),
        hex_digest(&journal_sha),
        hex_digest(&coordinator.commit_journal().head_digest()),
        hex_digest(&database_state_sha),
        alpha.state.maturity.as_str(),
        alpha.state.validity.as_str(),
        beta.state.validity.as_str(),
        unknown_policy_rejected,
        wrong_verifier_rejected,
        insufficient_evidence_rejected,
        duplicate_provenance_rejected,
        neutral_policy_rejected,
        record_drift_rejected,
        policy_corruption_rejected,
        policy_truncation_rejected,
        journal_corruption_rejected,
        journal_truncation_rejected,
    );

    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&report_path, report)?;
    println!(
        "PASS_ULTRABALLOONDB_TRUST_RECORD_BINDING_POLICY_COCOMMIT_PROBE"
    );
    println!("REPORT={}", report_path.display());
    Ok(())
}
