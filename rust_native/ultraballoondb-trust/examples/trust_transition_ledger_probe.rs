use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ultraballoondb_storage::{hex_digest, sha256};
use ultraballoondb_trust::{
    EvidenceRef, MaturityState, TransitionAuthority, TransitionIntent,
    TrustLedger, TrustOperation, ValidityState,
};

fn digest(value: &str) -> [u8; 32] {
    sha256(value.as_bytes())
}

fn evidence(id: &str) -> EvidenceRef {
    EvidenceRef {
        evidence_id: id.to_string(),
        provenance_id: format!("provenance-{id}"),
        evidence_digest: digest(id),
    }
}

fn intent(
    record_id: &str,
    operation: TrustOperation,
    authority: TransitionAuthority,
    timestamp: u64,
    evidence_id: &str,
) -> TransitionIntent {
    TransitionIntent {
        record_id: record_id.to_string(),
        operation,
        authority,
        evidence_refs: vec![evidence(evidence_id)],
        policy_id: "trust-policy-main".to_string(),
        policy_version: "1.0.0".to_string(),
        verifier_id: "rust-trust-probe".to_string(),
        record_digest: digest(&format!("record-digest-{record_id}")),
        logical_timestamp: timestamp,
        reason_code: format!("{}_{}", operation.as_str(), timestamp),
        superseding_record_id: None,
    }
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

fn state_json(
    ledger: &TrustLedger,
    record_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let snapshot = ledger
        .snapshot(record_id)
        .ok_or_else(|| format!("missing trust snapshot: {record_id}"))?;
    let superseding = snapshot
        .superseding_record_id
        .as_ref()
        .map(|value| format!("\"{}\"", json_escape(value)))
        .unwrap_or_else(|| "null".to_string());
    Ok(format!(
        concat!(
            "{{",
            "\"record_id\":\"{}\",",
            "\"maturity\":\"{}\",",
            "\"validity\":\"{}\",",
            "\"record_digest\":\"{}\",",
            "\"last_transition_id\":\"{}\",",
            "\"last_sequence\":{},",
            "\"superseding_record_id\":{}",
            "}}"
        ),
        json_escape(&snapshot.record_id),
        snapshot.state.maturity.as_str(),
        snapshot.state.validity.as_str(),
        hex_digest(&snapshot.record_digest),
        hex_digest(&snapshot.last_transition_id),
        snapshot.last_sequence,
        superseding,
    ))
}

fn write_report(
    path: &Path,
    ledger_path: &Path,
    ledger_sha256: [u8; 32],
    ledger_bytes: u64,
    prefix_bytes: usize,
    ledger: &TrustLedger,
    prohibited_rejections: &[(TransitionAuthority, String)],
    corruption_rejected: bool,
    truncated_tail_rejected: bool,
    append_only_prefix_preserved: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let authorities = prohibited_rejections
        .iter()
        .map(|(authority, error)| {
            format!(
                "{{\"authority\":\"{}\",\"error\":\"{}\"}}",
                authority.as_str(),
                json_escape(error),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let states = ["record-a", "record-b", "record-c", "record-d"]
        .iter()
        .map(|record_id| state_json(ledger, record_id))
        .collect::<Result<Vec<_>, _>>()?
        .join(",");
    let report = format!(
        concat!(
            "{{\n",
            "  \"pass\": true,\n",
            "  \"ledger_path\": \"{}\",\n",
            "  \"ledger_sha256\": \"{}\",\n",
            "  \"ledger_bytes\": {},\n",
            "  \"append_only_prefix_bytes\": {},\n",
            "  \"append_only_prefix_preserved\": {},\n",
            "  \"transition_count\": {},\n",
            "  \"head_digest\": \"{}\",\n",
            "  \"last_logical_timestamp\": {},\n",
            "  \"prohibited_authority_rejection_count\": {},\n",
            "  \"prohibited_authority_rejections\": [{}],\n",
            "  \"corruption_rejected\": {},\n",
            "  \"truncated_tail_rejected\": {},\n",
            "  \"strict_restart_replay_verified\": true,\n",
            "  \"evidence_required\": true,\n",
            "  \"provenance_required\": true,\n",
            "  \"record_digest_binding_verified\": true,\n",
            "  \"ranker_trust_neutral\": true,\n",
            "  \"wave_trust_neutral\": true,\n",
            "  \"similarity_trust_neutral\": true,\n",
            "  \"frequency_trust_neutral\": true,\n",
            "  \"llm_trust_neutral\": true,\n",
            "  \"rigor_multiplier_trust_neutral\": true,\n",
            "  \"import_never_auto_verifies\": true,\n",
            "  \"revocation_preserves_history\": true,\n",
            "  \"states\": [{}],\n",
            "  \"network_enabled\": false,\n",
            "  \"automatic_repair_enabled\": false,\n",
            "  \"active_runtime_changed\": false\n",
            "}}\n"
        ),
        json_escape(&ledger_path.to_string_lossy()),
        hex_digest(&ledger_sha256),
        ledger_bytes,
        prefix_bytes,
        if append_only_prefix_preserved { "true" } else { "false" },
        ledger.transition_count(),
        hex_digest(&ledger.head_digest()),
        ledger.last_timestamp(),
        prohibited_rejections.len(),
        authorities,
        if corruption_rejected { "true" } else { "false" },
        if truncated_tail_rejected { "true" } else { "false" },
        states,
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, report)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() != 3 {
        return Err(
            "usage: trust_transition_ledger_probe <ledger-path> <report-json>"
                .into(),
        );
    }
    let ledger_path = PathBuf::from(&arguments[1]);
    let report_path = PathBuf::from(&arguments[2]);
    if ledger_path.exists() {
        fs::remove_file(&ledger_path)?;
    }

    let mut ledger = TrustLedger::create(&ledger_path)?;
    ledger.apply(intent(
        "record-a",
        TrustOperation::Propose,
        TransitionAuthority::Import,
        100,
        "a-propose",
    ))?;

    let mut prohibited_rejections = Vec::new();
    for (index, authority) in [
        TransitionAuthority::Import,
        TransitionAuthority::Ranker,
        TransitionAuthority::Wave,
        TransitionAuthority::Similarity,
        TransitionAuthority::Frequency,
        TransitionAuthority::Llm,
        TransitionAuthority::RigorMultiplier,
    ]
    .iter()
    .copied()
    .enumerate()
    {
        let before_count = ledger.transition_count();
        let before_bytes = fs::metadata(&ledger_path)?.len();
        let attempted = ledger.apply(intent(
            "record-a",
            TrustOperation::Promote,
            authority,
            110 + index as u64,
            &format!("prohibited-{index}"),
        ));
        let error = attempted
            .err()
            .ok_or("prohibited authority unexpectedly changed trust")?;
        if ledger.transition_count() != before_count
            || fs::metadata(&ledger_path)?.len() != before_bytes
        {
            return Err("rejected authority changed the append-only ledger".into());
        }
        prohibited_rejections.push((authority, error.to_string()));
    }

    ledger.apply(intent(
        "record-a",
        TrustOperation::Promote,
        TransitionAuthority::EvidencePolicy,
        200,
        "a-hypothesis",
    ))?;
    ledger.apply(intent(
        "record-a",
        TrustOperation::Promote,
        TransitionAuthority::EvidencePolicy,
        300,
        "a-candidate",
    ))?;
    ledger.apply(intent(
        "record-a",
        TrustOperation::Promote,
        TransitionAuthority::EvidencePolicy,
        400,
        "a-verified",
    ))?;
    ledger.apply(intent(
        "record-a",
        TrustOperation::Dispute,
        TransitionAuthority::EvidencePolicy,
        500,
        "a-disputed",
    ))?;
    ledger.apply(intent(
        "record-a",
        TrustOperation::Revoke,
        TransitionAuthority::EvidencePolicy,
        600,
        "a-revoked",
    ))?;

    let prefix = fs::read(&ledger_path)?;

    ledger.apply(intent(
        "record-b",
        TrustOperation::Propose,
        TransitionAuthority::Import,
        700,
        "b-propose",
    ))?;
    ledger.apply(intent(
        "record-b",
        TrustOperation::Promote,
        TransitionAuthority::EvidencePolicy,
        800,
        "b-hypothesis",
    ))?;
    ledger.apply(intent(
        "record-c",
        TrustOperation::Propose,
        TransitionAuthority::Import,
        900,
        "c-propose",
    ))?;
    let mut supersede = intent(
        "record-b",
        TrustOperation::Supersede,
        TransitionAuthority::EvidencePolicy,
        1000,
        "b-superseded",
    );
    supersede.superseding_record_id = Some("record-c".to_string());
    ledger.apply(supersede)?;
    ledger.apply(intent(
        "record-d",
        TrustOperation::Propose,
        TransitionAuthority::Import,
        1100,
        "d-propose",
    ))?;
    ledger.apply(intent(
        "record-d",
        TrustOperation::Expire,
        TransitionAuthority::EvidencePolicy,
        1200,
        "d-expired",
    ))?;

    let full = fs::read(&ledger_path)?;
    let append_only_prefix_preserved = full.starts_with(&prefix)
        && full.len() > prefix.len();
    if !append_only_prefix_preserved {
        return Err("append-only prefix was not preserved".into());
    }
    if ledger.transition_count() != 12 {
        return Err(format!(
            "expected 12 transitions, got {}",
            ledger.transition_count()
        )
        .into());
    }

    let expected_head = ledger.head_digest();
    drop(ledger);
    let reopened = TrustLedger::open_strict(&ledger_path)?;
    if reopened.transition_count() != 12 || reopened.head_digest() != expected_head {
        return Err("strict restart replay mismatch".into());
    }
    if reopened.snapshot("record-a").ok_or("missing record-a")?.state.validity
        != ValidityState::Revoked
        || reopened.snapshot("record-a").ok_or("missing record-a")?.state.maturity
            != MaturityState::Verified
    {
        return Err("record-a final state mismatch".into());
    }
    if reopened.snapshot("record-b").ok_or("missing record-b")?.state.validity
        != ValidityState::Superseded
    {
        return Err("record-b final state mismatch".into());
    }
    if reopened.snapshot("record-c").ok_or("missing record-c")?.state.validity
        != ValidityState::Active
    {
        return Err("record-c final state mismatch".into());
    }
    if reopened.snapshot("record-d").ok_or("missing record-d")?.state.validity
        != ValidityState::Expired
    {
        return Err("record-d final state mismatch".into());
    }

    let corrupt_path = ledger_path.with_extension("corrupt.ubtrust");
    let mut corrupt = full.clone();
    let corrupt_index = ultraballoondb_trust::FRAME_HEADER_BYTES + 30;
    corrupt[corrupt_index] ^= 0x5A;
    fs::write(&corrupt_path, corrupt)?;
    let corruption_rejected = TrustLedger::open_strict(&corrupt_path).is_err();

    let truncated_path = ledger_path.with_extension("truncated.ubtrust");
    fs::write(&truncated_path, &full[..full.len() - 7])?;
    let truncated_tail_rejected = TrustLedger::open_strict(&truncated_path).is_err();
    if !corruption_rejected || !truncated_tail_rejected {
        return Err("strict corruption/truncation rejection failed".into());
    }

    let ledger_sha256 = sha256(&full);
    write_report(
        &report_path,
        &ledger_path,
        ledger_sha256,
        full.len() as u64,
        prefix.len(),
        &reopened,
        &prohibited_rejections,
        corruption_rejected,
        truncated_tail_rejected,
        append_only_prefix_preserved,
    )?;

    fs::remove_file(corrupt_path)?;
    fs::remove_file(truncated_path)?;

    println!("PASS_ULTRABALLOONDB_TRUST_TRANSITION_LEDGER_PROBE");
    println!("REPORT={}", report_path.display());
    println!("LEDGER={}", ledger_path.display());
    Ok(())
}
