use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ultraballoondb_lifecycle::{
    BatchLimits, DurableDatabase, TransactionCore, TransactionId,
};
use ultraballoondb_storage::{hex_digest, sha256};
use ultraballoondb_trust_auth::{
    run_cli, signed_trust_request_digest, AuthorizationLedger, KeyRegistry,
    TrustPaths, DOMAIN_TRUST_COMMIT, ROLE_ALL, ROLE_TRUST_OPERATOR,
};
use ultraballoondb_trust_commit::{
    PolicyRegistry, TrustCommitJournal,
};
use ultraballoondb_trust::TrustLedger;

fn secret(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn write_secret(path: &Path, value: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, value)?;
    Ok(())
}

fn execute(arguments: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let mut values = vec!["ultraballoondb-trust".to_string()];
    values.extend(arguments.iter().map(|value| value.to_string()));
    let output = run_cli(values)?;
    if !output.contains("\"ok\":true") {
        return Err(format!("CLI output is not successful: {output}").into());
    }
    Ok(output)
}

fn expect_error(arguments: &[&str]) -> bool {
    let mut values = vec!["ultraballoondb-trust".to_string()];
    values.extend(arguments.iter().map(|value| value.to_string()));
    run_cli(values).is_err()
}

fn put_records(
    database_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut database = DurableDatabase::create(database_root)?;
    let generation = database.next_generation()?;
    let sequence = database.next_segment_sequence()?;
    let transaction_id = TransactionId::new(
        *b"T3-INITIAL-DB001",
    );
    let mut core = TransactionCore::new(BatchLimits::default());
    core.begin(transaction_id)?;
    core.put_record(
        1001,
        "alpha-record",
        2001,
        b"alpha-payload-v1",
    )?;
    core.put_record(
        1002,
        "beta-record",
        2002,
        b"beta-payload-v1",
    )?;
    core.prepare()?;
    core.commit_durable(&mut database, generation, sequence)?;
    core.release_terminal(transaction_id)?;
    database.checkpoint(generation)?;
    Ok(())
}

fn evidence_line(
    evidence_id: &str,
    provenance_id: &str,
) -> String {
    format!(
        "{}\t{}\t{}\n",
        evidence_id,
        provenance_id,
        hex_digest(&sha256(
            format!("{evidence_id}:{provenance_id}").as_bytes(),
        )),
    )
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
                    .expect("write to String");
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
            "usage: trust_authorization_cli_probe <root> <report-json>"
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
    let trust_root = root.join("trust");
    let root_key_path = root.join("root.key");
    let operator_key_path = root.join("operator.key");
    let auditor_key_path = root.join("auditor.key");
    let wrong_key_path = root.join("wrong.key");
    let alpha_import_evidence = root.join("alpha-import.tsv");
    let beta_import_evidence = root.join("beta-import.tsv");
    let alpha_promote_evidence = root.join("alpha-promote.tsv");

    put_records(&database_root)?;
    write_secret(&root_key_path, &secret(0x11))?;
    write_secret(&operator_key_path, &secret(0x22))?;
    write_secret(&auditor_key_path, &secret(0x33))?;
    write_secret(&wrong_key_path, &secret(0x44))?;
    fs::write(
        &alpha_import_evidence,
        evidence_line("alpha-import", "source-A"),
    )?;
    fs::write(
        &beta_import_evidence,
        evidence_line("beta-import", "source-B"),
    )?;
    fs::write(
        &alpha_promote_evidence,
        evidence_line("alpha-promote-1", "lab-A")
            + &evidence_line("alpha-promote-2", "lab-B"),
    )?;

    let db = database_root.to_string_lossy().to_string();
    let trust = trust_root.to_string_lossy().to_string();
    let root_key = root_key_path.to_string_lossy().to_string();
    let operator_key = operator_key_path.to_string_lossy().to_string();
    let auditor_key = auditor_key_path.to_string_lossy().to_string();

    let init_output = execute(&[
        "trust-init",
        "--db", &db,
        "--trust-root", &trust,
    ])?;

    let bootstrap_output = execute(&[
        "trust-key-bootstrap",
        "--trust-root", &trust,
        "--key-id", "root-admin",
        "--role-mask", &ROLE_ALL.to_string(),
        "--key-file", &root_key,
        "--logical-timestamp", "10",
        "--nonce", "key-nonce-10",
    ])?;

    let register_operator_output = execute(&[
        "trust-key-register",
        "--trust-root", &trust,
        "--new-key-id", "operator",
        "--new-role-mask", &ROLE_TRUST_OPERATOR.to_string(),
        "--new-key-file", &operator_key,
        "--signer-key-id", "root-admin",
        "--signer-key-file", &root_key,
        "--logical-timestamp", "20",
        "--nonce", "key-nonce-20",
    ])?;

    let register_auditor_output = execute(&[
        "trust-key-register",
        "--trust-root", &trust,
        "--new-key-id", "auditor",
        "--new-role-mask", "8",
        "--new-key-file", &auditor_key,
        "--signer-key-id", "root-admin",
        "--signer-key-file", &root_key,
        "--logical-timestamp", "30",
        "--nonce", "key-nonce-30",
    ])?;

    let import_policy_output = execute(&[
        "trust-policy-register",
        "--trust-root", &trust,
        "--policy-id", "import-policy",
        "--policy-version", "1",
        "--authority", "IMPORT",
        "--operation-mask", "1",
        "--min-evidence", "1",
        "--max-evidence", "2",
        "--verifier-id", "import-verifier",
        "--unique-provenance", "false",
        "--signer-key-id", "root-admin",
        "--signer-key-file", &root_key,
        "--authorization-timestamp", "100",
        "--nonce", "auth-nonce-100",
    ])?;

    let promote_policy_output = execute(&[
        "trust-policy-register",
        "--trust-root", &trust,
        "--policy-id", "promotion-policy",
        "--policy-version", "1",
        "--authority", "EVIDENCE_POLICY",
        "--operation-mask", "2",
        "--min-evidence", "2",
        "--max-evidence", "4",
        "--verifier-id", "promotion-verifier",
        "--unique-provenance", "true",
        "--signer-key-id", "root-admin",
        "--signer-key-file", &root_key,
        "--authorization-timestamp", "110",
        "--nonce", "auth-nonce-110",
    ])?;

    let alpha_import_path =
        alpha_import_evidence.to_string_lossy().to_string();
    let beta_import_path =
        beta_import_evidence.to_string_lossy().to_string();
    let alpha_promote_path =
        alpha_promote_evidence.to_string_lossy().to_string();

    let alpha_propose_output = execute(&[
        "trust-commit",
        "--db", &db,
        "--trust-root", &trust,
        "--record-id", "alpha-record",
        "--operation", "PROPOSE",
        "--authority", "IMPORT",
        "--evidence-file", &alpha_import_path,
        "--policy-id", "import-policy",
        "--policy-version", "1",
        "--verifier-id", "import-verifier",
        "--logical-timestamp", "1000",
        "--reason-code", "IMPORTED",
        "--signer-key-id", "operator",
        "--signer-key-file", &operator_key,
        "--authorization-timestamp", "120",
        "--nonce", "auth-nonce-120",
    ])?;

    let beta_propose_output = execute(&[
        "trust-commit",
        "--db", &db,
        "--trust-root", &trust,
        "--record-id", "beta-record",
        "--operation", "PROPOSE",
        "--authority", "IMPORT",
        "--evidence-file", &beta_import_path,
        "--policy-id", "import-policy",
        "--policy-version", "1",
        "--verifier-id", "import-verifier",
        "--logical-timestamp", "1010",
        "--reason-code", "IMPORTED",
        "--signer-key-id", "operator",
        "--signer-key-file", &operator_key,
        "--authorization-timestamp", "130",
        "--nonce", "auth-nonce-130",
    ])?;

    let alpha_promote_arguments = [
        "trust-commit",
        "--db", &db,
        "--trust-root", &trust,
        "--record-id", "alpha-record",
        "--operation", "PROMOTE",
        "--authority", "EVIDENCE_POLICY",
        "--evidence-file", &alpha_promote_path,
        "--policy-id", "promotion-policy",
        "--policy-version", "1",
        "--verifier-id", "promotion-verifier",
        "--logical-timestamp", "1020",
        "--reason-code", "RAW_TO_HYPOTHESIS",
        "--signer-key-id", "operator",
        "--signer-key-file", &operator_key,
        "--authorization-timestamp", "140",
        "--nonce", "auth-nonce-140",
    ];
    let alpha_promote_output = execute(&alpha_promote_arguments)?;
    let alpha_promote_retry = execute(&alpha_promote_arguments)?;
    if !alpha_promote_retry.contains("\"changed\":false") {
        return Err("authorized trust retry was not idempotent".into());
    }

    let paths = TrustPaths::from_root(&trust_root);
    let registry_before_revoke =
        KeyRegistry::open_strict(&paths.key_registry)?;
    let wrong_secret_rejected = registry_before_revoke.authorize(
        DOMAIN_TRUST_COMMIT,
        ROLE_TRUST_OPERATOR,
        sha256(b"wrong-secret-test"),
        "operator",
        &secret(0x44),
        141,
        "negative-wrong-secret",
    ).is_err();
    let auditor_role_rejected = registry_before_revoke.authorize(
        DOMAIN_TRUST_COMMIT,
        ROLE_TRUST_OPERATOR,
        sha256(b"auditor-role-test"),
        "auditor",
        &secret(0x33),
        142,
        "negative-auditor-role",
    ).is_err();

    let mut proof = registry_before_revoke.authorize(
        DOMAIN_TRUST_COMMIT,
        ROLE_TRUST_OPERATOR,
        sha256(b"tamper-test"),
        "operator",
        &secret(0x22),
        143,
        "negative-tamper",
    )?;
    proof.signature[0] ^= 0x80;
    let tampered_signature_rejected =
        registry_before_revoke
            .verify_proof_with_secret(&proof, &secret(0x22))
            .is_err();

    if !wrong_secret_rejected
        || !auditor_role_rejected
        || !tampered_signature_rejected
    {
        return Err("authorization rejection matrix failed".into());
    }

    let revoke_output = execute(&[
        "trust-key-revoke",
        "--trust-root", &trust,
        "--target-key-id", "operator",
        "--signer-key-id", "root-admin",
        "--signer-key-file", &root_key,
        "--logical-timestamp", "40",
        "--nonce", "key-nonce-40",
    ])?;

    let revoked_key_rejected = expect_error(&[
        "trust-commit",
        "--db", &db,
        "--trust-root", &trust,
        "--record-id", "beta-record",
        "--operation", "PROMOTE",
        "--authority", "EVIDENCE_POLICY",
        "--evidence-file", &alpha_promote_path,
        "--policy-id", "promotion-policy",
        "--policy-version", "1",
        "--verifier-id", "promotion-verifier",
        "--logical-timestamp", "1030",
        "--reason-code", "REVOKED_KEY",
        "--signer-key-id", "operator",
        "--signer-key-file", &operator_key,
        "--authorization-timestamp", "150",
        "--nonce", "auth-nonce-150",
    ]);
    let last_admin_revoke_rejected = expect_error(&[
        "trust-key-revoke",
        "--trust-root", &trust,
        "--target-key-id", "root-admin",
        "--signer-key-id", "root-admin",
        "--signer-key-file", &root_key,
        "--logical-timestamp", "50",
        "--nonce", "key-nonce-50",
    ]);
    if !revoked_key_rejected || !last_admin_revoke_rejected {
        return Err("revocation safety matrix failed".into());
    }

    let status_output = execute(&[
        "trust-status",
        "--db", &db,
        "--trust-root", &trust,
    ])?;
    let list_keys_output = execute(&[
        "trust-list-keys",
        "--trust-root", &trust,
    ])?;
    let list_policies_output = execute(&[
        "trust-list-policies",
        "--trust-root", &trust,
    ])?;
    let list_authorizations_output = execute(&[
        "trust-list-authorizations",
        "--trust-root", &trust,
    ])?;

    let keys = KeyRegistry::open_strict(&paths.key_registry)?;
    let authorizations =
        AuthorizationLedger::open_strict(&paths.authorization_ledger)?;
    let policies = PolicyRegistry::open_strict(&paths.policy_registry)?;
    let trust_ledger = TrustLedger::open_strict(&paths.trust_ledger)?;
    let journal = TrustCommitJournal::open_strict(&paths.commit_journal)?;
    let database = DurableDatabase::open(&database_root, false)?;

    if keys.event_count() != 4
        || keys.active_key_count() != 2
        || authorizations.record_count() != 5
        || policies.policy_count() != 2
        || trust_ledger.transition_count() != 3
        || journal.entry_count() != 12
    {
        return Err(format!(
            "final count mismatch: keys={} active={} auth={} policies={} transitions={} journal={}",
            keys.event_count(),
            keys.active_key_count(),
            authorizations.record_count(),
            policies.policy_count(),
            trust_ledger.transition_count(),
            journal.entry_count(),
        ).into());
    }

    let binding_count = database.records()?.iter().filter(|record| {
        record.record_id.starts_with("__ubdb_trust_binding__/")
    }).count();
    if binding_count != 3 {
        return Err(format!(
            "binding record count mismatch: {binding_count}",
        ).into());
    }

    if !status_output.contains("\"key_event_count\":4")
        || !status_output.contains("\"authorization_count\":5")
        || !list_keys_output.contains("\"key_count\":3")
        || !list_policies_output.contains("\"policy_count\":2")
        || !list_authorizations_output
            .contains("\"authorization_count\":5")
    {
        return Err("CLI read surface counts mismatch".into());
    }

    let alpha = trust_ledger
        .snapshot("alpha-record")
        .ok_or("alpha trust state missing")?;
    let beta = trust_ledger
        .snapshot("beta-record")
        .ok_or("beta trust state missing")?;
    if alpha.state.maturity.as_str() != "HYPOTHESIS"
        || alpha.state.validity.as_str() != "ACTIVE"
        || beta.state.maturity.as_str() != "RAW"
        || beta.state.validity.as_str() != "ACTIVE"
    {
        return Err("final trust states mismatch".into());
    }

    let report = format!(
        concat!(
            "{{\n",
            "  \"pass\": true,\n",
            "  \"database_root\": \"{}\",\n",
            "  \"trust_root\": \"{}\",\n",
            "  \"key_registry_path\": \"{}\",\n",
            "  \"authorization_ledger_path\": \"{}\",\n",
            "  \"policy_registry_path\": \"{}\",\n",
            "  \"trust_ledger_path\": \"{}\",\n",
            "  \"commit_journal_path\": \"{}\",\n",
            "  \"root_key_path\": \"{}\",\n",
            "  \"operator_key_path\": \"{}\",\n",
            "  \"auditor_key_path\": \"{}\",\n",
            "  \"key_event_count\": 4,\n",
            "  \"active_key_count\": 2,\n",
            "  \"authorization_count\": 5,\n",
            "  \"policy_count\": 2,\n",
            "  \"trust_transition_count\": 3,\n",
            "  \"commit_journal_entry_count\": 12,\n",
            "  \"database_binding_record_count\": 3,\n",
            "  \"cli_command_count\": 10,\n",
            "  \"wrong_secret_rejected\": {},\n",
            "  \"auditor_role_rejected\": {},\n",
            "  \"tampered_signature_rejected\": {},\n",
            "  \"revoked_key_rejected\": {},\n",
            "  \"last_admin_revoke_rejected\": {},\n",
            "  \"idempotent_trust_retry\": true,\n",
            "  \"alpha_maturity\": \"HYPOTHESIS\",\n",
            "  \"alpha_validity\": \"ACTIVE\",\n",
            "  \"beta_maturity\": \"RAW\",\n",
            "  \"beta_validity\": \"ACTIVE\",\n",
            "  \"key_registry_sha256\": \"{}\",\n",
            "  \"authorization_ledger_sha256\": \"{}\",\n",
            "  \"policy_registry_sha256\": \"{}\",\n",
            "  \"trust_ledger_sha256\": \"{}\",\n",
            "  \"commit_journal_sha256\": \"{}\",\n",
            "  \"key_registry_head\": \"{}\",\n",
            "  \"authorization_head\": \"{}\",\n",
            "  \"raw_secret_persisted\": false,\n",
            "  \"signature_algorithm\": \"HMAC-SHA256\",\n",
            "  \"asymmetric_signature\": false,\n",
            "  \"network_enabled\": false,\n",
            "  \"automatic_repair_enabled\": false,\n",
            "  \"active_runtime_changed\": false,\n",
            "  \"outputs\": {{\n",
            "    \"trust_init\": \"{}\",\n",
            "    \"key_bootstrap\": \"{}\",\n",
            "    \"key_register_operator\": \"{}\",\n",
            "    \"key_register_auditor\": \"{}\",\n",
            "    \"policy_import\": \"{}\",\n",
            "    \"policy_promote\": \"{}\",\n",
            "    \"alpha_propose\": \"{}\",\n",
            "    \"beta_propose\": \"{}\",\n",
            "    \"alpha_promote\": \"{}\",\n",
            "    \"key_revoke\": \"{}\"\n",
            "  }}\n",
            "}}\n"
        ),
        json_escape(&database_root.to_string_lossy()),
        json_escape(&trust_root.to_string_lossy()),
        json_escape(&paths.key_registry.to_string_lossy()),
        json_escape(&paths.authorization_ledger.to_string_lossy()),
        json_escape(&paths.policy_registry.to_string_lossy()),
        json_escape(&paths.trust_ledger.to_string_lossy()),
        json_escape(&paths.commit_journal.to_string_lossy()),
        json_escape(&root_key_path.to_string_lossy()),
        json_escape(&operator_key_path.to_string_lossy()),
        json_escape(&auditor_key_path.to_string_lossy()),
        wrong_secret_rejected,
        auditor_role_rejected,
        tampered_signature_rejected,
        revoked_key_rejected,
        last_admin_revoke_rejected,
        hex_digest(&sha256(&fs::read(&paths.key_registry)?)),
        hex_digest(&sha256(&fs::read(&paths.authorization_ledger)?)),
        hex_digest(&sha256(&fs::read(&paths.policy_registry)?)),
        hex_digest(&sha256(&fs::read(&paths.trust_ledger)?)),
        hex_digest(&sha256(&fs::read(&paths.commit_journal)?)),
        hex_digest(&keys.head_digest()),
        hex_digest(&authorizations.head_digest()),
        json_escape(&init_output),
        json_escape(&bootstrap_output),
        json_escape(&register_operator_output),
        json_escape(&register_auditor_output),
        json_escape(&import_policy_output),
        json_escape(&promote_policy_output),
        json_escape(&alpha_propose_output),
        json_escape(&beta_propose_output),
        json_escape(&alpha_promote_output),
        json_escape(&revoke_output),
    );

    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&report_path, report)?;
    println!(
        "PASS_ULTRABALLOONDB_TRUST_AUTHORIZATION_SIGNATURES_CLI_PROBE"
    );
    println!("REPORT={}", report_path.display());
    Ok(())
}
