use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ultraballoondb_lifecycle::{
    BatchLimits, DurableDatabase, TransactionCore, TransactionId,
};
use ultraballoondb_storage::{hex_digest, sha256};
use ultraballoondb_trust::TrustLedger;
use ultraballoondb_trust_auth::{
    run_cli, AuthorizationLedger, KeyRegistry, PolicyStatusLedger,
    TrustPaths, DOMAIN_TRUST_COMMIT, ROLE_ALL, ROLE_TRUST_OPERATOR,
};
use ultraballoondb_trust_commit::{
    PolicyRegistry, TrustCommitJournal,
};

fn secret(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn write_secret(
    path: &Path,
    value: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, value)?;
    Ok(())
}

fn execute(
    arguments: &[&str],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut values = vec!["ultraballoondb-trust".to_string()];
    values.extend(arguments.iter().map(|value| value.to_string()));
    let output = run_cli(values)?;
    if !output.contains("\"ok\":true") {
        return Err(format!(
            "CLI output is not successful: {output}",
        ).into());
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
        *b"T4-INITIAL-DB001",
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
    core.commit_durable(
        &mut database,
        generation,
        sequence,
    )?;
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

fn file_sha(path: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(sha256(&fs::read(path)?))
}

fn tree_contains_secret(
    root: &Path,
    secrets: &[Vec<u8>],
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(current) = stack.pop() {
        let mut entries = fs::read_dir(&current)?
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                return Err(format!(
                    "unexpected symlink in export: {}",
                    path.display(),
                ).into());
            }
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                let bytes = fs::read(&path)?;
                if secrets.iter().any(|secret| {
                    bytes.windows(secret.len())
                        .any(|window| window == secret.as_slice())
                }) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() != 3 {
        return Err(
            "usage: trust_governance_audit_probe <root> <report-json>"
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
    let export_one = root.join("audit-export-one");
    let export_two = root.join("audit-export-two");

    let root_key_path = root.join("root.key");
    let operator_old_key_path = root.join("operator-old.key");
    let operator_new_key_path = root.join("operator-new.key");
    let auditor_key_path = root.join("auditor.key");

    let alpha_import_evidence = root.join("alpha-import.tsv");
    let alpha_promote_evidence = root.join("alpha-promote.tsv");
    let beta_import_evidence = root.join("beta-import.tsv");

    let root_secret = secret(0x11);
    let operator_old_secret = secret(0x22);
    let operator_new_secret = secret(0x2A);
    let auditor_secret = secret(0x33);

    put_records(&database_root)?;
    write_secret(&root_key_path, &root_secret)?;
    write_secret(&operator_old_key_path, &operator_old_secret)?;
    write_secret(&operator_new_key_path, &operator_new_secret)?;
    write_secret(&auditor_key_path, &auditor_secret)?;

    fs::write(
        &alpha_import_evidence,
        evidence_line("alpha-import", "source-A"),
    )?;
    fs::write(
        &alpha_promote_evidence,
        evidence_line("alpha-promote-1", "lab-A")
            + &evidence_line("alpha-promote-2", "lab-B"),
    )?;
    fs::write(
        &beta_import_evidence,
        evidence_line("beta-import", "source-B"),
    )?;

    let db = database_root.to_string_lossy().to_string();
    let trust = trust_root.to_string_lossy().to_string();
    let root_key = root_key_path.to_string_lossy().to_string();
    let operator_old_key =
        operator_old_key_path.to_string_lossy().to_string();
    let operator_new_key =
        operator_new_key_path.to_string_lossy().to_string();
    let auditor_key =
        auditor_key_path.to_string_lossy().to_string();

    let init_output = execute(&[
        "trust-init",
        "--db", &db,
        "--trust-root", &trust,
    ])?;

    let paths = TrustPaths::from_root(&trust_root);
    fs::remove_file(&paths.policy_status)?;
    let upgrade_output = execute(&[
        "trust-governance-upgrade",
        "--trust-root", &trust,
    ])?;
    if !upgrade_output.contains("\"changed\":true") {
        return Err("T3 governance upgrade did not create ledger".into());
    }
    let upgrade_retry_output = execute(&[
        "trust-governance-upgrade",
        "--trust-root", &trust,
    ])?;
    if !upgrade_retry_output.contains("\"changed\":false") {
        return Err("governance upgrade retry was not idempotent".into());
    }

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
        "--new-key-file", &operator_old_key,
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

    let import_v1_output = execute(&[
        "trust-policy-register",
        "--trust-root", &trust,
        "--policy-id", "import-policy",
        "--policy-version", "1",
        "--authority", "IMPORT",
        "--operation-mask", "1",
        "--min-evidence", "1",
        "--max-evidence", "2",
        "--verifier-id", "import-verifier-v1",
        "--unique-provenance", "false",
        "--signer-key-id", "root-admin",
        "--signer-key-file", &root_key,
        "--authorization-timestamp", "100",
        "--nonce", "auth-nonce-100",
    ])?;
    let promotion_output = execute(&[
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
    let alpha_promote_path =
        alpha_promote_evidence.to_string_lossy().to_string();
    let beta_import_path =
        beta_import_evidence.to_string_lossy().to_string();

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
        "--verifier-id", "import-verifier-v1",
        "--logical-timestamp", "1000",
        "--reason-code", "IMPORTED",
        "--signer-key-id", "operator",
        "--signer-key-file", &operator_old_key,
        "--authorization-timestamp", "120",
        "--nonce", "auth-nonce-120",
    ])?;

    let rotate_output = execute(&[
        "trust-key-rotate",
        "--trust-root", &trust,
        "--target-key-id", "operator",
        "--new-key-file", &operator_new_key,
        "--signer-key-id", "root-admin",
        "--signer-key-file", &root_key,
        "--logical-timestamp", "40",
        "--nonce", "key-nonce-40",
    ])?;

    let registry_after_rotation =
        KeyRegistry::open_strict(&paths.key_registry)?;
    let old_secret_rejected = registry_after_rotation.authorize(
        DOMAIN_TRUST_COMMIT,
        ROLE_TRUST_OPERATOR,
        sha256(b"old-secret-after-rotation"),
        "operator",
        &operator_old_secret,
        121,
        "negative-old-secret",
    ).is_err();
    let new_secret_accepted = registry_after_rotation.authorize(
        DOMAIN_TRUST_COMMIT,
        ROLE_TRUST_OPERATOR,
        sha256(b"new-secret-after-rotation"),
        "operator",
        &operator_new_secret,
        121,
        "positive-new-secret",
    ).is_ok();
    let mut same_fingerprint_registry =
        KeyRegistry::open_strict(&paths.key_registry)?;
    let same_fingerprint_rotation_rejected =
        same_fingerprint_registry.rotate_key(
            "operator",
            &operator_new_secret,
            "root-admin",
            &root_secret,
            41,
            "negative-same-fingerprint",
        ).is_err();
    let mut auditor_rotation_registry =
        KeyRegistry::open_strict(&paths.key_registry)?;
    let auditor_rotation_rejected =
        auditor_rotation_registry.rotate_key(
            "operator",
            &secret(0x2B),
            "auditor",
            &auditor_secret,
            41,
            "negative-auditor-rotation",
        ).is_err();
    if !old_secret_rejected
        || !new_secret_accepted
        || !same_fingerprint_rotation_rejected
        || !auditor_rotation_rejected
    {
        return Err("key rotation safety matrix failed".into());
    }

    let alpha_promote_output = execute(&[
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
        "--logical-timestamp", "1010",
        "--reason-code", "RAW_TO_HYPOTHESIS",
        "--signer-key-id", "operator",
        "--signer-key-file", &operator_new_key,
        "--authorization-timestamp", "130",
        "--nonce", "auth-nonce-130",
    ])?;

    let policy_revoke_output = execute(&[
        "trust-policy-revoke",
        "--trust-root", &trust,
        "--policy-id", "import-policy",
        "--policy-version", "1",
        "--reason-code", "SUPERSEDED_BY_V2",
        "--signer-key-id", "root-admin",
        "--signer-key-file", &root_key,
        "--authorization-timestamp", "140",
        "--nonce", "auth-nonce-140",
    ])?;

    let revoked_policy_rejected = expect_error(&[
        "trust-commit",
        "--db", &db,
        "--trust-root", &trust,
        "--record-id", "beta-record",
        "--operation", "PROPOSE",
        "--authority", "IMPORT",
        "--evidence-file", &beta_import_path,
        "--policy-id", "import-policy",
        "--policy-version", "1",
        "--verifier-id", "import-verifier-v1",
        "--logical-timestamp", "1020",
        "--reason-code", "REVOKED_POLICY",
        "--signer-key-id", "operator",
        "--signer-key-file", &operator_new_key,
        "--authorization-timestamp", "150",
        "--nonce", "auth-nonce-150-rejected",
    ]);

    let import_v2_output = execute(&[
        "trust-policy-register",
        "--trust-root", &trust,
        "--policy-id", "import-policy",
        "--policy-version", "2",
        "--authority", "IMPORT",
        "--operation-mask", "1",
        "--min-evidence", "1",
        "--max-evidence", "2",
        "--verifier-id", "import-verifier-v2",
        "--unique-provenance", "false",
        "--signer-key-id", "root-admin",
        "--signer-key-file", &root_key,
        "--authorization-timestamp", "150",
        "--nonce", "auth-nonce-150",
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
        "--policy-version", "2",
        "--verifier-id", "import-verifier-v2",
        "--logical-timestamp", "1020",
        "--reason-code", "IMPORTED_V2",
        "--signer-key-id", "operator",
        "--signer-key-file", &operator_new_key,
        "--authorization-timestamp", "160",
        "--nonce", "auth-nonce-160",
    ])?;

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

    let source_hashes_before = [
        file_sha(&paths.key_registry)?,
        file_sha(&paths.authorization_ledger)?,
        file_sha(&paths.policy_registry)?,
        file_sha(&paths.policy_status)?,
        file_sha(&paths.trust_ledger)?,
        file_sha(&paths.commit_journal)?,
    ];

    let export_one_text = export_one.to_string_lossy().to_string();
    let export_two_text = export_two.to_string_lossy().to_string();
    let audit_one_output = execute(&[
        "trust-audit-export",
        "--db", &db,
        "--trust-root", &trust,
        "--output-dir", &export_one_text,
    ])?;
    let audit_two_output = execute(&[
        "trust-audit-export",
        "--db", &db,
        "--trust-root", &trust,
        "--output-dir", &export_two_text,
    ])?;

    let source_hashes_after = [
        file_sha(&paths.key_registry)?,
        file_sha(&paths.authorization_ledger)?,
        file_sha(&paths.policy_registry)?,
        file_sha(&paths.policy_status)?,
        file_sha(&paths.trust_ledger)?,
        file_sha(&paths.commit_journal)?,
    ];
    let audit_source_unchanged =
        source_hashes_before == source_hashes_after;

    let summary_one = fs::read(export_one.join("audit-summary.json"))?;
    let summary_two = fs::read(export_two.join("audit-summary.json"))?;
    let manifest_one = fs::read(export_one.join("audit-manifest.json"))?;
    let manifest_two = fs::read(export_two.join("audit-manifest.json"))?;
    let receipt_one = fs::read(export_one.join("audit-receipt.json"))?;
    let receipt_two = fs::read(export_two.join("audit-receipt.json"))?;
    let deterministic_audit_export =
        summary_one == summary_two
        && manifest_one == manifest_two
        && receipt_one == receipt_two;

    let raw_secret_absent_from_export = !tree_contains_secret(
        &export_one,
        &[
            root_secret.clone(),
            operator_old_secret.clone(),
            operator_new_secret.clone(),
            auditor_secret.clone(),
        ],
    )?;

    let keys = KeyRegistry::open_strict(&paths.key_registry)?;
    let authorizations =
        AuthorizationLedger::open_strict(&paths.authorization_ledger)?;
    let policies = PolicyRegistry::open_strict(&paths.policy_registry)?;
    let policy_status =
        PolicyStatusLedger::open_strict(&paths.policy_status)?;
    let trust_ledger = TrustLedger::open_strict(&paths.trust_ledger)?;
    let journal = TrustCommitJournal::open_strict(
        &paths.commit_journal,
    )?;
    let database = DurableDatabase::open(&database_root, false)?;

    let binding_count = database.records()?.iter().filter(|record| {
        record.record_id.starts_with("__ubdb_trust_binding__/")
    }).count();

    if keys.event_count() != 4
        || keys.active_key_count() != 3
        || authorizations.record_count() != 7
        || policies.policy_count() != 3
        || policy_status.revoked_count() != 1
        || trust_ledger.transition_count() != 3
        || journal.entry_count() != 12
        || binding_count != 3
    {
        return Err(format!(
            concat!(
                "final count mismatch: keys={} active={} auth={} ",
                "policies={} policy_revocations={} transitions={} ",
                "journal={} bindings={}"
            ),
            keys.event_count(),
            keys.active_key_count(),
            authorizations.record_count(),
            policies.policy_count(),
            policy_status.revoked_count(),
            trust_ledger.transition_count(),
            journal.entry_count(),
            binding_count,
        ).into());
    }

    let operator = keys.get("operator")
        .ok_or("operator state missing")?;
    if operator.rotation_count != 1
        || operator.fingerprint != sha256(&operator_new_secret)
        || operator.role_mask != ROLE_TRUST_OPERATOR
    {
        return Err("operator rotation state mismatch".into());
    }
    if !policy_status.is_revoked("import-policy", "1")
        || policy_status.is_revoked("import-policy", "2")
    {
        return Err("policy revocation state mismatch".into());
    }

    if !revoked_policy_rejected
        || !audit_source_unchanged
        || !deterministic_audit_export
        || !raw_secret_absent_from_export
    {
        return Err("policy/audit safety matrix failed".into());
    }

    if !status_output.contains("\"key_event_count\":4")
        || !status_output.contains("\"authorization_count\":7")
        || !status_output.contains("\"policy_revocation_count\":1")
        || !status_output.contains("\"active_policy_count\":2")
        || !list_keys_output.contains("\"rotation_count\":1")
        || !list_policies_output.contains("\"revoked\":true")
        || !list_authorizations_output
            .contains("\"authorization_count\":7")
        || !audit_one_output.contains("\"source_unchanged\":true")
        || !audit_two_output.contains("\"deterministic_format\":true")
    {
        return Err("T4 CLI read surface mismatch".into());
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
            "  \"policy_status_path\": \"{}\",\n",
            "  \"trust_ledger_path\": \"{}\",\n",
            "  \"commit_journal_path\": \"{}\",\n",
            "  \"root_key_path\": \"{}\",\n",
            "  \"operator_old_key_path\": \"{}\",\n",
            "  \"operator_new_key_path\": \"{}\",\n",
            "  \"auditor_key_path\": \"{}\",\n",
            "  \"audit_export_one\": \"{}\",\n",
            "  \"audit_export_two\": \"{}\",\n",
            "  \"key_event_count\": 4,\n",
            "  \"active_key_count\": 3,\n",
            "  \"authorization_count\": 7,\n",
            "  \"policy_count\": 3,\n",
            "  \"policy_revocation_count\": 1,\n",
            "  \"active_policy_count\": 2,\n",
            "  \"trust_transition_count\": 3,\n",
            "  \"commit_journal_entry_count\": 12,\n",
            "  \"database_binding_record_count\": 3,\n",
            "  \"cli_command_count\": 14,\n",
            "  \"governance_upgrade_created\": true,\n",
            "  \"governance_upgrade_idempotent\": true,\n",
            "  \"old_secret_rejected\": {},\n",
            "  \"new_secret_accepted\": {},\n",
            "  \"same_fingerprint_rotation_rejected\": {},\n",
            "  \"auditor_rotation_rejected\": {},\n",
            "  \"revoked_policy_rejected\": {},\n",
            "  \"audit_source_unchanged\": {},\n",
            "  \"deterministic_audit_export\": {},\n",
            "  \"raw_secret_absent_from_export\": {},\n",
            "  \"operator_rotation_count\": 1,\n",
            "  \"key_registry_sha256\": \"{}\",\n",
            "  \"authorization_ledger_sha256\": \"{}\",\n",
            "  \"policy_registry_sha256\": \"{}\",\n",
            "  \"policy_status_sha256\": \"{}\",\n",
            "  \"trust_ledger_sha256\": \"{}\",\n",
            "  \"commit_journal_sha256\": \"{}\",\n",
            "  \"audit_manifest_sha256\": \"{}\",\n",
            "  \"audit_receipt_sha256\": \"{}\",\n",
            "  \"signature_algorithm\": \"HMAC-SHA256\",\n",
            "  \"asymmetric_signature\": false,\n",
            "  \"raw_secret_persisted\": false,\n",
            "  \"network_enabled\": false,\n",
            "  \"automatic_repair_enabled\": false,\n",
            "  \"active_runtime_changed\": false,\n",
            "  \"outputs\": {{\n",
            "    \"trust_init\": \"{}\",\n",
            "    \"governance_upgrade\": \"{}\",\n",
            "    \"governance_upgrade_retry\": \"{}\",\n",
            "    \"key_bootstrap\": \"{}\",\n",
            "    \"key_register_operator\": \"{}\",\n",
            "    \"key_register_auditor\": \"{}\",\n",
            "    \"policy_import_v1\": \"{}\",\n",
            "    \"policy_promotion\": \"{}\",\n",
            "    \"alpha_propose\": \"{}\",\n",
            "    \"key_rotate\": \"{}\",\n",
            "    \"alpha_promote\": \"{}\",\n",
            "    \"policy_revoke\": \"{}\",\n",
            "    \"policy_import_v2\": \"{}\",\n",
            "    \"beta_propose\": \"{}\",\n",
            "    \"audit_export_one\": \"{}\",\n",
            "    \"audit_export_two\": \"{}\"\n",
            "  }}\n",
            "}}\n"
        ),
        json_escape(&database_root.to_string_lossy()),
        json_escape(&trust_root.to_string_lossy()),
        json_escape(&paths.key_registry.to_string_lossy()),
        json_escape(&paths.authorization_ledger.to_string_lossy()),
        json_escape(&paths.policy_registry.to_string_lossy()),
        json_escape(&paths.policy_status.to_string_lossy()),
        json_escape(&paths.trust_ledger.to_string_lossy()),
        json_escape(&paths.commit_journal.to_string_lossy()),
        json_escape(&root_key_path.to_string_lossy()),
        json_escape(&operator_old_key_path.to_string_lossy()),
        json_escape(&operator_new_key_path.to_string_lossy()),
        json_escape(&auditor_key_path.to_string_lossy()),
        json_escape(&export_one.to_string_lossy()),
        json_escape(&export_two.to_string_lossy()),
        old_secret_rejected,
        new_secret_accepted,
        same_fingerprint_rotation_rejected,
        auditor_rotation_rejected,
        revoked_policy_rejected,
        audit_source_unchanged,
        deterministic_audit_export,
        raw_secret_absent_from_export,
        hex_digest(&file_sha(&paths.key_registry)?),
        hex_digest(&file_sha(&paths.authorization_ledger)?),
        hex_digest(&file_sha(&paths.policy_registry)?),
        hex_digest(&file_sha(&paths.policy_status)?),
        hex_digest(&file_sha(&paths.trust_ledger)?),
        hex_digest(&file_sha(&paths.commit_journal)?),
        hex_digest(&sha256(&manifest_one)),
        hex_digest(&sha256(&receipt_one)),
        json_escape(&init_output),
        json_escape(&upgrade_output),
        json_escape(&upgrade_retry_output),
        json_escape(&bootstrap_output),
        json_escape(&register_operator_output),
        json_escape(&register_auditor_output),
        json_escape(&import_v1_output),
        json_escape(&promotion_output),
        json_escape(&alpha_propose_output),
        json_escape(&rotate_output),
        json_escape(&alpha_promote_output),
        json_escape(&policy_revoke_output),
        json_escape(&import_v2_output),
        json_escape(&beta_propose_output),
        json_escape(&audit_one_output),
        json_escape(&audit_two_output),
    );

    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&report_path, report)?;
    println!(
        "PASS_ULTRABALLOONDB_TRUST_GOVERNANCE_AUDIT_PROBE"
    );
    println!("REPORT={}", report_path.display());
    Ok(())
}
