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
use ultraballoondb_trust_auth::{
    key_fingerprint, key_rotate_subject, policy_revoke_subject,
    run_cli as run_trust_cli, signed_trust_request_digest,
    AuthorizationLedger, KeyRegistry, PolicyStatusLedger, TrustPaths,
    DOMAIN_TRUST_COMMIT, ROLE_ALL, ROLE_AUDITOR, ROLE_POLICY_ADMIN,
    ROLE_TRUST_OPERATOR,
};
use ultraballoondb_trust_commit::{
    PolicyDefinition, PolicyRegistry, TrustCommitJournal,
    TrustCommitRequest,
};
use ultraballoondb_trust_enterprise::{
    run_cli as run_enterprise_cli, ApprovalLedger, EnterprisePaths,
    ENTERPRISE_APPROVAL_THRESHOLD,
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

fn execute_trust(
    arguments: &[&str],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut values = vec!["ultraballoondb-trust".to_string()];
    values.extend(arguments.iter().map(|value| value.to_string()));
    let output = run_trust_cli(values)?;
    if !output.contains("\"ok\":true") {
        return Err(format!(
            "trust CLI output is not successful: {output}",
        ).into());
    }
    Ok(output)
}

fn execute_enterprise(
    arguments: &[&str],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut values = vec![
        "ultraballoondb-trust-enterprise".to_string(),
    ];
    values.extend(arguments.iter().map(|value| value.to_string()));
    let output = run_enterprise_cli(values)?;
    if !output.contains("\"ok\":true") {
        return Err(format!(
            "enterprise CLI output is not successful: {output}",
        ).into());
    }
    Ok(output)
}

fn expect_enterprise_error(arguments: &[&str]) -> bool {
    let mut values = vec![
        "ultraballoondb-trust-enterprise".to_string(),
    ];
    values.extend(arguments.iter().map(|value| value.to_string()));
    run_enterprise_cli(values).is_err()
}

fn put_records(
    database_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut database = DurableDatabase::create(database_root)?;
    let generation = database.next_generation()?;
    let sequence = database.next_segment_sequence()?;
    let transaction_id = TransactionId::new(
        *b"T5-INITIAL-DB001",
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

fn json_string_field(
    text: &str,
    field: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let marker = format!("\"{field}\":\"");
    let start = text.find(&marker)
        .ok_or_else(|| format!(
            "JSON field missing: {field}",
        ))?
        + marker.len();
    let tail = &text[start..];
    let end = tail.find('"')
        .ok_or_else(|| format!(
            "JSON string field unterminated: {field}",
        ))?;
    Ok(tail[..end].to_string())
}

fn parse_digest(
    value: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if value.len() != 64 {
        return Err("digest must contain 64 hex characters".into());
    }
    let mut output = [0u8; 32];
    for index in 0..32 {
        output[index] = u8::from_str_radix(
            &value[index * 2..index * 2 + 2],
            16,
        )?;
    }
    Ok(output)
}

fn request_approval(
    trust_root: &str,
    domain: &str,
    subject: [u8; 32],
    requester_key_id: &str,
    requester_key_file: &str,
    created_at: u64,
    expires_at: u64,
    nonce: &str,
) -> Result<(String, [u8; 32]), Box<dyn std::error::Error>> {
    let output = execute_enterprise(&[
        "approval-request",
        "--trust-root", trust_root,
        "--domain", domain,
        "--subject-digest", &hex_digest(&subject),
        "--requester-key-id", requester_key_id,
        "--requester-key-file", requester_key_file,
        "--created-at", &created_at.to_string(),
        "--expires-at", &expires_at.to_string(),
        "--nonce", nonce,
    ])?;
    let request_id_text = json_string_field(
        &output,
        "request_id",
    )?;
    let request_id = parse_digest(&request_id_text)?;
    Ok((output, request_id))
}

fn approve_twice(
    trust_root: &str,
    request_id: [u8; 32],
    auditor_a_key: &str,
    auditor_b_key: &str,
    timestamp_a: u64,
    timestamp_b: u64,
    nonce_prefix: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let request_id_text = hex_digest(&request_id);
    let first = execute_enterprise(&[
        "approval-sign",
        "--trust-root", trust_root,
        "--request-id", &request_id_text,
        "--approver-key-id", "auditor-a",
        "--approver-key-file", auditor_a_key,
        "--logical-timestamp", &timestamp_a.to_string(),
        "--nonce", &format!("{nonce_prefix}-a"),
    ])?;
    let second = execute_enterprise(&[
        "approval-sign",
        "--trust-root", trust_root,
        "--request-id", &request_id_text,
        "--approver-key-id", "auditor-b",
        "--approver-key-file", auditor_b_key,
        "--logical-timestamp", &timestamp_b.to_string(),
        "--nonce", &format!("{nonce_prefix}-b"),
    ])?;
    Ok((first, second))
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
                write!(
                    &mut output,
                    "\\u{:04X}",
                    character as u32,
                )
                .expect("write to String");
            }
            character => output.push(character),
        }
    }
    output
}

fn file_sha(
    path: &Path,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
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
                    "unexpected audit symlink: {}",
                    path.display(),
                ).into());
            }
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                let data = fs::read(path)?;
                if secrets.iter().any(|secret| {
                    data.windows(secret.len())
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
            "usage: trust_enterprise_approval_audit_probe <root> <report-json>"
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
    let audit_one = root.join("enterprise-audit-one");
    let audit_two = root.join("enterprise-audit-two");

    let root_key_path = root.join("root.key");
    let policy_admin_key_path = root.join("policy-admin.key");
    let operator_old_key_path = root.join("operator-old.key");
    let operator_new_key_path = root.join("operator-new.key");
    let auditor_a_key_path = root.join("auditor-a.key");
    let auditor_b_key_path = root.join("auditor-b.key");

    let root_secret = secret(0x11);
    let policy_admin_secret = secret(0x21);
    let operator_old_secret = secret(0x31);
    let operator_new_secret = secret(0x32);
    let auditor_a_secret = secret(0x41);
    let auditor_b_secret = secret(0x42);

    put_records(&database_root)?;
    write_secret(&root_key_path, &root_secret)?;
    write_secret(&policy_admin_key_path, &policy_admin_secret)?;
    write_secret(&operator_old_key_path, &operator_old_secret)?;
    write_secret(&operator_new_key_path, &operator_new_secret)?;
    write_secret(&auditor_a_key_path, &auditor_a_secret)?;
    write_secret(&auditor_b_key_path, &auditor_b_secret)?;

    let alpha_evidence_path = root.join("alpha.tsv");
    let beta_evidence_path = root.join("beta.tsv");
    fs::write(
        &alpha_evidence_path,
        evidence_line("alpha-import", "source-A"),
    )?;
    fs::write(
        &beta_evidence_path,
        evidence_line("beta-import", "source-B"),
    )?;

    let db = database_root.to_string_lossy().to_string();
    let trust = trust_root.to_string_lossy().to_string();
    let root_key = root_key_path.to_string_lossy().to_string();
    let policy_admin_key =
        policy_admin_key_path.to_string_lossy().to_string();
    let operator_old_key =
        operator_old_key_path.to_string_lossy().to_string();
    let operator_new_key =
        operator_new_key_path.to_string_lossy().to_string();
    let auditor_a_key =
        auditor_a_key_path.to_string_lossy().to_string();
    let auditor_b_key =
        auditor_b_key_path.to_string_lossy().to_string();
    let alpha_evidence =
        alpha_evidence_path.to_string_lossy().to_string();
    let beta_evidence =
        beta_evidence_path.to_string_lossy().to_string();

    let trust_init_output = execute_trust(&[
        "trust-init",
        "--db", &db,
        "--trust-root", &trust,
    ])?;
    let key_bootstrap_output = execute_trust(&[
        "trust-key-bootstrap",
        "--trust-root", &trust,
        "--key-id", "root-admin",
        "--role-mask", &ROLE_ALL.to_string(),
        "--key-file", &root_key,
        "--logical-timestamp", "10",
        "--nonce", "key-10",
    ])?;
    let register_policy_admin_output = execute_trust(&[
        "trust-key-register",
        "--trust-root", &trust,
        "--new-key-id", "policy-admin",
        "--new-role-mask", &ROLE_POLICY_ADMIN.to_string(),
        "--new-key-file", &policy_admin_key,
        "--signer-key-id", "root-admin",
        "--signer-key-file", &root_key,
        "--logical-timestamp", "20",
        "--nonce", "key-20",
    ])?;
    let register_operator_output = execute_trust(&[
        "trust-key-register",
        "--trust-root", &trust,
        "--new-key-id", "operator",
        "--new-role-mask", &ROLE_TRUST_OPERATOR.to_string(),
        "--new-key-file", &operator_old_key,
        "--signer-key-id", "root-admin",
        "--signer-key-file", &root_key,
        "--logical-timestamp", "30",
        "--nonce", "key-30",
    ])?;
    let register_auditor_a_output = execute_trust(&[
        "trust-key-register",
        "--trust-root", &trust,
        "--new-key-id", "auditor-a",
        "--new-role-mask", &ROLE_AUDITOR.to_string(),
        "--new-key-file", &auditor_a_key,
        "--signer-key-id", "root-admin",
        "--signer-key-file", &root_key,
        "--logical-timestamp", "40",
        "--nonce", "key-40",
    ])?;
    let register_auditor_b_output = execute_trust(&[
        "trust-key-register",
        "--trust-root", &trust,
        "--new-key-id", "auditor-b",
        "--new-role-mask", &ROLE_AUDITOR.to_string(),
        "--new-key-file", &auditor_b_key,
        "--signer-key-id", "root-admin",
        "--signer-key-file", &root_key,
        "--logical-timestamp", "50",
        "--nonce", "key-50",
    ])?;

    let enterprise_enable_output = execute_enterprise(&[
        "enterprise-enable",
        "--trust-root", &trust,
        "--signer-key-id", "root-admin",
        "--signer-key-file", &root_key,
        "--activated-at", "100",
        "--nonce", "enterprise-enable-100",
    ])?;
    let enterprise_enable_retry_output = execute_enterprise(&[
        "enterprise-enable",
        "--trust-root", &trust,
        "--signer-key-id", "root-admin",
        "--signer-key-file", &root_key,
        "--activated-at", "100",
        "--nonce", "enterprise-enable-100",
    ])?;
    if !enterprise_enable_retry_output.contains("\"changed\":false") {
        return Err("enterprise enable retry was not idempotent".into());
    }

    let policy_v1 = PolicyDefinition {
        policy_id: "import-policy".to_string(),
        policy_version: "1".to_string(),
        allowed_authority: TransitionAuthority::Import,
        allowed_operation_mask: 1,
        min_evidence_refs: 1,
        max_evidence_refs: 2,
        required_verifier_id: "import-verifier-v1".to_string(),
        require_unique_provenance: false,
    };
    let policy_v1_digest = policy_v1.digest()?;

    let (policy_v1_request_output, policy_v1_request_id) =
        request_approval(
            &trust,
            "POLICY_REGISTER",
            policy_v1_digest,
            "policy-admin",
            &policy_admin_key,
            110,
            190,
            "request-policy-v1",
        )?;

    let self_approval_rejected = expect_enterprise_error(&[
        "approval-sign",
        "--trust-root", &trust,
        "--request-id", &hex_digest(&policy_v1_request_id),
        "--approver-key-id", "policy-admin",
        "--approver-key-file", &policy_admin_key,
        "--logical-timestamp", "111",
        "--nonce", "self-approval",
    ]);
    let first_policy_approval = execute_enterprise(&[
        "approval-sign",
        "--trust-root", &trust,
        "--request-id", &hex_digest(&policy_v1_request_id),
        "--approver-key-id", "auditor-a",
        "--approver-key-file", &auditor_a_key,
        "--logical-timestamp", "111",
        "--nonce", "policy-v1-a",
    ])?;
    let insufficient_quorum_rejected = expect_enterprise_error(&[
        "approved-policy-register",
        "--trust-root", &trust,
        "--request-id", &hex_digest(&policy_v1_request_id),
        "--policy-id", "import-policy",
        "--policy-version", "1",
        "--authority", "IMPORT",
        "--operation-mask", "1",
        "--min-evidence", "1",
        "--max-evidence", "2",
        "--verifier-id", "import-verifier-v1",
        "--unique-provenance", "false",
        "--signer-key-id", "policy-admin",
        "--signer-key-file", &policy_admin_key,
        "--logical-timestamp", "112",
        "--nonce", "policy-v1-too-early",
    ]);
    let duplicate_approver_rejected = expect_enterprise_error(&[
        "approval-sign",
        "--trust-root", &trust,
        "--request-id", &hex_digest(&policy_v1_request_id),
        "--approver-key-id", "auditor-a",
        "--approver-key-file", &auditor_a_key,
        "--logical-timestamp", "112",
        "--nonce", "policy-v1-a-duplicate",
    ]);
    let second_policy_approval = execute_enterprise(&[
        "approval-sign",
        "--trust-root", &trust,
        "--request-id", &hex_digest(&policy_v1_request_id),
        "--approver-key-id", "auditor-b",
        "--approver-key-file", &auditor_b_key,
        "--logical-timestamp", "112",
        "--nonce", "policy-v1-b",
    ])?;
    let policy_v1_register_output = execute_enterprise(&[
        "approved-policy-register",
        "--trust-root", &trust,
        "--request-id", &hex_digest(&policy_v1_request_id),
        "--policy-id", "import-policy",
        "--policy-version", "1",
        "--authority", "IMPORT",
        "--operation-mask", "1",
        "--min-evidence", "1",
        "--max-evidence", "2",
        "--verifier-id", "import-verifier-v1",
        "--unique-provenance", "false",
        "--signer-key-id", "policy-admin",
        "--signer-key-file", &policy_admin_key,
        "--logical-timestamp", "113",
        "--nonce", "policy-v1-register",
    ])?;

    let alpha_request = TrustCommitRequest {
        record_id: "alpha-record".to_string(),
        operation: TrustOperation::Propose,
        authority: TransitionAuthority::Import,
        evidence_refs: vec![EvidenceRef {
            evidence_id: "alpha-import".to_string(),
            provenance_id: "source-A".to_string(),
            evidence_digest: sha256(b"alpha-import:source-A"),
        }],
        policy_id: "import-policy".to_string(),
        policy_version: "1".to_string(),
        verifier_id: "import-verifier-v1".to_string(),
        logical_timestamp: 1000,
        reason_code: "IMPORTED_ALPHA".to_string(),
        superseding_record_id: None,
    };
    let alpha_subject = signed_trust_request_digest(
        &alpha_request,
    )?;
    let (alpha_approval_request_output, alpha_approval_id) =
        request_approval(
            &trust,
            "TRUST_COMMIT",
            alpha_subject,
            "operator",
            &operator_old_key,
            120,
            195,
            "request-alpha",
        )?;
    let (alpha_approve_a, alpha_approve_b) = approve_twice(
        &trust,
        alpha_approval_id,
        &auditor_a_key,
        &auditor_b_key,
        121,
        122,
        "alpha",
    )?;
    let alpha_commit_output = execute_enterprise(&[
        "approved-trust-commit",
        "--db", &db,
        "--trust-root", &trust,
        "--request-id", &hex_digest(&alpha_approval_id),
        "--record-id", "alpha-record",
        "--operation", "PROPOSE",
        "--authority", "IMPORT",
        "--evidence-file", &alpha_evidence,
        "--policy-id", "import-policy",
        "--policy-version", "1",
        "--verifier-id", "import-verifier-v1",
        "--transition-timestamp", "1000",
        "--reason-code", "IMPORTED_ALPHA",
        "--signer-key-id", "operator",
        "--signer-key-file", &operator_old_key,
        "--authorization-timestamp", "123",
        "--nonce", "alpha-commit",
    ])?;

    let trust_paths = TrustPaths::from_root(&trust_root);
    let registry_before_rotation =
        KeyRegistry::open_strict(&trust_paths.key_registry)?;
    let operator_before = registry_before_rotation.get("operator")
        .cloned()
        .ok_or("operator key missing")?;
    let operator_new_fingerprint = key_fingerprint(
        &operator_new_secret,
    )?;
    let rotation_subject = key_rotate_subject(
        "operator",
        operator_before.fingerprint,
        operator_new_fingerprint,
        operator_before.role_mask,
    )?;
    let (rotation_request_output, rotation_request_id) =
        request_approval(
            &trust,
            "KEY_ROTATE",
            rotation_subject,
            "root-admin",
            &root_key,
            130,
            196,
            "request-rotation",
        )?;
    let (rotation_approve_a, rotation_approve_b) = approve_twice(
        &trust,
        rotation_request_id,
        &auditor_a_key,
        &auditor_b_key,
        131,
        132,
        "rotation",
    )?;
    let rotation_output = execute_enterprise(&[
        "approved-key-rotate",
        "--trust-root", &trust,
        "--request-id", &hex_digest(&rotation_request_id),
        "--target-key-id", "operator",
        "--expected-old-fingerprint",
        &hex_digest(&operator_before.fingerprint),
        "--new-key-file", &operator_new_key,
        "--signer-key-id", "root-admin",
        "--signer-key-file", &root_key,
        "--logical-timestamp", "133",
        "--nonce", "rotate-operator",
    ])?;

    let registry_after_rotation =
        KeyRegistry::open_strict(&trust_paths.key_registry)?;
    let old_secret_rejected = registry_after_rotation.authorize(
        DOMAIN_TRUST_COMMIT,
        ROLE_TRUST_OPERATOR,
        sha256(b"old-secret-rejected"),
        "operator",
        &operator_old_secret,
        134,
        "negative-old",
    ).is_err();
    let new_secret_accepted = registry_after_rotation.authorize(
        DOMAIN_TRUST_COMMIT,
        ROLE_TRUST_OPERATOR,
        sha256(b"new-secret-accepted"),
        "operator",
        &operator_new_secret,
        134,
        "positive-new",
    ).is_ok();

    let revoke_subject = policy_revoke_subject(
        "import-policy",
        "1",
        policy_v1_digest,
        "SUPERSEDED_BY_V2",
    )?;
    let (revoke_request_output, revoke_request_id) =
        request_approval(
            &trust,
            "POLICY_REVOKE",
            revoke_subject,
            "policy-admin",
            &policy_admin_key,
            140,
            197,
            "request-revoke-v1",
        )?;
    let (revoke_approve_a, revoke_approve_b) = approve_twice(
        &trust,
        revoke_request_id,
        &auditor_a_key,
        &auditor_b_key,
        141,
        142,
        "revoke-v1",
    )?;
    let revoke_output = execute_enterprise(&[
        "approved-policy-revoke",
        "--trust-root", &trust,
        "--request-id", &hex_digest(&revoke_request_id),
        "--policy-id", "import-policy",
        "--policy-version", "1",
        "--reason-code", "SUPERSEDED_BY_V2",
        "--signer-key-id", "policy-admin",
        "--signer-key-file", &policy_admin_key,
        "--logical-timestamp", "143",
        "--nonce", "revoke-v1",
    ])?;

    let policy_v2 = PolicyDefinition {
        policy_id: "import-policy".to_string(),
        policy_version: "2".to_string(),
        allowed_authority: TransitionAuthority::Import,
        allowed_operation_mask: 1,
        min_evidence_refs: 1,
        max_evidence_refs: 2,
        required_verifier_id: "import-verifier-v2".to_string(),
        require_unique_provenance: false,
    };
    let policy_v2_digest = policy_v2.digest()?;
    let (policy_v2_request_output, policy_v2_request_id) =
        request_approval(
            &trust,
            "POLICY_REGISTER",
            policy_v2_digest,
            "policy-admin",
            &policy_admin_key,
            150,
            198,
            "request-policy-v2",
        )?;
    let (policy_v2_approve_a, policy_v2_approve_b) =
        approve_twice(
            &trust,
            policy_v2_request_id,
            &auditor_a_key,
            &auditor_b_key,
            151,
            152,
            "policy-v2",
        )?;
    let policy_v2_register_output = execute_enterprise(&[
        "approved-policy-register",
        "--trust-root", &trust,
        "--request-id", &hex_digest(&policy_v2_request_id),
        "--policy-id", "import-policy",
        "--policy-version", "2",
        "--authority", "IMPORT",
        "--operation-mask", "1",
        "--min-evidence", "1",
        "--max-evidence", "2",
        "--verifier-id", "import-verifier-v2",
        "--unique-provenance", "false",
        "--signer-key-id", "policy-admin",
        "--signer-key-file", &policy_admin_key,
        "--logical-timestamp", "153",
        "--nonce", "policy-v2-register",
    ])?;

    let beta_request = TrustCommitRequest {
        record_id: "beta-record".to_string(),
        operation: TrustOperation::Propose,
        authority: TransitionAuthority::Import,
        evidence_refs: vec![EvidenceRef {
            evidence_id: "beta-import".to_string(),
            provenance_id: "source-B".to_string(),
            evidence_digest: sha256(b"beta-import:source-B"),
        }],
        policy_id: "import-policy".to_string(),
        policy_version: "2".to_string(),
        verifier_id: "import-verifier-v2".to_string(),
        logical_timestamp: 1010,
        reason_code: "IMPORTED_BETA".to_string(),
        superseding_record_id: None,
    };
    let beta_subject = signed_trust_request_digest(&beta_request)?;
    let (beta_approval_request_output, beta_approval_id) =
        request_approval(
            &trust,
            "TRUST_COMMIT",
            beta_subject,
            "operator",
            &operator_new_key,
            160,
            199,
            "request-beta",
        )?;
    let (beta_approve_a, beta_approve_b) = approve_twice(
        &trust,
        beta_approval_id,
        &auditor_a_key,
        &auditor_b_key,
        161,
        162,
        "beta",
    )?;
    let beta_commit_output = execute_enterprise(&[
        "approved-trust-commit",
        "--db", &db,
        "--trust-root", &trust,
        "--request-id", &hex_digest(&beta_approval_id),
        "--record-id", "beta-record",
        "--operation", "PROPOSE",
        "--authority", "IMPORT",
        "--evidence-file", &beta_evidence,
        "--policy-id", "import-policy",
        "--policy-version", "2",
        "--verifier-id", "import-verifier-v2",
        "--transition-timestamp", "1010",
        "--reason-code", "IMPORTED_BETA",
        "--signer-key-id", "operator",
        "--signer-key-file", &operator_new_key,
        "--authorization-timestamp", "163",
        "--nonce", "beta-commit",
    ])?;

    let (expired_request_output, expired_request_id) =
        request_approval(
            &trust,
            "TRUST_COMMIT",
            beta_subject,
            "operator",
            &operator_new_key,
            170,
            172,
            "request-expired",
        )?;
    let expired_approval_output = execute_enterprise(&[
        "approval-sign",
        "--trust-root", &trust,
        "--request-id", &hex_digest(&expired_request_id),
        "--approver-key-id", "auditor-a",
        "--approver-key-file", &auditor_a_key,
        "--logical-timestamp", "171",
        "--nonce", "expired-a",
    ])?;
    let expired_second_approval_rejected =
        expect_enterprise_error(&[
            "approval-sign",
            "--trust-root", &trust,
            "--request-id", &hex_digest(&expired_request_id),
            "--approver-key-id", "auditor-b",
            "--approver-key-file", &auditor_b_key,
            "--logical-timestamp", "173",
            "--nonce", "expired-b",
        ]);
    let expired_execution_rejected =
        expect_enterprise_error(&[
            "approved-trust-commit",
            "--db", &db,
            "--trust-root", &trust,
            "--request-id", &hex_digest(&expired_request_id),
            "--record-id", "beta-record",
            "--operation", "PROPOSE",
            "--authority", "IMPORT",
            "--evidence-file", &beta_evidence,
            "--policy-id", "import-policy",
            "--policy-version", "2",
            "--verifier-id", "import-verifier-v2",
            "--transition-timestamp", "1010",
            "--reason-code", "IMPORTED_BETA",
            "--signer-key-id", "operator",
            "--signer-key-file", &operator_new_key,
            "--authorization-timestamp", "174",
            "--nonce", "expired-execution",
        ]);

    let enterprise_status_output = execute_enterprise(&[
        "enterprise-status",
        "--trust-root", &trust,
        "--logical-timestamp", "200",
    ])?;
    let expired_status_output = execute_enterprise(&[
        "approval-status",
        "--trust-root", &trust,
        "--request-id", &hex_digest(&expired_request_id),
        "--logical-timestamp", "200",
    ])?;
    if !expired_status_output.contains("\"status\":\"EXPIRED\"") {
        return Err("expired approval status mismatch".into());
    }

    let audit_one_text = audit_one.to_string_lossy().to_string();
    let audit_two_text = audit_two.to_string_lossy().to_string();
    let audit_one_output = execute_enterprise(&[
        "enterprise-audit-export",
        "--db", &db,
        "--trust-root", &trust,
        "--output-dir", &audit_one_text,
        "--logical-timestamp", "200",
    ])?;
    let audit_two_output = execute_enterprise(&[
        "enterprise-audit-export",
        "--db", &db,
        "--trust-root", &trust,
        "--output-dir", &audit_two_text,
        "--logical-timestamp", "200",
    ])?;

    let deterministic_export = fs::read(
        audit_one.join("enterprise-summary.json"),
    )? == fs::read(
        audit_two.join("enterprise-summary.json"),
    )? && fs::read(
        audit_one.join("enterprise-manifest.json"),
    )? == fs::read(
        audit_two.join("enterprise-manifest.json"),
    )? && fs::read(
        audit_one.join("enterprise-receipt.json"),
    )? == fs::read(
        audit_two.join("enterprise-receipt.json"),
    )?;

    let enterprise_paths =
        EnterprisePaths::from_trust_root(&trust_root);
    let approvals = ApprovalLedger::open_strict(
        &enterprise_paths.approvals,
    )?;
    let keys = KeyRegistry::open_strict(
        &trust_paths.key_registry,
    )?;
    let authorizations = AuthorizationLedger::open_strict(
        &trust_paths.authorization_ledger,
    )?;
    let policies = PolicyRegistry::open_strict(
        &trust_paths.policy_registry,
    )?;
    let policy_status = PolicyStatusLedger::open_strict(
        &trust_paths.policy_status,
    )?;
    let trust_ledger = TrustLedger::open_strict(
        &trust_paths.trust_ledger,
    )?;
    let journal = TrustCommitJournal::open_strict(
        &trust_paths.commit_journal,
    )?;
    let database = DurableDatabase::open(&database_root, false)?;

    let binding_count = database.records()?.iter().filter(|record| {
        record.record_id.starts_with("__ubdb_trust_binding__/")
    }).count();

    let expected_approval_events = 26usize;
    if keys.event_count() != 6
        || keys.active_key_count() != 5
        || authorizations.record_count() != 5
        || policies.policy_count() != 2
        || policy_status.revoked_count() != 1
        || trust_ledger.transition_count() != 2
        || journal.entry_count() != 8
        || binding_count != 2
        || approvals.event_count() != expected_approval_events
        || approvals.request_count() != 7
        || approvals.approval_count() != 13
        || approvals.finalization_count() != 6
        || approvals.expired_count_at(200) != 1
    {
        return Err(format!(
            concat!(
                "final count mismatch: keys={} active={} auth={} ",
                "policies={} revocations={} transitions={} journal={} ",
                "bindings={} approval_events={} requests={} approvals={} ",
                "finalizations={} expired={}"
            ),
            keys.event_count(),
            keys.active_key_count(),
            authorizations.record_count(),
            policies.policy_count(),
            policy_status.revoked_count(),
            trust_ledger.transition_count(),
            journal.entry_count(),
            binding_count,
            approvals.event_count(),
            approvals.request_count(),
            approvals.approval_count(),
            approvals.finalization_count(),
            approvals.expired_count_at(200),
        ).into());
    }

    let source_files = [
        &trust_paths.key_registry,
        &trust_paths.authorization_ledger,
        &trust_paths.policy_registry,
        &trust_paths.policy_status,
        &trust_paths.trust_ledger,
        &trust_paths.commit_journal,
        &enterprise_paths.profile,
        &enterprise_paths.approvals,
    ];
    let source_hashes = source_files.iter()
        .map(|path| file_sha(path))
        .collect::<Result<Vec<_>, _>>()?;

    let raw_secret_absent_from_export = !tree_contains_secret(
        &audit_one,
        &[
            root_secret.clone(),
            policy_admin_secret.clone(),
            operator_old_secret.clone(),
            operator_new_secret.clone(),
            auditor_a_secret.clone(),
            auditor_b_secret.clone(),
        ],
    )?;

    if !self_approval_rejected
        || !insufficient_quorum_rejected
        || !duplicate_approver_rejected
        || !old_secret_rejected
        || !new_secret_accepted
        || !expired_second_approval_rejected
        || !expired_execution_rejected
        || !deterministic_export
        || !raw_secret_absent_from_export
    {
        return Err("enterprise negative/safety matrix failed".into());
    }
    if !audit_one_output.contains(
        "\"protected_operation_count\":6",
    ) || !audit_one_output.contains(
        "\"covered_operation_count\":6",
    ) || !audit_one_output.contains(
        "\"uncovered_operation_count\":0",
    ) || !enterprise_status_output.contains(
        "\"approval_event_count\":26",
    ) {
        return Err("enterprise status/audit output mismatch".into());
    }

    let enterprise_manifest = fs::read(
        audit_one.join("enterprise-manifest.json"),
    )?;
    let enterprise_receipt = fs::read(
        audit_one.join("enterprise-receipt.json"),
    )?;

    let report = format!(
        concat!(
            "{{\n",
            "  \"pass\": true,\n",
            "  \"database_root\": \"{}\",\n",
            "  \"database_state_digest\": \"{}\",\n",
            "  \"trust_root\": \"{}\",\n",
            "  \"enterprise_profile_path\": \"{}\",\n",
            "  \"approval_ledger_path\": \"{}\",\n",
            "  \"key_registry_path\": \"{}\",\n",
            "  \"authorization_ledger_path\": \"{}\",\n",
            "  \"policy_registry_path\": \"{}\",\n",
            "  \"policy_status_path\": \"{}\",\n",
            "  \"trust_ledger_path\": \"{}\",\n",
            "  \"commit_journal_path\": \"{}\",\n",
            "  \"root_key_path\": \"{}\",\n",
            "  \"policy_admin_key_path\": \"{}\",\n",
            "  \"operator_old_key_path\": \"{}\",\n",
            "  \"operator_new_key_path\": \"{}\",\n",
            "  \"auditor_a_key_path\": \"{}\",\n",
            "  \"auditor_b_key_path\": \"{}\",\n",
            "  \"audit_export_one\": \"{}\",\n",
            "  \"audit_export_two\": \"{}\",\n",
            "  \"profile_id\": \"ENTERPRISE_STRICT_V1\",\n",
            "  \"approval_threshold\": {},\n",
            "  \"key_event_count\": 6,\n",
            "  \"active_key_count\": 5,\n",
            "  \"authorization_count\": 5,\n",
            "  \"policy_count\": 2,\n",
            "  \"policy_revocation_count\": 1,\n",
            "  \"active_policy_count\": 1,\n",
            "  \"trust_transition_count\": 2,\n",
            "  \"commit_journal_entry_count\": 8,\n",
            "  \"database_binding_record_count\": 2,\n",
            "  \"approval_event_count\": 26,\n",
            "  \"approval_request_count\": 7,\n",
            "  \"approval_signature_count\": 13,\n",
            "  \"approval_finalization_count\": 6,\n",
            "  \"expired_request_count\": 1,\n",
            "  \"protected_operation_count\": 6,\n",
            "  \"covered_operation_count\": 6,\n",
            "  \"uncovered_operation_count\": 0,\n",
            "  \"cli_command_count\": 12,\n",
            "  \"enterprise_enable_idempotent\": true,\n",
            "  \"self_approval_rejected\": {},\n",
            "  \"insufficient_quorum_rejected\": {},\n",
            "  \"duplicate_approver_rejected\": {},\n",
            "  \"old_secret_rejected\": {},\n",
            "  \"new_secret_accepted\": {},\n",
            "  \"expired_second_approval_rejected\": {},\n",
            "  \"expired_execution_rejected\": {},\n",
            "  \"deterministic_export\": {},\n",
            "  \"raw_secret_absent_from_export\": {},\n",
            "  \"profile_sha256\": \"{}\",\n",
            "  \"approval_ledger_sha256\": \"{}\",\n",
            "  \"enterprise_manifest_sha256\": \"{}\",\n",
            "  \"enterprise_receipt_sha256\": \"{}\",\n",
            "  \"source_hash_count\": {},\n",
            "  \"raw_secret_persisted\": false,\n",
            "  \"network_enabled\": false,\n",
            "  \"automatic_repair_enabled\": false,\n",
            "  \"active_runtime_changed\": false,\n",
            "  \"outputs\": {{\n",
            "    \"trust_init\": \"{}\",\n",
            "    \"key_bootstrap\": \"{}\",\n",
            "    \"register_policy_admin\": \"{}\",\n",
            "    \"register_operator\": \"{}\",\n",
            "    \"register_auditor_a\": \"{}\",\n",
            "    \"register_auditor_b\": \"{}\",\n",
            "    \"enterprise_enable\": \"{}\",\n",
            "    \"enterprise_enable_retry\": \"{}\",\n",
            "    \"policy_v1_request\": \"{}\",\n",
            "    \"policy_v1_approve_a\": \"{}\",\n",
            "    \"policy_v1_approve_b\": \"{}\",\n",
            "    \"policy_v1_register\": \"{}\",\n",
            "    \"alpha_request\": \"{}\",\n",
            "    \"alpha_approve_a\": \"{}\",\n",
            "    \"alpha_approve_b\": \"{}\",\n",
            "    \"alpha_commit\": \"{}\",\n",
            "    \"rotation_request\": \"{}\",\n",
            "    \"rotation_approve_a\": \"{}\",\n",
            "    \"rotation_approve_b\": \"{}\",\n",
            "    \"rotation\": \"{}\",\n",
            "    \"revoke_request\": \"{}\",\n",
            "    \"revoke_approve_a\": \"{}\",\n",
            "    \"revoke_approve_b\": \"{}\",\n",
            "    \"revoke\": \"{}\",\n",
            "    \"policy_v2_request\": \"{}\",\n",
            "    \"policy_v2_approve_a\": \"{}\",\n",
            "    \"policy_v2_approve_b\": \"{}\",\n",
            "    \"policy_v2_register\": \"{}\",\n",
            "    \"beta_request\": \"{}\",\n",
            "    \"beta_approve_a\": \"{}\",\n",
            "    \"beta_approve_b\": \"{}\",\n",
            "    \"beta_commit\": \"{}\",\n",
            "    \"expired_request\": \"{}\",\n",
            "    \"expired_approval\": \"{}\",\n",
            "    \"enterprise_status\": \"{}\",\n",
            "    \"audit_one\": \"{}\",\n",
            "    \"audit_two\": \"{}\"\n",
            "  }}\n",
            "}}\n"
        ),
        json_escape(&database_root.to_string_lossy()),
        hex_digest(&database.state_sha256()),
        json_escape(&trust_root.to_string_lossy()),
        json_escape(&enterprise_paths.profile.to_string_lossy()),
        json_escape(&enterprise_paths.approvals.to_string_lossy()),
        json_escape(&trust_paths.key_registry.to_string_lossy()),
        json_escape(&trust_paths.authorization_ledger.to_string_lossy()),
        json_escape(&trust_paths.policy_registry.to_string_lossy()),
        json_escape(&trust_paths.policy_status.to_string_lossy()),
        json_escape(&trust_paths.trust_ledger.to_string_lossy()),
        json_escape(&trust_paths.commit_journal.to_string_lossy()),
        json_escape(&root_key_path.to_string_lossy()),
        json_escape(&policy_admin_key_path.to_string_lossy()),
        json_escape(&operator_old_key_path.to_string_lossy()),
        json_escape(&operator_new_key_path.to_string_lossy()),
        json_escape(&auditor_a_key_path.to_string_lossy()),
        json_escape(&auditor_b_key_path.to_string_lossy()),
        json_escape(&audit_one.to_string_lossy()),
        json_escape(&audit_two.to_string_lossy()),
        ENTERPRISE_APPROVAL_THRESHOLD,
        self_approval_rejected,
        insufficient_quorum_rejected,
        duplicate_approver_rejected,
        old_secret_rejected,
        new_secret_accepted,
        expired_second_approval_rejected,
        expired_execution_rejected,
        deterministic_export,
        raw_secret_absent_from_export,
        hex_digest(&file_sha(&enterprise_paths.profile)?),
        hex_digest(&file_sha(&enterprise_paths.approvals)?),
        hex_digest(&sha256(&enterprise_manifest)),
        hex_digest(&sha256(&enterprise_receipt)),
        source_hashes.len(),
        json_escape(&trust_init_output),
        json_escape(&key_bootstrap_output),
        json_escape(&register_policy_admin_output),
        json_escape(&register_operator_output),
        json_escape(&register_auditor_a_output),
        json_escape(&register_auditor_b_output),
        json_escape(&enterprise_enable_output),
        json_escape(&enterprise_enable_retry_output),
        json_escape(&policy_v1_request_output),
        json_escape(&first_policy_approval),
        json_escape(&second_policy_approval),
        json_escape(&policy_v1_register_output),
        json_escape(&alpha_approval_request_output),
        json_escape(&alpha_approve_a),
        json_escape(&alpha_approve_b),
        json_escape(&alpha_commit_output),
        json_escape(&rotation_request_output),
        json_escape(&rotation_approve_a),
        json_escape(&rotation_approve_b),
        json_escape(&rotation_output),
        json_escape(&revoke_request_output),
        json_escape(&revoke_approve_a),
        json_escape(&revoke_approve_b),
        json_escape(&revoke_output),
        json_escape(&policy_v2_request_output),
        json_escape(&policy_v2_approve_a),
        json_escape(&policy_v2_approve_b),
        json_escape(&policy_v2_register_output),
        json_escape(&beta_approval_request_output),
        json_escape(&beta_approve_a),
        json_escape(&beta_approve_b),
        json_escape(&beta_commit_output),
        json_escape(&expired_request_output),
        json_escape(&expired_approval_output),
        json_escape(&enterprise_status_output),
        json_escape(&audit_one_output),
        json_escape(&audit_two_output),
    );

    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&report_path, report)?;
    println!(
        "PASS_ULTRABALLOONDB_TRUST_ENTERPRISE_APPROVAL_AUDIT_PROBE"
    );
    println!("REPORT={}", report_path.display());
    Ok(())
}
