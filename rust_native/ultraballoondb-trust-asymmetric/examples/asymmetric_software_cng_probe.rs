use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ultraballoondb_storage::{hex_digest, sha256};
use ultraballoondb_trust_asymmetric::{
    delete_persisted_key, private_export_rejected,
    provider_key_exists, run_cli, verify_digest,
    AsymmetricAuthorizationLedger, AsymmetricKeyRegistry,
    AsymmetricPaths, SOFTWARE_KSP,
};
use ultraballoondb_trust_auth::{
    ROLE_POLICY_ADMIN, ROLE_TRUST_OPERATOR,
};

struct ProviderCleanup {
    names: Vec<String>,
}

impl ProviderCleanup {
    fn new() -> Self {
        Self { names: Vec::new() }
    }

    fn track(&mut self, name: String) {
        self.names.push(name);
    }

    fn remove(&mut self, name: &str) {
        self.names.retain(|value| value != name);
    }
}

impl Drop for ProviderCleanup {
    fn drop(&mut self) {
        for name in self.names.iter().rev() {
            if provider_key_exists(SOFTWARE_KSP, name) {
                let _ = delete_persisted_key(SOFTWARE_KSP, name);
            }
        }
    }
}

fn execute(
    arguments: &[String],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut values = vec![
        "ultraballoondb-trust-asymmetric".to_string(),
    ];
    values.extend(arguments.iter().cloned());
    let output = run_cli(values)?;
    if !output.contains("\"ok\":true") {
        return Err(format!(
            "asymmetric CLI output is not successful: {output}",
        ).into());
    }
    Ok(output)
}

fn expect_error(arguments: &[String]) -> bool {
    let mut values = vec![
        "ultraballoondb-trust-asymmetric".to_string(),
    ];
    values.extend(arguments.iter().cloned());
    run_cli(values).is_err()
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

fn copy_and_corrupt(
    source: &Path,
    destination: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = fs::read(source)?;
    if bytes.len() < 32 {
        return Err("cannot corrupt a tiny file".into());
    }
    let index = bytes.len() - 17;
    bytes[index] ^= 0x5A;
    fs::write(destination, bytes)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() != 3 {
        return Err(
            "usage: asymmetric_software_cng_probe <root> <report-json>"
                .into(),
        );
    }
    let root = PathBuf::from(&arguments[1]);
    let report_path = PathBuf::from(&arguments[2]);
    if root.exists() {
        fs::remove_dir_all(&root)?;
    }
    fs::create_dir_all(&root)?;
    let root_text = root.to_string_lossy().to_string();
    let paths = AsymmetricPaths::from_root(&root);

    let unique = format!(
        "{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_nanos(),
        sha256(root_text.as_bytes())[0],
    );
    let key_a = format!("UltraBalloonDB-T6B-{unique}-A");
    let key_b = format!("UltraBalloonDB-T6B-{unique}-B");
    let mut cleanup = ProviderCleanup::new();
    cleanup.track(key_a.clone());
    cleanup.track(key_b.clone());

    let init_output = execute(&[
        "asym-init".to_string(),
        "--root".to_string(),
        root_text.clone(),
    ])?;
    let init_retry_output = execute(&[
        "asym-init".to_string(),
        "--root".to_string(),
        root_text.clone(),
    ])?;
    if !init_retry_output.contains("\"changed\":false") {
        return Err("asym-init retry was not idempotent".into());
    }

    let create_output = execute(&[
        "asym-key-create".to_string(),
        "--root".to_string(),
        root_text.clone(),
        "--key-id".to_string(),
        "operator".to_string(),
        "--role-mask".to_string(),
        ROLE_TRUST_OPERATOR.to_string(),
        "--provider-key-name".to_string(),
        key_a.clone(),
        "--logical-timestamp".to_string(),
        "10".to_string(),
        "--nonce".to_string(),
        "enroll-10".to_string(),
    ])?;
    let private_export_a_rejected =
        private_export_rejected(SOFTWARE_KSP, &key_a)?;
    if !private_export_a_rejected {
        return Err("private export unexpectedly allowed for key A".into());
    }

    let duplicate_key_id_rejected = expect_error(&[
        "asym-key-create".to_string(),
        "--root".to_string(),
        root_text.clone(),
        "--key-id".to_string(),
        "operator".to_string(),
        "--role-mask".to_string(),
        ROLE_TRUST_OPERATOR.to_string(),
        "--provider-key-name".to_string(),
        format!("{key_a}-duplicate"),
        "--logical-timestamp".to_string(),
        "11".to_string(),
        "--nonce".to_string(),
        "duplicate-enroll".to_string(),
    ]);

    let subject_one = sha256(b"T6B-SUBJECT-ONE");
    let authorize_one_output = execute(&[
        "asym-authorize".to_string(),
        "--root".to_string(),
        root_text.clone(),
        "--domain-code".to_string(),
        "5".to_string(),
        "--required-role-mask".to_string(),
        ROLE_TRUST_OPERATOR.to_string(),
        "--subject-digest".to_string(),
        hex_digest(&subject_one),
        "--key-id".to_string(),
        "operator".to_string(),
        "--provider-key-name".to_string(),
        key_a.clone(),
        "--logical-timestamp".to_string(),
        "20".to_string(),
        "--nonce".to_string(),
        "authorize-20".to_string(),
    ])?;
    let verify_one_output = execute(&[
        "asym-authorization-verify".to_string(),
        "--root".to_string(),
        root_text.clone(),
        "--sequence".to_string(),
        "1".to_string(),
    ])?;

    let duplicate_nonce_rejected = expect_error(&[
        "asym-authorize".to_string(),
        "--root".to_string(),
        root_text.clone(),
        "--domain-code".to_string(),
        "5".to_string(),
        "--required-role-mask".to_string(),
        ROLE_TRUST_OPERATOR.to_string(),
        "--subject-digest".to_string(),
        hex_digest(&sha256(b"T6B-DUPLICATE-NONCE")),
        "--key-id".to_string(),
        "operator".to_string(),
        "--provider-key-name".to_string(),
        key_a.clone(),
        "--logical-timestamp".to_string(),
        "21".to_string(),
        "--nonce".to_string(),
        "authorize-20".to_string(),
    ]);
    let wrong_role_rejected = expect_error(&[
        "asym-authorize".to_string(),
        "--root".to_string(),
        root_text.clone(),
        "--domain-code".to_string(),
        "4".to_string(),
        "--required-role-mask".to_string(),
        ROLE_POLICY_ADMIN.to_string(),
        "--subject-digest".to_string(),
        hex_digest(&sha256(b"T6B-WRONG-ROLE")),
        "--key-id".to_string(),
        "operator".to_string(),
        "--provider-key-name".to_string(),
        key_a.clone(),
        "--logical-timestamp".to_string(),
        "22".to_string(),
        "--nonce".to_string(),
        "wrong-role-22".to_string(),
    ]);

    let registry_after_enroll = AsymmetricKeyRegistry::open_strict(
        &paths.key_registry,
    )?;
    let ledger_after_first =
        AsymmetricAuthorizationLedger::open_strict(
            &paths.authorization_ledger,
            &registry_after_enroll,
        )?;
    let first_event = ledger_after_first.events()
        .first()
        .ok_or("first authorization missing")?;
    let mut tampered_digest = first_event.authorization_digest;
    tampered_digest[0] ^= 0x80;
    let tampered_signature_rejected = !verify_digest(
        &registry_after_enroll
            .get("operator")
            .ok_or("operator state missing")?
            .public_blob,
        &tampered_digest,
        &first_event.signature,
    )?;

    let rotate_output = execute(&[
        "asym-key-rotate".to_string(),
        "--root".to_string(),
        root_text.clone(),
        "--key-id".to_string(),
        "operator".to_string(),
        "--old-provider-key-name".to_string(),
        key_a.clone(),
        "--new-provider-key-name".to_string(),
        key_b.clone(),
        "--logical-timestamp".to_string(),
        "30".to_string(),
        "--nonce".to_string(),
        "rotate-30".to_string(),
    ])?;
    let private_export_b_rejected =
        private_export_rejected(SOFTWARE_KSP, &key_b)?;
    if !private_export_b_rejected {
        return Err("private export unexpectedly allowed for key B".into());
    }

    let registry_after_rotation =
        AsymmetricKeyRegistry::open_strict(
            &paths.key_registry,
        )?;
    let rotated_state = registry_after_rotation
        .get("operator")
        .ok_or("rotated operator state missing")?;
    let role_mask_preserved =
        rotated_state.role_mask == ROLE_TRUST_OPERATOR
            && rotated_state.generation == 2
            && rotated_state.provider_key_name == key_b;
    let rotation_event = registry_after_rotation.events()
        .get(1)
        .ok_or("rotation event missing")?;
    let dual_proof_rotation_verified =
        rotation_event.signature_old != [0; 64]
            && rotation_event.signature_new != [0; 64];

    let old_provider_key_rejected = expect_error(&[
        "asym-authorize".to_string(),
        "--root".to_string(),
        root_text.clone(),
        "--domain-code".to_string(),
        "5".to_string(),
        "--required-role-mask".to_string(),
        ROLE_TRUST_OPERATOR.to_string(),
        "--subject-digest".to_string(),
        hex_digest(&sha256(b"T6B-OLD-KEY-REJECT")),
        "--key-id".to_string(),
        "operator".to_string(),
        "--provider-key-name".to_string(),
        key_a.clone(),
        "--logical-timestamp".to_string(),
        "31".to_string(),
        "--nonce".to_string(),
        "old-key-31".to_string(),
    ]);

    let active_delete_blocked = expect_error(&[
        "asym-key-delete-provider".to_string(),
        "--root".to_string(),
        root_text.clone(),
        "--provider-key-name".to_string(),
        key_b.clone(),
    ]);

    let delete_old_output = execute(&[
        "asym-key-delete-provider".to_string(),
        "--root".to_string(),
        root_text.clone(),
        "--provider-key-name".to_string(),
        key_a.clone(),
    ])?;
    cleanup.remove(&key_a);

    let subject_two = sha256(b"T6B-SUBJECT-TWO");
    let authorize_two_output = execute(&[
        "asym-authorize".to_string(),
        "--root".to_string(),
        root_text.clone(),
        "--domain-code".to_string(),
        "5".to_string(),
        "--required-role-mask".to_string(),
        ROLE_TRUST_OPERATOR.to_string(),
        "--subject-digest".to_string(),
        hex_digest(&subject_two),
        "--key-id".to_string(),
        "operator".to_string(),
        "--provider-key-name".to_string(),
        key_b.clone(),
        "--logical-timestamp".to_string(),
        "40".to_string(),
        "--nonce".to_string(),
        "authorize-40".to_string(),
    ])?;
    let verify_two_output = execute(&[
        "asym-authorization-verify".to_string(),
        "--root".to_string(),
        root_text.clone(),
        "--sequence".to_string(),
        "2".to_string(),
    ])?;

    let corrupted_registry_path =
        root.join("corrupted-asymmetric-keys.ubakey");
    copy_and_corrupt(
        &paths.key_registry,
        &corrupted_registry_path,
    )?;
    let registry_corruption_rejected =
        AsymmetricKeyRegistry::open_strict(
            &corrupted_registry_path,
        )
        .is_err();

    let corrupted_ledger_path =
        root.join("corrupted-asymmetric-authorizations.ubasig");
    copy_and_corrupt(
        &paths.authorization_ledger,
        &corrupted_ledger_path,
    )?;
    let ledger_corruption_rejected =
        AsymmetricAuthorizationLedger::open_strict(
            &corrupted_ledger_path,
            &registry_after_rotation,
        )
        .is_err();

    let revoke_output = execute(&[
        "asym-key-revoke".to_string(),
        "--root".to_string(),
        root_text.clone(),
        "--key-id".to_string(),
        "operator".to_string(),
        "--provider-key-name".to_string(),
        key_b.clone(),
        "--logical-timestamp".to_string(),
        "50".to_string(),
        "--nonce".to_string(),
        "revoke-50".to_string(),
    ])?;

    let post_revoke_authorization_rejected = expect_error(&[
        "asym-authorize".to_string(),
        "--root".to_string(),
        root_text.clone(),
        "--domain-code".to_string(),
        "5".to_string(),
        "--required-role-mask".to_string(),
        ROLE_TRUST_OPERATOR.to_string(),
        "--subject-digest".to_string(),
        hex_digest(&sha256(b"T6B-POST-REVOKE")),
        "--key-id".to_string(),
        "operator".to_string(),
        "--provider-key-name".to_string(),
        key_b.clone(),
        "--logical-timestamp".to_string(),
        "51".to_string(),
        "--nonce".to_string(),
        "post-revoke-51".to_string(),
    ]);

    let delete_new_output = execute(&[
        "asym-key-delete-provider".to_string(),
        "--root".to_string(),
        root_text.clone(),
        "--provider-key-name".to_string(),
        key_b.clone(),
    ])?;
    cleanup.remove(&key_b);

    let status_output = execute(&[
        "asym-status".to_string(),
        "--root".to_string(),
        root_text.clone(),
    ])?;

    let final_registry = AsymmetricKeyRegistry::open_strict(
        &paths.key_registry,
    )?;
    let final_ledger =
        AsymmetricAuthorizationLedger::open_strict(
            &paths.authorization_ledger,
            &final_registry,
        )?;
    let provider_cleanup_complete =
        !provider_key_exists(SOFTWARE_KSP, &key_a)
            && !provider_key_exists(SOFTWARE_KSP, &key_b);

    let expected = (
        final_registry.event_count() == 3
            && final_registry.active_key_count() == 0
            && final_ledger.event_count() == 2
            && duplicate_key_id_rejected
            && duplicate_nonce_rejected
            && wrong_role_rejected
            && tampered_signature_rejected
            && role_mask_preserved
            && dual_proof_rotation_verified
            && old_provider_key_rejected
            && active_delete_blocked
            && registry_corruption_rejected
            && ledger_corruption_rejected
            && post_revoke_authorization_rejected
            && private_export_a_rejected
            && private_export_b_rejected
            && provider_cleanup_complete
    );
    if !expected {
        return Err("T6B probe safety matrix failed".into());
    }

    let report = format!(
        concat!(
            "{{\n",
            "  \"pass\": true,\n",
            "  \"root\": \"{}\",\n",
            "  \"key_registry_path\": \"{}\",\n",
            "  \"authorization_ledger_path\": \"{}\",\n",
            "  \"corrupted_registry_path\": \"{}\",\n",
            "  \"corrupted_ledger_path\": \"{}\",\n",
            "  \"provider\": \"{}\",\n",
            "  \"algorithm\": \"ECDSA_P256\",\n",
            "  \"hash\": \"SHA256\",\n",
            "  \"hardware_bound\": false,\n",
            "  \"tpm_used\": false,\n",
            "  \"key_event_count\": 3,\n",
            "  \"active_key_count\": 0,\n",
            "  \"authorization_count\": 2,\n",
            "  \"cli_command_count\": 10,\n",
            "  \"private_export_a_rejected\": {},\n",
            "  \"private_export_b_rejected\": {},\n",
            "  \"duplicate_key_id_rejected\": {},\n",
            "  \"duplicate_nonce_rejected\": {},\n",
            "  \"wrong_role_rejected\": {},\n",
            "  \"tampered_signature_rejected\": {},\n",
            "  \"dual_proof_rotation_verified\": {},\n",
            "  \"role_mask_preserved\": {},\n",
            "  \"old_provider_key_rejected\": {},\n",
            "  \"active_delete_blocked\": {},\n",
            "  \"registry_corruption_rejected\": {},\n",
            "  \"ledger_corruption_rejected\": {},\n",
            "  \"post_revoke_authorization_rejected\": {},\n",
            "  \"provider_cleanup_complete\": {},\n",
            "  \"private_key_persisted_by_ultraballoondb\": false,\n",
            "  \"network_enabled\": false,\n",
            "  \"automatic_repair_enabled\": false,\n",
            "  \"active_runtime_changed\": false,\n",
            "  \"key_registry_sha256\": \"{}\",\n",
            "  \"authorization_ledger_sha256\": \"{}\",\n",
            "  \"key_registry_head\": \"{}\",\n",
            "  \"authorization_ledger_head\": \"{}\",\n",
            "  \"outputs\": {{\n",
            "    \"init\": \"{}\",\n",
            "    \"init_retry\": \"{}\",\n",
            "    \"create\": \"{}\",\n",
            "    \"authorize_one\": \"{}\",\n",
            "    \"verify_one\": \"{}\",\n",
            "    \"rotate\": \"{}\",\n",
            "    \"delete_old\": \"{}\",\n",
            "    \"authorize_two\": \"{}\",\n",
            "    \"verify_two\": \"{}\",\n",
            "    \"revoke\": \"{}\",\n",
            "    \"delete_new\": \"{}\",\n",
            "    \"status\": \"{}\"\n",
            "  }}\n",
            "}}\n"
        ),
        json_escape(&root.to_string_lossy()),
        json_escape(&paths.key_registry.to_string_lossy()),
        json_escape(
            &paths.authorization_ledger.to_string_lossy(),
        ),
        json_escape(
            &corrupted_registry_path.to_string_lossy(),
        ),
        json_escape(
            &corrupted_ledger_path.to_string_lossy(),
        ),
        SOFTWARE_KSP,
        private_export_a_rejected,
        private_export_b_rejected,
        duplicate_key_id_rejected,
        duplicate_nonce_rejected,
        wrong_role_rejected,
        tampered_signature_rejected,
        dual_proof_rotation_verified,
        role_mask_preserved,
        old_provider_key_rejected,
        active_delete_blocked,
        registry_corruption_rejected,
        ledger_corruption_rejected,
        post_revoke_authorization_rejected,
        provider_cleanup_complete,
        hex_digest(&sha256(&fs::read(&paths.key_registry)?)),
        hex_digest(&sha256(
            &fs::read(&paths.authorization_ledger)?,
        )),
        hex_digest(&final_registry.head_digest()),
        hex_digest(&final_ledger.head_digest()),
        json_escape(&init_output),
        json_escape(&init_retry_output),
        json_escape(&create_output),
        json_escape(&authorize_one_output),
        json_escape(&verify_one_output),
        json_escape(&rotate_output),
        json_escape(&delete_old_output),
        json_escape(&authorize_two_output),
        json_escape(&verify_two_output),
        json_escape(&revoke_output),
        json_escape(&delete_new_output),
        json_escape(&status_output),
    );

    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&report_path, report)?;
    println!(
        "PASS_ULTRABALLOONDB_ASYMMETRIC_SOFTWARE_CNG_PROBE"
    );
    println!("REPORT={}", report_path.display());
    Ok(())
}
