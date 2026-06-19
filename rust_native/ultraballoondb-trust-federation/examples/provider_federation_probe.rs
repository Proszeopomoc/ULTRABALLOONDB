use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ultraballoondb_storage::sha256;
use ultraballoondb_trust_asymmetric::{
    delete_persisted_key, hex, parse_hex_digest, select_provider, AsymmetricAuthorizationLedger,
    AsymmetricKeyRegistry, ProviderClass, ProviderRequirement, SigningProvider,
    SoftwareCngProvider, UnavailableProvider, DOMAIN_FEDERATION_BUNDLE,
    DOMAIN_POLICY_REGISTER, DOMAIN_POLICY_REVOKE, SOFTWARE_KSP,
};
use ultraballoondb_trust_federation::{
    authority_subject_digest, bundle_subject_digest, namespace_policy_digest,
    namespace_policy_subject_digest, EnterpriseFederationLedger,
    FederationEventKind,
};

const CONTROLLER_ROLE: u16 = 0x0100;
const AUTHORITY_ROLE: u16 = 0x0200;

fn main() {
    if let Err(error) = run() {
        eprintln!("NO_GO_T6C_PROVIDER_FEDERATION_PROBE={error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let output_root = std::env::args_os().nth(1)
        .map(PathBuf::from)
        .ok_or("usage: provider_federation_probe <output-root> <t6a-evidence-sha256>")?;
    let t6a_evidence_digest = std::env::args().nth(2)
        .ok_or("missing T6A evidence SHA256")?;
    let t6a_evidence_digest = parse_hex_digest(&t6a_evidence_digest)?;
    fs::create_dir_all(&output_root)?;
    let registry_path = output_root.join("asymmetric-keys.ubakey");
    let authorization_path = output_root.join("asymmetric-authorizations.ubasig");
    let federation_path = output_root.join("enterprise-federation.ubfed");

    let unique = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
    );
    let controller_provider_key = format!("UltraBalloonDB-T6C-controller-{unique}");
    let authority_a_provider_key = format!("UltraBalloonDB-T6C-authority-a-{unique}");
    let authority_b_provider_key = format!("UltraBalloonDB-T6C-authority-b-{unique}");
    let authority_c_provider_key = format!("UltraBalloonDB-T6C-authority-c-{unique}");
    let provider_key_names = [
        controller_provider_key.clone(),
        authority_a_provider_key.clone(),
        authority_b_provider_key.clone(),
        authority_c_provider_key.clone(),
    ];

    let software = SoftwareCngProvider;
    let unavailable_tpm = UnavailableProvider {
        name: "Microsoft Platform Crypto Provider".to_string(),
        class: ProviderClass::Tpm,
        evidence_digest: t6a_evidence_digest,
    };
    let candidates: [&dyn SigningProvider; 2] = [&unavailable_tpm, &software];
    let software_selected = select_provider(
        &candidates,
        ProviderRequirement::SoftwareAllowed,
    )?.capabilities().provider_name == SOFTWARE_KSP;
    let hardware_policy_rejected = select_provider(
        &candidates,
        ProviderRequirement::HardwareRequired,
    ).is_err();
    let tpm_policy_rejected = select_provider(
        &candidates,
        ProviderRequirement::TpmRequired,
    ).is_err();
    if !software_selected || !hardware_policy_rejected || !tpm_policy_rejected {
        return Err("provider selection did not fail closed".into());
    }

    let mut registry = AsymmetricKeyRegistry::create(&registry_path)?;
    registry.enroll_new_key_with_provider(
        &software, ProviderRequirement::SoftwareAllowed,
        "controller", CONTROLLER_ROLE, &controller_provider_key, 1, "key-enroll-controller",
    )?;
    registry.enroll_new_key_with_provider(
        &software, ProviderRequirement::SoftwareAllowed,
        "authority-a", AUTHORITY_ROLE, &authority_a_provider_key, 2, "key-enroll-a",
    )?;
    registry.enroll_new_key_with_provider(
        &software, ProviderRequirement::SoftwareAllowed,
        "authority-b", AUTHORITY_ROLE, &authority_b_provider_key, 3, "key-enroll-b",
    )?;

    let mut authorizations = AsymmetricAuthorizationLedger::create(&authorization_path)?;
    let mut federation = EnterpriseFederationLedger::create(&federation_path)?;
    let namespace = "enterprise/core";
    let policy_digest = namespace_policy_digest(
        namespace, 1, "controller", CONTROLLER_ROLE, AUTHORITY_ROLE, 2,
        ProviderRequirement::SoftwareAllowed,
    )?;
    let policy_subject = namespace_policy_subject_digest(policy_digest);
    let policy_auth = authorizations.authorize_with_provider(
        &registry, &software, ProviderRequirement::SoftwareAllowed,
        DOMAIN_POLICY_REGISTER, CONTROLLER_ROLE, policy_subject,
        "controller", &controller_provider_key, 1, "auth-policy-set",
    )?;
    federation.set_namespace_policy(
        &registry, &authorizations, namespace, 1, "controller",
        CONTROLLER_ROLE, AUTHORITY_ROLE, 2,
        ProviderRequirement::SoftwareAllowed,
        policy_auth.sequence, 1,
    )?;

    let enroll_a_subject = authority_subject_digest(
        FederationEventKind::AuthorityEnroll, namespace, "authority-a", 1, policy_digest,
    )?;
    let enroll_a_auth = authorizations.authorize_with_provider(
        &registry, &software, ProviderRequirement::SoftwareAllowed,
        DOMAIN_POLICY_REGISTER, CONTROLLER_ROLE, enroll_a_subject,
        "controller", &controller_provider_key, 2, "auth-enroll-a",
    )?;
    federation.enroll_authority(
        &registry, &authorizations, namespace, "authority-a", 1,
        enroll_a_auth.sequence, 2,
    )?;

    let enroll_b_subject = authority_subject_digest(
        FederationEventKind::AuthorityEnroll, namespace, "authority-b", 1, policy_digest,
    )?;
    let enroll_b_auth = authorizations.authorize_with_provider(
        &registry, &software, ProviderRequirement::SoftwareAllowed,
        DOMAIN_POLICY_REGISTER, CONTROLLER_ROLE, enroll_b_subject,
        "controller", &controller_provider_key, 3, "auth-enroll-b",
    )?;
    federation.enroll_authority(
        &registry, &authorizations, namespace, "authority-b", 1,
        enroll_b_auth.sequence, 3,
    )?;

    let bundle_1_digest = sha256(b"enterprise-policy-bundle-v1");
    let bundle_1_subject = bundle_subject_digest(
        namespace, 1, 1, policy_digest, [0; 32], bundle_1_digest,
    )?;
    let approve_1_a = authorizations.authorize_with_provider(
        &registry, &software, ProviderRequirement::SoftwareAllowed,
        DOMAIN_FEDERATION_BUNDLE, AUTHORITY_ROLE, bundle_1_subject,
        "authority-a", &authority_a_provider_key, 4, "approve-v1-a",
    )?;
    let approve_1_b = authorizations.authorize_with_provider(
        &registry, &software, ProviderRequirement::SoftwareAllowed,
        DOMAIN_FEDERATION_BUNDLE, AUTHORITY_ROLE, bundle_1_subject,
        "authority-b", &authority_b_provider_key, 5, "approve-v1-b",
    )?;
    federation.accept_bundle(
        &registry, &authorizations, namespace, 1, 1, policy_digest,
        [0; 32], bundle_1_digest,
        &[approve_1_a.sequence, approve_1_b.sequence], 4,
    )?;

    let revoke_b_subject = authority_subject_digest(
        FederationEventKind::AuthorityRevoke, namespace, "authority-b", 1, policy_digest,
    )?;
    let revoke_b_auth = authorizations.authorize_with_provider(
        &registry, &software, ProviderRequirement::SoftwareAllowed,
        DOMAIN_POLICY_REVOKE, CONTROLLER_ROLE, revoke_b_subject,
        "controller", &controller_provider_key, 6, "auth-revoke-b",
    )?;
    federation.revoke_authority(
        &registry, &authorizations, namespace, "authority-b",
        revoke_b_auth.sequence, 5,
    )?;

    let bundle_2_digest = sha256(b"enterprise-policy-bundle-v2");
    let bundle_2_subject = bundle_subject_digest(
        namespace, 1, 2, policy_digest, bundle_1_digest, bundle_2_digest,
    )?;
    let approve_2_a = authorizations.authorize_with_provider(
        &registry, &software, ProviderRequirement::SoftwareAllowed,
        DOMAIN_FEDERATION_BUNDLE, AUTHORITY_ROLE, bundle_2_subject,
        "authority-a", &authority_a_provider_key, 7, "approve-v2-a",
    )?;
    let single_approval_rejected = federation.accept_bundle(
        &registry, &authorizations, namespace, 1, 2, policy_digest,
        bundle_1_digest, bundle_2_digest, &[approve_2_a.sequence], 6,
    ).is_err();
    if !single_approval_rejected {
        return Err("single approval unexpectedly reached quorum".into());
    }

    registry.enroll_new_key_with_provider(
        &software, ProviderRequirement::SoftwareAllowed,
        "authority-c", AUTHORITY_ROLE, &authority_c_provider_key, 4, "key-enroll-c",
    )?;
    let enroll_c_subject = authority_subject_digest(
        FederationEventKind::AuthorityEnroll, namespace, "authority-c", 1, policy_digest,
    )?;
    let enroll_c_auth = authorizations.authorize_with_provider(
        &registry, &software, ProviderRequirement::SoftwareAllowed,
        DOMAIN_POLICY_REGISTER, CONTROLLER_ROLE, enroll_c_subject,
        "controller", &controller_provider_key, 8, "auth-enroll-c",
    )?;
    federation.enroll_authority(
        &registry, &authorizations, namespace, "authority-c", 1,
        enroll_c_auth.sequence, 6,
    )?;
    let approve_2_c = authorizations.authorize_with_provider(
        &registry, &software, ProviderRequirement::SoftwareAllowed,
        DOMAIN_FEDERATION_BUNDLE, AUTHORITY_ROLE, bundle_2_subject,
        "authority-c", &authority_c_provider_key, 9, "approve-v2-c",
    )?;
    federation.accept_bundle(
        &registry, &authorizations, namespace, 1, 2, policy_digest,
        bundle_1_digest, bundle_2_digest,
        &[approve_2_a.sequence, approve_2_c.sequence], 7,
    )?;

    registry.revoke_with_provider(
        &software, "authority-b", &authority_b_provider_key, 5, "key-revoke-b",
    )?;
    registry.revoke_with_provider(
        &software, "authority-a", &authority_a_provider_key, 6, "key-revoke-a",
    )?;
    registry.revoke_with_provider(
        &software, "authority-c", &authority_c_provider_key, 7, "key-revoke-c",
    )?;
    registry.revoke_with_provider(
        &software, "controller", &controller_provider_key, 8, "key-revoke-controller",
    )?;

    let strict_registry = AsymmetricKeyRegistry::open_strict(&registry_path)?;
    let strict_authorizations = AsymmetricAuthorizationLedger::open_strict(
        &authorization_path, &strict_registry,
    )?;
    let strict_federation = EnterpriseFederationLedger::open_strict(
        &federation_path, &strict_registry, &strict_authorizations,
    )?;
    let accepted = strict_federation.accepted_bundles().get(namespace)
        .ok_or("accepted namespace bundle missing")?;
    let counters_ok = strict_registry.event_count() == 8
        && strict_registry.active_key_count() == 0
        && strict_authorizations.event_count() == 9
        && strict_federation.event_count() == 7
        && strict_federation.active_authority_count() == 2
        && strict_federation.accepted_namespace_bundle_count() == 1
        && accepted.bundle_version == 2
        && accepted.bundle_digest == bundle_2_digest;
    if !counters_ok {
        return Err("strict replay counters mismatch".into());
    }

    let report = format!(
        concat!(
            "{{\n",
            "  \"pass\": true,\n",
            "  \"software_provider_selected\": {},\n",
            "  \"hardware_required_rejected\": {},\n",
            "  \"tpm_required_rejected\": {},\n",
            "  \"single_approval_rejected\": {},\n",
            "  \"key_event_count\": {},\n",
            "  \"active_key_count\": {},\n",
            "  \"authorization_event_count\": {},\n",
            "  \"federation_event_count\": {},\n",
            "  \"configured_active_authority_count\": {},\n",
            "  \"effective_active_authority_count\": 0,\n",
            "  \"accepted_namespace_bundle_count\": {},\n",
            "  \"accepted_bundle_version\": {},\n",
            "  \"registry_head_sha256\": \"{}\",\n",
            "  \"authorization_head_sha256\": \"{}\",\n",
            "  \"federation_head_sha256\": \"{}\",\n",
            "  \"policy_digest\": \"{}\",\n",
            "  \"accepted_bundle_digest\": \"{}\",\n",
            "  \"hardware_bound\": false,\n",
            "  \"tpm_used\": false,\n",
            "  \"network_used\": false,\n",
            "  \"active_runtime_changed\": false\n",
            "}}\n"
        ),
        software_selected,
        hardware_policy_rejected,
        tpm_policy_rejected,
        single_approval_rejected,
        strict_registry.event_count(),
        strict_registry.active_key_count(),
        strict_authorizations.event_count(),
        strict_federation.event_count(),
        strict_federation.active_authority_count(),
        strict_federation.accepted_namespace_bundle_count(),
        accepted.bundle_version,
        hex(&strict_registry.head_digest()),
        hex(&strict_authorizations.head_digest()),
        hex(&strict_federation.head_digest()),
        hex(&policy_digest),
        hex(&accepted.bundle_digest),
    );
    fs::write(output_root.join("provider_federation_probe_report.json"), report)?;

    for key_name in &provider_key_names {
        delete_persisted_key(SOFTWARE_KSP, key_name)?;
    }
    println!("PASS_ULTRABALLOONDB_V00R3T6C_PROVIDER_FEDERATION_PROBE");
    println!("KEY_EVENT_COUNT=8");
    println!("AUTHORIZATION_EVENT_COUNT=9");
    println!("FEDERATION_EVENT_COUNT=7");
    println!("CONFIGURED_ACTIVE_AUTHORITY_COUNT=2");
    println!("EFFECTIVE_ACTIVE_AUTHORITY_COUNT=0");
    println!("ACCEPTED_BUNDLE_VERSION=2");
    println!("HARDWARE_REQUIRED_REJECTED=TRUE");
    println!("TPM_REQUIRED_REJECTED=TRUE");
    Ok(())
}
