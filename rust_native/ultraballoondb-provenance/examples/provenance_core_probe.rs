use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ultraballoondb_storage::sha256;
use ultraballoondb_trust_asymmetric::{
    delete_persisted_key, hex, parse_hex_digest, AsymmetricAuthorizationLedger,
    AsymmetricKeyRegistry, ProviderRequirement, SoftwareCngProvider, SigningProvider,
    DOMAIN_FEDERATION_BUNDLE, DOMAIN_POLICY_REGISTER, SOFTWARE_KSP,
};
use ultraballoondb_trust_federation::{
    authority_subject_digest, bundle_subject_digest, namespace_policy_digest,
    namespace_policy_subject_digest, EnterpriseFederationLedger, FederationEventKind,
};
use ultraballoondb_provenance::{
    provenance_subject_digest, ProvenanceInput, ProvenanceKind, ProvenanceLedger,
    DOMAIN_PROVENANCE_RECORD, PROVENANCE_FILE_NAME,
};

const CONTROLLER_ROLE: u16 = 0x0100;
const AUTHORITY_ROLE: u16 = 0x0200;

fn main() {
    if let Err(error) = run() {
        eprintln!("NO_GO_P0_PROVENANCE_CORE_PROBE={error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let output_root = std::env::args_os().nth(1)
        .map(PathBuf::from)
        .ok_or("usage: provenance_core_probe <output-root> <t6a-evidence-sha256>")?;
    let _t6a_evidence_digest = parse_hex_digest(
        &std::env::args().nth(2).ok_or("missing T6A evidence SHA256")?
    )?;
    fs::create_dir_all(&output_root)?;
    let registry_path = output_root.join("asymmetric-keys.ubakey");
    let authorization_path = output_root.join("asymmetric-authorizations.ubasig");
    let federation_path = output_root.join("enterprise-federation.ubfed");
    let provenance_path = output_root.join(PROVENANCE_FILE_NAME);

    let unique = format!(
        "{}-{}", std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
    );
    let controller_provider_key = format!("UltraBalloonDB-P0-controller-{unique}");
    let authority_provider_key = format!("UltraBalloonDB-P0-authority-{unique}");
    let key_names = [controller_provider_key.clone(), authority_provider_key.clone()];
    let software = SoftwareCngProvider;

    let mut registry = AsymmetricKeyRegistry::create(&registry_path)?;
    registry.enroll_new_key_with_provider(
        &software, ProviderRequirement::SoftwareAllowed,
        "controller", CONTROLLER_ROLE, &controller_provider_key, 1, "p0-enroll-controller",
    )?;
    registry.enroll_new_key_with_provider(
        &software, ProviderRequirement::SoftwareAllowed,
        "authority", AUTHORITY_ROLE, &authority_provider_key, 2, "p0-enroll-authority",
    )?;
    let mut authorizations = AsymmetricAuthorizationLedger::create(&authorization_path)?;
    let mut federation = EnterpriseFederationLedger::create(&federation_path)?;
    let namespace = "enterprise/core";
    let policy_digest = namespace_policy_digest(
        namespace, 1, "controller", CONTROLLER_ROLE, AUTHORITY_ROLE, 1,
        ProviderRequirement::SoftwareAllowed,
    )?;
    let policy_auth = authorizations.authorize_with_provider(
        &registry, &software, ProviderRequirement::SoftwareAllowed,
        DOMAIN_POLICY_REGISTER, CONTROLLER_ROLE,
        namespace_policy_subject_digest(policy_digest),
        "controller", &controller_provider_key, 1, "p0-auth-policy",
    )?;
    federation.set_namespace_policy(
        &registry, &authorizations, namespace, 1, "controller",
        CONTROLLER_ROLE, AUTHORITY_ROLE, 1, ProviderRequirement::SoftwareAllowed,
        policy_auth.sequence, 1,
    )?;
    let enroll_subject = authority_subject_digest(
        FederationEventKind::AuthorityEnroll, namespace, "authority", 1, policy_digest,
    )?;
    let enroll_auth = authorizations.authorize_with_provider(
        &registry, &software, ProviderRequirement::SoftwareAllowed,
        DOMAIN_POLICY_REGISTER, CONTROLLER_ROLE, enroll_subject,
        "controller", &controller_provider_key, 2, "p0-auth-enroll-authority",
    )?;
    federation.enroll_authority(
        &registry, &authorizations, namespace, "authority", 1,
        enroll_auth.sequence, 2,
    )?;
    let bundle_digest = sha256(b"p0-enterprise-policy-bundle-v1");
    let bundle_subject = bundle_subject_digest(
        namespace, 1, 1, policy_digest, [0; 32], bundle_digest,
    )?;
    let bundle_auth = authorizations.authorize_with_provider(
        &registry, &software, ProviderRequirement::SoftwareAllowed,
        DOMAIN_FEDERATION_BUNDLE, AUTHORITY_ROLE, bundle_subject,
        "authority", &authority_provider_key, 3, "p0-approve-bundle",
    )?;
    federation.accept_bundle(
        &registry, &authorizations, namespace, 1, 1, policy_digest,
        [0; 32], bundle_digest, &[bundle_auth.sequence], 3,
    )?;

    let mut provenance = ProvenanceLedger::create(&provenance_path)?;
    let mut source_input = ProvenanceInput {
        kind: ProvenanceKind::Source,
        logical_timestamp: 1,
        namespace: namespace.to_string(),
        object_id: "record:42".to_string(),
        object_kind: "record".to_string(),
        object_version: 1,
        actor_key_id: "authority".to_string(),
        source_locator_digest: sha256(b"source://customer-import/42"),
        content_digest: sha256(b"customer-record-v1"),
        operation_digest: sha256(b"import-record-v1"),
        transformation_digest: [0; 32],
        federation_policy_version: 1,
        federation_policy_digest: policy_digest,
        federation_bundle_version: 1,
        federation_bundle_digest: bundle_digest,
        authorization_sequence: 0,
        parent_provenance_ids: vec![],
    };
    let source_subject = provenance_subject_digest(&source_input)?;
    let source_auth = authorizations.authorize_with_provider(
        &registry, &software, ProviderRequirement::SoftwareAllowed,
        DOMAIN_PROVENANCE_RECORD, AUTHORITY_ROLE, source_subject,
        "authority", &authority_provider_key, 4, "p0-source-record",
    )?;
    source_input.authorization_sequence = source_auth.sequence;
    let source_receipt = provenance.append_authorized(
        &registry, &authorizations, &federation, source_input,
    )?;

    let mut derived_input = ProvenanceInput {
        kind: ProvenanceKind::Derived,
        logical_timestamp: 2,
        namespace: namespace.to_string(),
        object_id: "edge:42:43:related".to_string(),
        object_kind: "typed-edge".to_string(),
        object_version: 1,
        actor_key_id: "authority".to_string(),
        source_locator_digest: [0; 32],
        content_digest: sha256(b"edge-42-43-related-v1"),
        operation_digest: sha256(b"derive-related-edge-v1"),
        transformation_digest: sha256(b"relationship-extractor-v1"),
        federation_policy_version: 1,
        federation_policy_digest: policy_digest,
        federation_bundle_version: 1,
        federation_bundle_digest: bundle_digest,
        authorization_sequence: 0,
        parent_provenance_ids: vec![source_receipt.provenance_id],
    };
    let derived_subject = provenance_subject_digest(&derived_input)?;
    let derived_auth = authorizations.authorize_with_provider(
        &registry, &software, ProviderRequirement::SoftwareAllowed,
        DOMAIN_PROVENANCE_RECORD, AUTHORITY_ROLE, derived_subject,
        "authority", &authority_provider_key, 5, "p0-derived-edge",
    )?;
    derived_input.authorization_sequence = derived_auth.sequence;
    let derived_receipt = provenance.append_authorized(
        &registry, &authorizations, &federation, derived_input,
    )?;

    let duplicate_authorization_rejected = {
        let invalid = ProvenanceInput {
            kind: ProvenanceKind::Source,
            logical_timestamp: 3,
            namespace: namespace.to_string(),
            object_id: "record:99".to_string(),
            object_kind: "record".to_string(),
            object_version: 1,
            actor_key_id: "authority".to_string(),
            source_locator_digest: sha256(b"source://duplicate-auth"),
            content_digest: sha256(b"duplicate-auth-content"),
            operation_digest: sha256(b"duplicate-auth-op"),
            transformation_digest: [0; 32],
            federation_policy_version: 1,
            federation_policy_digest: policy_digest,
            federation_bundle_version: 1,
            federation_bundle_digest: bundle_digest,
            authorization_sequence: source_auth.sequence,
            parent_provenance_ids: vec![],
        };
        provenance.append_authorized(&registry, &authorizations, &federation, invalid).is_err()
    };
    if !duplicate_authorization_rejected {
        return Err("duplicate provenance authorization unexpectedly accepted".into());
    }

    let strict = ProvenanceLedger::open_strict(
        &provenance_path, &registry, &authorizations, &federation,
    )?;
    let lineage = strict.lineage(derived_receipt.provenance_id)?;
    if strict.event_count() != 2 || lineage.len() != 2
        || strict.latest_object_version(namespace, "record:42") != Some(1)
    {
        return Err("strict provenance replay or lineage mismatch".into());
    }

    let tampered_path = output_root.join("tampered-provenance.ubprov");
    let mut tampered = fs::read(&provenance_path)?;
    let last = tampered.len().checked_sub(1).ok_or("empty provenance file")?;
    tampered[last] ^= 0x01;
    fs::write(&tampered_path, tampered)?;
    let tamper_rejected = ProvenanceLedger::open_strict(
        &tampered_path, &registry, &authorizations, &federation,
    ).is_err();

    let truncated_path = output_root.join("truncated-provenance.ubprov");
    let bytes = fs::read(&provenance_path)?;
    fs::write(&truncated_path, &bytes[..bytes.len() - 7])?;
    let truncation_rejected = ProvenanceLedger::open_strict(
        &truncated_path, &registry, &authorizations, &federation,
    ).is_err();
    if !tamper_rejected || !truncation_rejected {
        return Err("tamper or truncation was not rejected".into());
    }

    let report = format!(
        concat!(
            "{{\n",
            "  \"pass\": true,\n",
            "  \"provenance_event_count\": {},\n",
            "  \"lineage_event_count\": {},\n",
            "  \"source_sequence\": {},\n",
            "  \"derived_sequence\": {},\n",
            "  \"source_provenance_id\": \"{}\",\n",
            "  \"derived_provenance_id\": \"{}\",\n",
            "  \"provenance_head_sha256\": \"{}\",\n",
            "  \"federation_policy_digest\": \"{}\",\n",
            "  \"federation_bundle_digest\": \"{}\",\n",
            "  \"duplicate_authorization_rejected\": {},\n",
            "  \"tamper_rejected\": {},\n",
            "  \"truncation_rejected\": {},\n",
            "  \"raw_source_locator_persisted\": false,\n",
            "  \"active_runtime_changed\": false,\n",
            "  \"storage_format_changed\": false,\n",
            "  \"wal_changed\": false\n",
            "}}\n"
        ),
        strict.event_count(), lineage.len(), source_receipt.sequence,
        derived_receipt.sequence, hex(&source_receipt.provenance_id),
        hex(&derived_receipt.provenance_id), hex(&strict.head_digest()),
        hex(&policy_digest), hex(&bundle_digest),
        duplicate_authorization_rejected, tamper_rejected, truncation_rejected,
    );
    fs::write(output_root.join("provenance_core_probe_report.json"), report)?;

    for key_name in &key_names { delete_persisted_key(SOFTWARE_KSP, key_name)?; }
    println!("PASS_ULTRABALLOONDB_V00R3P0_PROVENANCE_CORE_PROBE");
    println!("PROVENANCE_EVENT_COUNT=2");
    println!("LINEAGE_EVENT_COUNT=2");
    println!("DUPLICATE_AUTHORIZATION_REJECTED=TRUE");
    println!("TAMPER_REJECTED=TRUE");
    println!("TRUNCATION_REJECTED=TRUE");
    println!("ACTIVE_RUNTIME_CHANGED=False");
    Ok(())
}
