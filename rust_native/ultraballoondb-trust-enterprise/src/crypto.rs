use ultraballoondb_storage::sha256;
use ultraballoondb_trust_auth::{
    hmac_sha256, key_fingerprint,
};

use crate::{EnterpriseError, Result};

pub const PROFILE_SUBJECT_DOMAIN: [u8; 8] = *b"UBENPR01";
pub const PROFILE_SIGNATURE_DOMAIN: [u8; 8] = *b"UBENSG01";
pub const REQUEST_ID_DOMAIN: [u8; 8] = *b"UBAPRQ01";
pub const APPROVAL_SIGNATURE_DOMAIN: [u8; 8] = *b"UBAPSG01";
pub const OPERATION_REFERENCE_DOMAIN: [u8; 8] = *b"UBAPOP01";
pub const ENTERPRISE_AUDIT_ROOT_DOMAIN: [u8; 8] = *b"UBEAUD01";

pub fn validate_identifier(
    name: &str,
    value: &str,
) -> Result<()> {
    if value.is_empty() || value.len() > 1024 {
        return Err(EnterpriseError::Invalid(format!(
            "{name} must contain 1..1024 UTF-8 bytes",
        )));
    }
    if value.chars().any(|character| character.is_control()) {
        return Err(EnterpriseError::Invalid(format!(
            "{name} contains a control character",
        )));
    }
    Ok(())
}

pub fn profile_subject_digest(
    profile_id: &str,
    threshold: u16,
    approver_role_mask: u16,
    max_logical_ttl: u64,
    protected_domain_mask: u64,
    requester_excluded: bool,
    distinct_approvers: bool,
    one_time_finalization: bool,
) -> Result<[u8; 32]> {
    validate_identifier("profile_id", profile_id)?;
    if threshold < 2 {
        return Err(EnterpriseError::Invalid(
            "enterprise threshold must be at least 2".to_string(),
        ));
    }
    if approver_role_mask == 0
        || max_logical_ttl == 0
        || protected_domain_mask == 0
    {
        return Err(EnterpriseError::Invalid(
            "enterprise profile contains a zero requirement".to_string(),
        ));
    }
    let profile_id_bytes = profile_id.as_bytes();
    let mut output = Vec::new();
    output.extend_from_slice(&PROFILE_SUBJECT_DOMAIN);
    output.extend_from_slice(&threshold.to_le_bytes());
    output.extend_from_slice(&approver_role_mask.to_le_bytes());
    output.extend_from_slice(&max_logical_ttl.to_le_bytes());
    output.extend_from_slice(&protected_domain_mask.to_le_bytes());
    output.push(u8::from(requester_excluded));
    output.push(u8::from(distinct_approvers));
    output.push(u8::from(one_time_finalization));
    output.extend_from_slice(&[0; 5]);
    output.extend_from_slice(&(profile_id_bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(profile_id_bytes);
    Ok(sha256(&output))
}


pub fn profile_signature_message(
    profile_digest: [u8; 32],
    activated_at: u64,
    signer_fingerprint: [u8; 32],
    key_registry_head: [u8; 32],
    signer_key_id: &str,
    nonce: &str,
) -> Result<Vec<u8>> {
    validate_identifier("signer_key_id", signer_key_id)?;
    validate_identifier("nonce", nonce)?;
    if profile_digest == [0; 32]
        || signer_fingerprint == [0; 32]
        || key_registry_head == [0; 32]
        || activated_at == 0
    {
        return Err(EnterpriseError::Invalid(
            "invalid enterprise profile signature fields".to_string(),
        ));
    }
    let signer = signer_key_id.as_bytes();
    let nonce_bytes = nonce.as_bytes();
    let mut output = Vec::new();
    output.extend_from_slice(&PROFILE_SIGNATURE_DOMAIN);
    output.extend_from_slice(&profile_digest);
    output.extend_from_slice(&activated_at.to_le_bytes());
    output.extend_from_slice(&signer_fingerprint);
    output.extend_from_slice(&key_registry_head);
    output.extend_from_slice(&(signer.len() as u32).to_le_bytes());
    output.extend_from_slice(&(nonce_bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(signer);
    output.extend_from_slice(nonce_bytes);
    Ok(output)
}

pub fn enterprise_signature_message(
    event_kind: u8,
    request_id: [u8; 32],
    profile_digest: [u8; 32],
    subject_digest: [u8; 32],
    operation_reference: [u8; 32],
    logical_timestamp: u64,
    expires_at: u64,
    actor_fingerprint: [u8; 32],
    key_registry_head: [u8; 32],
    requester_id: &str,
    actor_id: &str,
    nonce: &str,
) -> Result<Vec<u8>> {
    validate_identifier("requester_id", requester_id)?;
    validate_identifier("actor_id", actor_id)?;
    validate_identifier("nonce", nonce)?;
    if profile_digest == [0; 32]
        || actor_fingerprint == [0; 32]
        || key_registry_head == [0; 32]
    {
        return Err(EnterpriseError::Invalid(
            "enterprise signature message contains zero digest"
                .to_string(),
        ));
    }
    let requester = requester_id.as_bytes();
    let actor = actor_id.as_bytes();
    let nonce_bytes = nonce.as_bytes();
    let mut output = Vec::new();
    output.extend_from_slice(&APPROVAL_SIGNATURE_DOMAIN);
    output.push(event_kind);
    output.extend_from_slice(&[0; 7]);
    output.extend_from_slice(&request_id);
    output.extend_from_slice(&profile_digest);
    output.extend_from_slice(&subject_digest);
    output.extend_from_slice(&operation_reference);
    output.extend_from_slice(&logical_timestamp.to_le_bytes());
    output.extend_from_slice(&expires_at.to_le_bytes());
    output.extend_from_slice(&actor_fingerprint);
    output.extend_from_slice(&key_registry_head);
    output.extend_from_slice(&(requester.len() as u32).to_le_bytes());
    output.extend_from_slice(&(actor.len() as u32).to_le_bytes());
    output.extend_from_slice(&(nonce_bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(requester);
    output.extend_from_slice(actor);
    output.extend_from_slice(nonce_bytes);
    Ok(output)
}

pub fn request_id(
    profile_digest: [u8; 32],
    domain_code: u8,
    subject_digest: [u8; 32],
    requester_fingerprint: [u8; 32],
    created_at: u64,
    expires_at: u64,
    key_registry_head: [u8; 32],
    requester_id: &str,
    nonce: &str,
) -> Result<[u8; 32]> {
    validate_identifier("requester_id", requester_id)?;
    validate_identifier("nonce", nonce)?;
    if profile_digest == [0; 32]
        || subject_digest == [0; 32]
        || requester_fingerprint == [0; 32]
        || key_registry_head == [0; 32]
        || created_at == 0
        || expires_at <= created_at
    {
        return Err(EnterpriseError::Invalid(
            "invalid approval request identity fields".to_string(),
        ));
    }
    let requester = requester_id.as_bytes();
    let nonce_bytes = nonce.as_bytes();
    let mut output = Vec::new();
    output.extend_from_slice(&REQUEST_ID_DOMAIN);
    output.extend_from_slice(&profile_digest);
    output.push(domain_code);
    output.extend_from_slice(&[0; 7]);
    output.extend_from_slice(&subject_digest);
    output.extend_from_slice(&requester_fingerprint);
    output.extend_from_slice(&created_at.to_le_bytes());
    output.extend_from_slice(&expires_at.to_le_bytes());
    output.extend_from_slice(&key_registry_head);
    output.extend_from_slice(&(requester.len() as u32).to_le_bytes());
    output.extend_from_slice(&(nonce_bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(requester);
    output.extend_from_slice(nonce_bytes);
    Ok(sha256(&output))
}

pub fn sign_enterprise_event(
    secret: &[u8],
    message: &[u8],
) -> Result<([u8; 32], [u8; 32])> {
    let fingerprint = key_fingerprint(secret)
        .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    let signature = hmac_sha256(secret, message)
        .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    Ok((fingerprint, signature))
}

pub fn deterministic_operation_reference(
    request_id: [u8; 32],
    operation_reference: [u8; 32],
) -> [u8; 32] {
    let mut output = Vec::new();
    output.extend_from_slice(&OPERATION_REFERENCE_DOMAIN);
    output.extend_from_slice(&request_id);
    output.extend_from_slice(&operation_reference);
    sha256(&output)
}

pub fn enterprise_audit_root_digest(
    manifest_digest: [u8; 32],
    summary_digest: [u8; 32],
    core_receipt_digest: [u8; 32],
) -> [u8; 32] {
    let mut output = Vec::new();
    output.extend_from_slice(&ENTERPRISE_AUDIT_ROOT_DOMAIN);
    output.extend_from_slice(&manifest_digest);
    output.extend_from_slice(&summary_digest);
    output.extend_from_slice(&core_receipt_digest);
    sha256(&output)
}
