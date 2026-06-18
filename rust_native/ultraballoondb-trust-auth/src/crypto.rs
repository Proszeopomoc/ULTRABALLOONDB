use ultraballoondb_storage::sha256;

use crate::{AuthError, Result};

pub const MIN_SECRET_BYTES: usize = 32;
pub const MAX_SECRET_BYTES: usize = 4096;
pub const HMAC_BLOCK_BYTES: usize = 64;
pub const SIGNATURE_DOMAIN: [u8; 8] = *b"UBAUTSG1";
pub const KEY_REGISTER_DOMAIN: [u8; 8] = *b"UBKEYSUB";
pub const KEY_REVOKE_DOMAIN: [u8; 8] = *b"UBKEYREV";
pub const TRUST_REQUEST_DOMAIN: [u8; 8] = *b"UBTRQA01";

pub fn validate_secret(secret: &[u8]) -> Result<()> {
    if secret.len() < MIN_SECRET_BYTES {
        return Err(AuthError::Invalid(format!(
            "secret must contain at least {MIN_SECRET_BYTES} bytes",
        )));
    }
    if secret.len() > MAX_SECRET_BYTES {
        return Err(AuthError::Invalid(format!(
            "secret exceeds maximum {MAX_SECRET_BYTES} bytes",
        )));
    }
    Ok(())
}

pub fn key_fingerprint(secret: &[u8]) -> Result<[u8; 32]> {
    validate_secret(secret)?;
    Ok(sha256(secret))
}

pub fn hmac_sha256(secret: &[u8], message: &[u8]) -> Result<[u8; 32]> {
    validate_secret(secret)?;
    let mut key_block = [0u8; HMAC_BLOCK_BYTES];
    if secret.len() > HMAC_BLOCK_BYTES {
        key_block[..32].copy_from_slice(&sha256(secret));
    } else {
        key_block[..secret.len()].copy_from_slice(secret);
    }

    let mut inner_pad = [0x36u8; HMAC_BLOCK_BYTES];
    let mut outer_pad = [0x5Cu8; HMAC_BLOCK_BYTES];
    for index in 0..HMAC_BLOCK_BYTES {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
    }

    let mut inner = Vec::with_capacity(HMAC_BLOCK_BYTES + message.len());
    inner.extend_from_slice(&inner_pad);
    inner.extend_from_slice(message);
    let inner_digest = sha256(&inner);

    let mut outer = Vec::with_capacity(HMAC_BLOCK_BYTES + 32);
    outer.extend_from_slice(&outer_pad);
    outer.extend_from_slice(&inner_digest);
    Ok(sha256(&outer))
}

pub fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

pub fn signature_message(
    domain_code: u8,
    required_role: u16,
    logical_timestamp: u64,
    subject_digest: [u8; 32],
    fingerprint: [u8; 32],
    key_registry_head: [u8; 32],
    key_id: &str,
    nonce: &str,
) -> Result<Vec<u8>> {
    validate_identifier("key_id", key_id)?;
    validate_identifier("nonce", nonce)?;
    let key_id_bytes = key_id.as_bytes();
    let nonce_bytes = nonce.as_bytes();
    let mut output = Vec::new();
    output.extend_from_slice(&SIGNATURE_DOMAIN);
    output.push(domain_code);
    output.push(0);
    output.extend_from_slice(&required_role.to_le_bytes());
    output.extend_from_slice(&logical_timestamp.to_le_bytes());
    output.extend_from_slice(&subject_digest);
    output.extend_from_slice(&fingerprint);
    output.extend_from_slice(&key_registry_head);
    output.extend_from_slice(&(key_id_bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(&(nonce_bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(key_id_bytes);
    output.extend_from_slice(nonce_bytes);
    Ok(output)
}

pub fn sign_authorization(
    secret: &[u8],
    domain_code: u8,
    required_role: u16,
    logical_timestamp: u64,
    subject_digest: [u8; 32],
    key_registry_head: [u8; 32],
    key_id: &str,
    nonce: &str,
) -> Result<([u8; 32], [u8; 32])> {
    let fingerprint = key_fingerprint(secret)?;
    let message = signature_message(
        domain_code,
        required_role,
        logical_timestamp,
        subject_digest,
        fingerprint,
        key_registry_head,
        key_id,
        nonce,
    )?;
    let signature = hmac_sha256(secret, &message)?;
    Ok((fingerprint, signature))
}

pub fn key_register_subject(
    key_id: &str,
    fingerprint: [u8; 32],
    role_mask: u16,
) -> Result<[u8; 32]> {
    validate_identifier("target_key_id", key_id)?;
    let key_id_bytes = key_id.as_bytes();
    let mut output = Vec::new();
    output.extend_from_slice(&KEY_REGISTER_DOMAIN);
    output.extend_from_slice(&role_mask.to_le_bytes());
    output.extend_from_slice(&(key_id_bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(&fingerprint);
    output.extend_from_slice(key_id_bytes);
    Ok(sha256(&output))
}

pub fn key_revoke_subject(
    key_id: &str,
    fingerprint: [u8; 32],
) -> Result<[u8; 32]> {
    validate_identifier("target_key_id", key_id)?;
    let key_id_bytes = key_id.as_bytes();
    let mut output = Vec::new();
    output.extend_from_slice(&KEY_REVOKE_DOMAIN);
    output.extend_from_slice(&(key_id_bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(&fingerprint);
    output.extend_from_slice(key_id_bytes);
    Ok(sha256(&output))
}

pub fn validate_identifier(name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(AuthError::Invalid(format!("{name} cannot be empty")));
    }
    if value.as_bytes().len() > 1024 * 1024 {
        return Err(AuthError::Invalid(format!(
            "{name} exceeds maximum length",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4231_case_one() {
        let key = [0x0Bu8; 20];
        assert!(validate_secret(&key).is_err());

        let long_key = [0x0Bu8; 32];
        let digest = hmac_sha256(&long_key, b"Hi There").unwrap();
        assert_eq!(
            hex(&digest),
            "198A607EB44BFBC69903A0F1CF2BBDC5BA0AA3F3D9AE3C1C7A3B1696A0B68CF7",
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|value| format!("{value:02X}")).collect()
    }
}
