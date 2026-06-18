use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ultraballoondb_storage::sha256;
use ultraballoondb_trust_auth::{
    KeyRegistry, ROLE_AUDITOR, ROLE_KEY_ADMIN,
};

use crate::crypto::{
    profile_signature_message, profile_subject_digest,
    sign_enterprise_event, validate_identifier,
};
use crate::{EnterpriseError, Result};

pub const ENTERPRISE_PROFILE_ID: &str =
    "ENTERPRISE_STRICT_V1";
pub const ENTERPRISE_APPROVAL_THRESHOLD: u16 = 2;
pub const ENTERPRISE_APPROVER_ROLE_MASK: u16 = ROLE_AUDITOR;
pub const ENTERPRISE_MAX_LOGICAL_TTL: u64 = 1000;
pub const ENTERPRISE_REQUESTER_EXCLUDED: bool = true;
pub const ENTERPRISE_DISTINCT_APPROVERS: bool = true;
pub const ENTERPRISE_ONE_TIME_FINALIZATION: bool = true;

const PROFILE_MAGIC: [u8; 8] = *b"UBENT01\0";
const PROFILE_PAYLOAD_MAGIC: [u8; 8] = *b"UBENP01\0";
const PROFILE_FRAME_DOMAIN: [u8; 8] = *b"UBENTFR1";
const FRAME_HEADER_BYTES: usize = 144;
const PROFILE_FIXED_BYTES: usize = 196;
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnterpriseProfile {
    pub profile_id: String,
    pub approval_threshold: u16,
    pub approver_role_mask: u16,
    pub max_logical_ttl: u64,
    pub protected_domain_mask: u64,
    pub requester_excluded: bool,
    pub distinct_approvers: bool,
    pub one_time_finalization: bool,
    pub activated_at: u64,
    pub signer_key_id: String,
    pub signer_fingerprint: [u8; 32],
    pub key_registry_head: [u8; 32],
    pub nonce: String,
    pub profile_digest: [u8; 32],
    pub signature: [u8; 32],
    pub frame_digest: [u8; 32],
}

impl EnterpriseProfile {
    pub fn strict(activated_at: u64) -> Self {
        Self {
            profile_id: ENTERPRISE_PROFILE_ID.to_string(),
            approval_threshold: ENTERPRISE_APPROVAL_THRESHOLD,
            approver_role_mask: ENTERPRISE_APPROVER_ROLE_MASK,
            max_logical_ttl: ENTERPRISE_MAX_LOGICAL_TTL,
            protected_domain_mask: protected_domain_mask(),
            requester_excluded: ENTERPRISE_REQUESTER_EXCLUDED,
            distinct_approvers: ENTERPRISE_DISTINCT_APPROVERS,
            one_time_finalization: ENTERPRISE_ONE_TIME_FINALIZATION,
            activated_at,
            signer_key_id: String::new(),
            signer_fingerprint: [0; 32],
            key_registry_head: [0; 32],
            nonce: String::new(),
            profile_digest: [0; 32],
            signature: [0; 32],
            frame_digest: [0; 32],
        }
    }

    pub fn covers_domain(&self, domain_code: u8) -> bool {
        if domain_code >= 64 {
            return false;
        }
        self.protected_domain_mask
            & (1u64 << domain_code) != 0
    }

    pub fn validate_static_contract(&self) -> Result<()> {
        validate_identifier("profile_id", &self.profile_id)?;
        validate_identifier("signer_key_id", &self.signer_key_id)?;
        validate_identifier("nonce", &self.nonce)?;
        if self.profile_id != ENTERPRISE_PROFILE_ID
            || self.approval_threshold
                != ENTERPRISE_APPROVAL_THRESHOLD
            || self.approver_role_mask
                != ENTERPRISE_APPROVER_ROLE_MASK
            || self.max_logical_ttl
                != ENTERPRISE_MAX_LOGICAL_TTL
            || self.protected_domain_mask
                != protected_domain_mask()
            || !self.requester_excluded
            || !self.distinct_approvers
            || !self.one_time_finalization
            || self.activated_at == 0
            || self.signer_fingerprint == [0; 32]
            || self.key_registry_head == [0; 32]
            || self.profile_digest == [0; 32]
            || self.signature == [0; 32]
        {
            return Err(EnterpriseError::Invalid(
                "enterprise strict profile contract mismatch".to_string(),
            ));
        }
        let expected = profile_subject_digest(
            &self.profile_id,
            self.approval_threshold,
            self.approver_role_mask,
            self.max_logical_ttl,
            self.protected_domain_mask,
            self.requester_excluded,
            self.distinct_approvers,
            self.one_time_finalization,
        )?;
        if expected != self.profile_digest {
            return Err(EnterpriseError::Integrity(
                "enterprise profile digest mismatch".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnterpriseProfileReceipt {
    pub changed: bool,
    pub path: PathBuf,
    pub profile_digest: [u8; 32],
    pub frame_digest: [u8; 32],
    pub activated_at: u64,
}

pub fn protected_domain_mask() -> u64 {
    (1u64 << 4)
        | (1u64 << 5)
        | (1u64 << 6)
        | (1u64 << 7)
}

pub fn enable_enterprise_profile(
    path: impl AsRef<Path>,
    key_registry_path: impl AsRef<Path>,
    signer_key_id: &str,
    signer_secret: &[u8],
    activated_at: u64,
    nonce: &str,
) -> Result<EnterpriseProfileReceipt> {
    let path = path.as_ref().to_path_buf();
    if path.exists() {
        let profile = open_enterprise_profile(&path)?;
        return Ok(EnterpriseProfileReceipt {
            changed: false,
            path,
            profile_digest: profile.profile_digest,
            frame_digest: profile.frame_digest,
            activated_at: profile.activated_at,
        });
    }

    validate_identifier("signer_key_id", signer_key_id)?;
    validate_identifier("nonce", nonce)?;
    if activated_at == 0 {
        return Err(EnterpriseError::Invalid(
            "enterprise activation timestamp must be non-zero"
                .to_string(),
        ));
    }

    let registry = KeyRegistry::open_strict(key_registry_path)
        .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    let signer = registry.get(signer_key_id).ok_or_else(|| {
        EnterpriseError::Invalid(format!(
            "enterprise profile signer is unknown: {signer_key_id}",
        ))
    })?;
    if !signer.has_role(ROLE_KEY_ADMIN) {
        return Err(EnterpriseError::Invalid(
            "enterprise profile signer must be active KEY_ADMIN"
                .to_string(),
        ));
    }

    let mut profile = EnterpriseProfile::strict(activated_at);
    profile.signer_key_id = signer_key_id.to_string();
    profile.signer_fingerprint = ultraballoondb_trust_auth::key_fingerprint(
        signer_secret,
    )
    .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    if profile.signer_fingerprint != signer.fingerprint {
        return Err(EnterpriseError::Invalid(
            "enterprise profile signer secret mismatch".to_string(),
        ));
    }
    profile.key_registry_head = registry.head_digest();
    profile.nonce = nonce.to_string();
    profile.profile_digest = profile_subject_digest(
        &profile.profile_id,
        profile.approval_threshold,
        profile.approver_role_mask,
        profile.max_logical_ttl,
        profile.protected_domain_mask,
        profile.requester_excluded,
        profile.distinct_approvers,
        profile.one_time_finalization,
    )?;
    let message = profile_signature_message(
        profile.profile_digest,
        profile.activated_at,
        profile.signer_fingerprint,
        profile.key_registry_head,
        &profile.signer_key_id,
        &profile.nonce,
    )?;
    let (fingerprint, signature) =
        sign_enterprise_event(signer_secret, &message)?;
    if fingerprint != profile.signer_fingerprint {
        return Err(EnterpriseError::Invalid(
            "enterprise profile signature fingerprint mismatch"
                .to_string(),
        ));
    }
    profile.signature = signature;

    let payload = encode_profile_payload(&profile)?;
    let payload_digest = sha256(&payload);
    let frame_digest = compute_frame_digest(
        payload_digest,
    );
    profile.frame_digest = frame_digest;
    let frame = encode_frame(
        payload_digest,
        frame_digest,
        &payload,
    )?;
    create_fsync(&path, &frame)?;

    Ok(EnterpriseProfileReceipt {
        changed: true,
        path,
        profile_digest: profile.profile_digest,
        frame_digest,
        activated_at,
    })
}

pub fn open_enterprise_profile(
    path: impl AsRef<Path>,
) -> Result<EnterpriseProfile> {
    let path = path.as_ref();
    if !path.is_file() {
        return Err(EnterpriseError::Invalid(format!(
            "enterprise profile missing: {}",
            path.display(),
        )));
    }
    let bytes = fs::read(path)?;
    if bytes.len() < FRAME_HEADER_BYTES {
        return Err(EnterpriseError::Invalid(
            "enterprise profile frame truncated".to_string(),
        ));
    }
    let header = &bytes[..FRAME_HEADER_BYTES];
    if header[0..8] != PROFILE_MAGIC
        || read_u16(header, 8)? != 1
        || read_u16(header, 10)? != 0
        || read_u32(header, 12)? as usize
            != FRAME_HEADER_BYTES
        || read_u64(header, 16)? != 1
        || read_digest(header, 32)? != [0; 32]
        || header[128..144] != [0; 16]
    {
        return Err(EnterpriseError::Invalid(
            "enterprise profile frame header mismatch".to_string(),
        ));
    }
    let payload_len = usize::try_from(read_u64(header, 24)?)
        .map_err(|_| EnterpriseError::Invalid(
            "enterprise profile payload length overflow".to_string(),
        ))?;
    if payload_len > MAX_PAYLOAD_BYTES
        || bytes.len() != FRAME_HEADER_BYTES + payload_len
    {
        return Err(EnterpriseError::Invalid(
            "enterprise profile payload length mismatch".to_string(),
        ));
    }
    let expected_payload_digest = read_digest(header, 64)?;
    let expected_frame_digest = read_digest(header, 96)?;
    let payload = &bytes[FRAME_HEADER_BYTES..];
    let actual_payload_digest = sha256(payload);
    if actual_payload_digest != expected_payload_digest {
        return Err(EnterpriseError::Integrity(
            "enterprise profile payload digest mismatch".to_string(),
        ));
    }
    let actual_frame_digest = compute_frame_digest(
        expected_payload_digest,
    );
    if actual_frame_digest != expected_frame_digest {
        return Err(EnterpriseError::Integrity(
            "enterprise profile frame digest mismatch".to_string(),
        ));
    }
    let mut profile = decode_profile_payload(payload)?;
    profile.frame_digest = expected_frame_digest;
    profile.validate_static_contract()?;
    Ok(profile)
}

fn encode_profile_payload(
    profile: &EnterpriseProfile,
) -> Result<Vec<u8>> {
    let profile_id = profile.profile_id.as_bytes();
    let signer = profile.signer_key_id.as_bytes();
    let nonce = profile.nonce.as_bytes();
    let flags = u8::from(profile.requester_excluded)
        | (u8::from(profile.distinct_approvers) << 1)
        | (u8::from(profile.one_time_finalization) << 2);
    let mut output = Vec::new();
    output.extend_from_slice(&PROFILE_PAYLOAD_MAGIC);
    output.extend_from_slice(
        &profile.approval_threshold.to_le_bytes(),
    );
    output.extend_from_slice(
        &profile.approver_role_mask.to_le_bytes(),
    );
    output.extend_from_slice(
        &profile.max_logical_ttl.to_le_bytes(),
    );
    output.extend_from_slice(
        &profile.protected_domain_mask.to_le_bytes(),
    );
    output.push(flags);
    output.extend_from_slice(&[0; 7]);
    output.extend_from_slice(
        &profile.activated_at.to_le_bytes(),
    );
    output.extend_from_slice(
        &(profile_id.len() as u32).to_le_bytes(),
    );
    output.extend_from_slice(
        &(signer.len() as u32).to_le_bytes(),
    );
    output.extend_from_slice(
        &(nonce.len() as u32).to_le_bytes(),
    );
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&profile.profile_digest);
    output.extend_from_slice(&profile.signer_fingerprint);
    output.extend_from_slice(&profile.key_registry_head);
    output.extend_from_slice(&profile.signature);
    output.extend_from_slice(&0u64.to_le_bytes());
    debug_assert_eq!(output.len(), PROFILE_FIXED_BYTES);
    output.extend_from_slice(profile_id);
    output.extend_from_slice(signer);
    output.extend_from_slice(nonce);
    Ok(output)
}

fn decode_profile_payload(
    payload: &[u8],
) -> Result<EnterpriseProfile> {
    if payload.len() < PROFILE_FIXED_BYTES
        || payload[0..8] != PROFILE_PAYLOAD_MAGIC
    {
        return Err(EnterpriseError::Invalid(
            "enterprise profile payload header mismatch".to_string(),
        ));
    }
    let approval_threshold = read_u16(payload, 8)?;
    let approver_role_mask = read_u16(payload, 10)?;
    let max_logical_ttl = read_u64(payload, 12)?;
    let protected_domain_mask = read_u64(payload, 20)?;
    let flags = payload[28];
    if flags & !0b111 != 0
        || payload[29..36] != [0; 7]
    {
        return Err(EnterpriseError::Invalid(
            "enterprise profile flags/reserved mismatch".to_string(),
        ));
    }
    let activated_at = read_u64(payload, 36)?;
    let profile_id_len = read_u32(payload, 44)? as usize;
    let signer_len = read_u32(payload, 48)? as usize;
    let nonce_len = read_u32(payload, 52)? as usize;
    if read_u32(payload, 56)? != 0
        || read_u64(payload, 188)? != 0
    {
        return Err(EnterpriseError::Invalid(
            "enterprise profile reserved field non-zero".to_string(),
        ));
    }
    let profile_digest = read_digest(payload, 60)?;
    let signer_fingerprint = read_digest(payload, 92)?;
    let key_registry_head = read_digest(payload, 124)?;
    let signature = read_digest(payload, 156)?;
    let mut cursor = PROFILE_FIXED_BYTES;
    let profile_id = read_string(
        payload,
        &mut cursor,
        profile_id_len,
        "profile_id",
    )?;
    let signer_key_id = read_string(
        payload,
        &mut cursor,
        signer_len,
        "signer_key_id",
    )?;
    let nonce = read_string(
        payload,
        &mut cursor,
        nonce_len,
        "nonce",
    )?;
    if cursor != payload.len() {
        return Err(EnterpriseError::Invalid(
            "enterprise profile trailing bytes".to_string(),
        ));
    }
    Ok(EnterpriseProfile {
        profile_id,
        approval_threshold,
        approver_role_mask,
        max_logical_ttl,
        protected_domain_mask,
        requester_excluded: flags & 1 != 0,
        distinct_approvers: flags & 2 != 0,
        one_time_finalization: flags & 4 != 0,
        activated_at,
        signer_key_id,
        signer_fingerprint,
        key_registry_head,
        nonce,
        profile_digest,
        signature,
        frame_digest: [0; 32],
    })
}

fn compute_frame_digest(
    payload_digest: [u8; 32],
) -> [u8; 32] {
    let mut output = Vec::new();
    output.extend_from_slice(&PROFILE_FRAME_DOMAIN);
    output.extend_from_slice(&1u64.to_le_bytes());
    output.extend_from_slice(&[0; 32]);
    output.extend_from_slice(&payload_digest);
    sha256(&output)
}

fn encode_frame(
    payload_digest: [u8; 32],
    frame_digest: [u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(EnterpriseError::Invalid(
            "enterprise profile payload too large".to_string(),
        ));
    }
    let mut output = Vec::new();
    output.extend_from_slice(&PROFILE_MAGIC);
    output.extend_from_slice(&1u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(
        &(FRAME_HEADER_BYTES as u32).to_le_bytes(),
    );
    output.extend_from_slice(&1u64.to_le_bytes());
    output.extend_from_slice(
        &(payload.len() as u64).to_le_bytes(),
    );
    output.extend_from_slice(&[0; 32]);
    output.extend_from_slice(&payload_digest);
    output.extend_from_slice(&frame_digest);
    output.extend_from_slice(&[0; 16]);
    debug_assert_eq!(output.len(), FRAME_HEADER_BYTES);
    output.extend_from_slice(payload);
    Ok(output)
}

fn create_fsync(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        return Err(EnterpriseError::Invalid(format!(
            "enterprise profile already exists: {}",
            path.display(),
        )));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn read_string(
    bytes: &[u8],
    cursor: &mut usize,
    length: usize,
    name: &str,
) -> Result<String> {
    if length > 1024 * 1024 {
        return Err(EnterpriseError::Invalid(format!(
            "{name} too long",
        )));
    }
    let end = cursor.checked_add(length).ok_or_else(|| {
        EnterpriseError::Invalid(
            "enterprise profile string overflow".to_string(),
        )
    })?;
    let value = bytes.get(*cursor..end).ok_or_else(|| {
        EnterpriseError::Invalid(format!(
            "truncated enterprise profile {name}",
        ))
    })?;
    *cursor = end;
    String::from_utf8(value.to_vec()).map_err(|_| {
        EnterpriseError::Invalid(format!(
            "enterprise profile {name} is not UTF-8",
        ))
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes.get(offset..offset + 2).ok_or_else(|| {
        EnterpriseError::Invalid("truncated u16".to_string())
    })?;
    Ok(u16::from_le_bytes(value.try_into().expect("checked")))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes.get(offset..offset + 4).ok_or_else(|| {
        EnterpriseError::Invalid("truncated u32".to_string())
    })?;
    Ok(u32::from_le_bytes(value.try_into().expect("checked")))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let value = bytes.get(offset..offset + 8).ok_or_else(|| {
        EnterpriseError::Invalid("truncated u64".to_string())
    })?;
    Ok(u64::from_le_bytes(value.try_into().expect("checked")))
}

fn read_digest(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; 32]> {
    let value = bytes.get(offset..offset + 32).ok_or_else(|| {
        EnterpriseError::Invalid(
            "truncated enterprise digest".to_string(),
        )
    })?;
    Ok(value.try_into().expect("checked digest"))
}
