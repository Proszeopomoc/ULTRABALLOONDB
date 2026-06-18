use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ultraballoondb_storage::sha256;
use ultraballoondb_trust_commit::PolicyDefinition;

use crate::crypto::{
    policy_revoke_subject, validate_identifier,
};
use crate::ledger::{
    AuthorizationRecord, DOMAIN_POLICY_REVOKE, ROLE_POLICY_ADMIN,
};
use crate::{AuthError, Result};

const POLICY_STATUS_MAGIC: [u8; 8] = *b"UBPST01\0";
const POLICY_STATUS_PAYLOAD_MAGIC: [u8; 8] = *b"UBPSP01\0";
const POLICY_STATUS_FRAME_DOMAIN: [u8; 8] = *b"UBPSTFR1";
const FRAME_HEADER_BYTES: usize = 144;
const POLICY_STATUS_FIXED_BYTES: usize = 176;
const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PolicyStatusEventKind {
    Revoke = 1,
}

impl PolicyStatusEventKind {
    fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Revoke),
            _ => Err(AuthError::Invalid(format!(
                "unknown policy status event kind {value}",
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Revoke => "POLICY_REVOKE",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyStatusEvent {
    pub sequence: u64,
    pub kind: PolicyStatusEventKind,
    pub policy_id: String,
    pub policy_version: String,
    pub policy_digest: [u8; 32],
    pub reason_code: String,
    pub signer_key_id: String,
    pub signer_fingerprint: [u8; 32],
    pub key_registry_head: [u8; 32],
    pub authorization_event_id: [u8; 32],
    pub logical_timestamp: u64,
    pub previous_digest: [u8; 32],
    pub frame_digest: [u8; 32],
}

#[derive(Debug)]
pub struct PolicyStatusLedger {
    path: PathBuf,
    events: Vec<PolicyStatusEvent>,
    revoked: BTreeMap<(String, String), PolicyStatusEvent>,
    head_digest: [u8; 32],
    last_timestamp: u64,
}

impl PolicyStatusLedger {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        create_empty_file(&path)?;
        Ok(Self {
            path,
            events: Vec::new(),
            revoked: BTreeMap::new(),
            head_digest: [0; 32],
            last_timestamp: 0,
        })
    }

    pub fn open_strict(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.is_file() {
            return Err(AuthError::Invalid(format!(
                "policy status ledger missing: {}",
                path.display(),
            )));
        }
        let bytes = fs::read(&path)?;
        let mut ledger = Self {
            path,
            events: Vec::new(),
            revoked: BTreeMap::new(),
            head_digest: [0; 32],
            last_timestamp: 0,
        };
        ledger.replay(&bytes)?;
        Ok(ledger)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn events(&self) -> &[PolicyStatusEvent] {
        &self.events
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }

    pub fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }

    pub fn is_revoked(
        &self,
        policy_id: &str,
        policy_version: &str,
    ) -> bool {
        self.revoked.contains_key(&(
            policy_id.to_string(),
            policy_version.to_string(),
        ))
    }

    pub fn revoked_event(
        &self,
        policy_id: &str,
        policy_version: &str,
    ) -> Option<&PolicyStatusEvent> {
        self.revoked.get(&(
            policy_id.to_string(),
            policy_version.to_string(),
        ))
    }

    pub fn append_revoke(
        &mut self,
        policy: &PolicyDefinition,
        authorization: &AuthorizationRecord,
        reason_code: &str,
    ) -> Result<(PolicyStatusEvent, bool)> {
        validate_identifier("reason_code", reason_code)?;
        let policy_digest = policy
            .digest()
            .map_err(|error| AuthError::Trust(error.to_string()))?;
        let expected_subject = policy_revoke_subject(
            &policy.policy_id,
            &policy.policy_version,
            policy_digest,
            reason_code,
        )?;
        if authorization.proof.domain_code != DOMAIN_POLICY_REVOKE
            || authorization.proof.required_role != ROLE_POLICY_ADMIN
            || authorization.proof.subject_digest != expected_subject
        {
            return Err(AuthError::Invalid(
                "policy revocation authorization mismatch".to_string(),
            ));
        }

        let key = (
            policy.policy_id.clone(),
            policy.policy_version.clone(),
        );
        if let Some(existing) = self.revoked.get(&key) {
            if existing.policy_digest == policy_digest
                && existing.reason_code == reason_code
                && existing.authorization_event_id
                    == authorization.event_id
            {
                return Ok((existing.clone(), false));
            }
            return Err(AuthError::Invalid(format!(
                "policy version is already revoked: {}@{}",
                policy.policy_id,
                policy.policy_version,
            )));
        }
        if authorization.proof.logical_timestamp <= self.last_timestamp {
            return Err(AuthError::Invalid(
                "policy status timestamp must be strictly increasing"
                    .to_string(),
            ));
        }

        let mut event = PolicyStatusEvent {
            sequence: (self.events.len() as u64)
                .checked_add(1)
                .ok_or_else(|| AuthError::Invalid(
                    "policy status sequence overflow".to_string(),
                ))?,
            kind: PolicyStatusEventKind::Revoke,
            policy_id: policy.policy_id.clone(),
            policy_version: policy.policy_version.clone(),
            policy_digest,
            reason_code: reason_code.to_string(),
            signer_key_id: authorization
                .proof
                .signer_key_id
                .clone(),
            signer_fingerprint: authorization
                .proof
                .signer_fingerprint,
            key_registry_head: authorization
                .proof
                .key_registry_head,
            authorization_event_id: authorization.event_id,
            logical_timestamp: authorization
                .proof
                .logical_timestamp,
            previous_digest: self.head_digest,
            frame_digest: [0; 32],
        };
        let payload = encode_payload(&event)?;
        let payload_digest = sha256(&payload);
        let frame_digest = compute_frame_digest(
            event.sequence,
            self.head_digest,
            payload_digest,
        );
        event.frame_digest = frame_digest;
        let frame = encode_frame(
            event.sequence,
            self.head_digest,
            payload_digest,
            frame_digest,
            &payload,
        )?;
        append_fsync(&self.path, &frame)?;
        self.last_timestamp = event.logical_timestamp;
        self.head_digest = frame_digest;
        self.revoked.insert(key, event.clone());
        self.events.push(event.clone());
        Ok((event, true))
    }

    fn replay(&mut self, bytes: &[u8]) -> Result<()> {
        let frames = decode_frames(bytes)?;
        for frame in frames {
            let mut event = decode_payload(&frame.payload)?;
            event.sequence = frame.sequence;
            event.previous_digest = frame.previous_digest;
            event.frame_digest = frame.frame_digest;
            validate_event(self, &event)?;
            let key = (
                event.policy_id.clone(),
                event.policy_version.clone(),
            );
            self.revoked.insert(key, event.clone());
            self.last_timestamp = event.logical_timestamp;
            self.head_digest = event.frame_digest;
            self.events.push(event);
        }
        Ok(())
    }
}

fn validate_event(
    ledger: &PolicyStatusLedger,
    event: &PolicyStatusEvent,
) -> Result<()> {
    validate_identifier("policy_id", &event.policy_id)?;
    validate_identifier("policy_version", &event.policy_version)?;
    validate_identifier("reason_code", &event.reason_code)?;
    validate_identifier("signer_key_id", &event.signer_key_id)?;
    if event.kind != PolicyStatusEventKind::Revoke
        || event.policy_digest == [0; 32]
        || event.signer_fingerprint == [0; 32]
        || event.key_registry_head == [0; 32]
        || event.authorization_event_id == [0; 32]
        || event.logical_timestamp == 0
        || event.logical_timestamp <= ledger.last_timestamp
    {
        return Err(AuthError::Invalid(
            "invalid policy status event".to_string(),
        ));
    }
    if ledger.is_revoked(
        &event.policy_id,
        &event.policy_version,
    ) {
        return Err(AuthError::Invalid(format!(
            "duplicate policy revocation: {}@{}",
            event.policy_id,
            event.policy_version,
        )));
    }
    let expected_subject = policy_revoke_subject(
        &event.policy_id,
        &event.policy_version,
        event.policy_digest,
        &event.reason_code,
    )?;
    if expected_subject == [0; 32] {
        return Err(AuthError::Invalid(
            "policy revocation subject cannot be zero".to_string(),
        ));
    }
    Ok(())
}

fn encode_payload(event: &PolicyStatusEvent) -> Result<Vec<u8>> {
    let policy_id = event.policy_id.as_bytes();
    let policy_version = event.policy_version.as_bytes();
    let reason = event.reason_code.as_bytes();
    let signer = event.signer_key_id.as_bytes();
    let mut output = Vec::new();
    output.extend_from_slice(&POLICY_STATUS_PAYLOAD_MAGIC);
    output.push(event.kind as u8);
    output.push(DOMAIN_POLICY_REVOKE);
    output.extend_from_slice(&ROLE_POLICY_ADMIN.to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&event.logical_timestamp.to_le_bytes());
    output.extend_from_slice(&(policy_id.len() as u32).to_le_bytes());
    output.extend_from_slice(&(policy_version.len() as u32).to_le_bytes());
    output.extend_from_slice(&(reason.len() as u32).to_le_bytes());
    output.extend_from_slice(&(signer.len() as u32).to_le_bytes());
    output.extend_from_slice(&event.policy_digest);
    output.extend_from_slice(&event.signer_fingerprint);
    output.extend_from_slice(&event.key_registry_head);
    output.extend_from_slice(&event.authorization_event_id);
    output.extend_from_slice(&0u64.to_le_bytes());
    debug_assert_eq!(output.len(), POLICY_STATUS_FIXED_BYTES);
    output.extend_from_slice(policy_id);
    output.extend_from_slice(policy_version);
    output.extend_from_slice(reason);
    output.extend_from_slice(signer);
    Ok(output)
}

fn decode_payload(payload: &[u8]) -> Result<PolicyStatusEvent> {
    if payload.len() < POLICY_STATUS_FIXED_BYTES
        || payload[0..8] != POLICY_STATUS_PAYLOAD_MAGIC
    {
        return Err(AuthError::Invalid(
            "policy status payload header mismatch".to_string(),
        ));
    }
    let kind = PolicyStatusEventKind::from_code(payload[8])?;
    if payload[9] != DOMAIN_POLICY_REVOKE
        || read_u16(payload, 10)? != ROLE_POLICY_ADMIN
        || read_u32(payload, 12)? != 0
    {
        return Err(AuthError::Invalid(
            "policy status domain/role mismatch".to_string(),
        ));
    }
    let logical_timestamp = read_u64(payload, 16)?;
    let policy_id_len = read_u32(payload, 24)? as usize;
    let version_len = read_u32(payload, 28)? as usize;
    let reason_len = read_u32(payload, 32)? as usize;
    let signer_len = read_u32(payload, 36)? as usize;
    let policy_digest = read_digest(payload, 40)?;
    let signer_fingerprint = read_digest(payload, 72)?;
    let key_registry_head = read_digest(payload, 104)?;
    let authorization_event_id = read_digest(payload, 136)?;
    if read_u64(payload, 168)? != 0 {
        return Err(AuthError::Invalid(
            "policy status reserved field non-zero".to_string(),
        ));
    }
    let mut cursor = POLICY_STATUS_FIXED_BYTES;
    let policy_id = read_string(
        payload, &mut cursor, policy_id_len, "policy_id"
    )?;
    let policy_version = read_string(
        payload, &mut cursor, version_len, "policy_version"
    )?;
    let reason_code = read_string(
        payload, &mut cursor, reason_len, "reason_code"
    )?;
    let signer_key_id = read_string(
        payload, &mut cursor, signer_len, "signer_key_id"
    )?;
    if cursor != payload.len() {
        return Err(AuthError::Invalid(
            "policy status payload trailing bytes".to_string(),
        ));
    }
    Ok(PolicyStatusEvent {
        sequence: 0,
        kind,
        policy_id,
        policy_version,
        policy_digest,
        reason_code,
        signer_key_id,
        signer_fingerprint,
        key_registry_head,
        authorization_event_id,
        logical_timestamp,
        previous_digest: [0; 32],
        frame_digest: [0; 32],
    })
}

struct Frame {
    sequence: u64,
    previous_digest: [u8; 32],
    frame_digest: [u8; 32],
    payload: Vec<u8>,
}

fn encode_frame(
    sequence: u64,
    previous_digest: [u8; 32],
    payload_digest: [u8; 32],
    frame_digest: [u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(AuthError::Invalid(
            "policy status payload exceeds maximum".to_string(),
        ));
    }
    let mut output = Vec::new();
    output.extend_from_slice(&POLICY_STATUS_MAGIC);
    output.extend_from_slice(&1u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&(FRAME_HEADER_BYTES as u32).to_le_bytes());
    output.extend_from_slice(&sequence.to_le_bytes());
    output.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    output.extend_from_slice(&previous_digest);
    output.extend_from_slice(&payload_digest);
    output.extend_from_slice(&frame_digest);
    output.extend_from_slice(&[0; 16]);
    debug_assert_eq!(output.len(), FRAME_HEADER_BYTES);
    output.extend_from_slice(payload);
    Ok(output)
}

fn decode_frames(bytes: &[u8]) -> Result<Vec<Frame>> {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    let mut head = [0u8; 32];
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if remaining < FRAME_HEADER_BYTES {
            return Err(AuthError::TruncatedTail {
                context: "policy status ledger",
                offset,
                remaining_bytes: remaining,
            });
        }
        let header = &bytes[offset..offset + FRAME_HEADER_BYTES];
        if header[0..8] != POLICY_STATUS_MAGIC
            || read_u16(header, 8)? != 1
            || read_u16(header, 10)? != 0
            || read_u32(header, 12)? as usize != FRAME_HEADER_BYTES
        {
            return Err(AuthError::Invalid(
                "policy status frame header mismatch".to_string(),
            ));
        }
        let sequence = read_u64(header, 16)?;
        if sequence != frames.len() as u64 + 1 {
            return Err(AuthError::Invalid(
                "policy status sequence mismatch".to_string(),
            ));
        }
        let payload_len = usize::try_from(read_u64(header, 24)?)
            .map_err(|_| AuthError::Invalid(
                "policy status payload length overflow".to_string(),
            ))?;
        if payload_len > MAX_PAYLOAD_BYTES {
            return Err(AuthError::Invalid(
                "policy status payload too large".to_string(),
            ));
        }
        let previous_digest = read_digest(header, 32)?;
        let expected_payload_digest = read_digest(header, 64)?;
        let expected_frame_digest = read_digest(header, 96)?;
        if header[128..144] != [0; 16] {
            return Err(AuthError::Invalid(
                "policy status reserved bytes non-zero".to_string(),
            ));
        }
        if previous_digest != head {
            return Err(AuthError::Integrity {
                context: "policy status previous digest".to_string(),
                expected: head,
                actual: previous_digest,
            });
        }
        let payload_start = offset + FRAME_HEADER_BYTES;
        let frame_end = payload_start
            .checked_add(payload_len)
            .ok_or_else(|| AuthError::Invalid(
                "policy status frame length overflow".to_string(),
            ))?;
        if frame_end > bytes.len() {
            return Err(AuthError::TruncatedTail {
                context: "policy status ledger",
                offset,
                remaining_bytes: remaining,
            });
        }
        let payload = bytes[payload_start..frame_end].to_vec();
        let actual_payload_digest = sha256(&payload);
        if actual_payload_digest != expected_payload_digest {
            return Err(AuthError::Integrity {
                context: "policy status payload".to_string(),
                expected: expected_payload_digest,
                actual: actual_payload_digest,
            });
        }
        let actual_frame_digest = compute_frame_digest(
            sequence,
            previous_digest,
            expected_payload_digest,
        );
        if actual_frame_digest != expected_frame_digest {
            return Err(AuthError::Integrity {
                context: "policy status frame".to_string(),
                expected: expected_frame_digest,
                actual: actual_frame_digest,
            });
        }
        frames.push(Frame {
            sequence,
            previous_digest,
            frame_digest: expected_frame_digest,
            payload,
        });
        head = expected_frame_digest;
        offset = frame_end;
    }
    Ok(frames)
}

fn compute_frame_digest(
    sequence: u64,
    previous_digest: [u8; 32],
    payload_digest: [u8; 32],
) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&POLICY_STATUS_FRAME_DOMAIN);
    preimage.extend_from_slice(&sequence.to_le_bytes());
    preimage.extend_from_slice(&previous_digest);
    preimage.extend_from_slice(&payload_digest);
    sha256(&preimage)
}

fn create_empty_file(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(AuthError::Invalid(format!(
            "file already exists: {}",
            path.display(),
        )));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?
        .sync_all()?;
    Ok(())
}

fn append_fsync(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
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
        return Err(AuthError::Invalid(format!(
            "{name} exceeds maximum length",
        )));
    }
    let end = cursor.checked_add(length).ok_or_else(|| {
        AuthError::Invalid("string length overflow".to_string())
    })?;
    let value = bytes.get(*cursor..end).ok_or_else(|| {
        AuthError::Invalid(format!("truncated {name}"))
    })?;
    *cursor = end;
    String::from_utf8(value.to_vec()).map_err(|_| {
        AuthError::Invalid(format!("{name} is not UTF-8"))
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes.get(offset..offset + 2).ok_or_else(|| {
        AuthError::Invalid("truncated u16".to_string())
    })?;
    Ok(u16::from_le_bytes(value.try_into().expect("checked u16")))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes.get(offset..offset + 4).ok_or_else(|| {
        AuthError::Invalid("truncated u32".to_string())
    })?;
    Ok(u32::from_le_bytes(value.try_into().expect("checked u32")))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let value = bytes.get(offset..offset + 8).ok_or_else(|| {
        AuthError::Invalid("truncated u64".to_string())
    })?;
    Ok(u64::from_le_bytes(value.try_into().expect("checked u64")))
}

fn read_digest(bytes: &[u8], offset: usize) -> Result<[u8; 32]> {
    let value = bytes.get(offset..offset + 32).ok_or_else(|| {
        AuthError::Invalid("truncated digest".to_string())
    })?;
    Ok(value.try_into().expect("checked digest"))
}
