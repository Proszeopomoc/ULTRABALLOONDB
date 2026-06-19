use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ultraballoondb_storage::sha256;

use crate::{
    export_public_blob, sign_digest, validate_identifier,
    verify_digest, AsymmetricError, AsymmetricKeyRegistry,
    Result,
};

const LEDGER_MAGIC: [u8; 8] = *b"UBASI01\0";
const LEDGER_PAYLOAD_MAGIC: [u8; 8] = *b"UBASP01\0";
const LEDGER_FRAME_DOMAIN: [u8; 8] = *b"UBASIFR1";
const AUTHORIZATION_DOMAIN: [u8; 8] = *b"UBASAU01";
const EVENT_ID_DOMAIN: [u8; 8] = *b"UBASEV01";
const FRAME_HEADER_BYTES: usize = 144;
const EVENT_FIXED_BYTES: usize = 280;
const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsymmetricAuthorization {
    pub sequence: u64,
    pub domain_code: u8,
    pub required_role_mask: u16,
    pub logical_timestamp: u64,
    pub key_id: String,
    pub nonce: String,
    pub subject_digest: [u8; 32],
    pub key_registry_head: [u8; 32],
    pub public_key_digest: [u8; 32],
    pub authorization_digest: [u8; 32],
    pub authorization_event_id: [u8; 32],
    pub signature: [u8; 64],
    pub previous_digest: [u8; 32],
    pub frame_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationReceipt {
    pub changed: bool,
    pub sequence: u64,
    pub key_id: String,
    pub authorization_digest: [u8; 32],
    pub authorization_event_id: [u8; 32],
    pub frame_digest: [u8; 32],
}

#[derive(Debug)]
pub struct AsymmetricAuthorizationLedger {
    path: PathBuf,
    events: Vec<AsymmetricAuthorization>,
    used_nonces: BTreeSet<(String, String)>,
    head_digest: [u8; 32],
    last_timestamp: u64,
}

impl AsymmetricAuthorizationLedger {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        create_empty_file(&path)?;
        Ok(Self {
            path,
            events: Vec::new(),
            used_nonces: BTreeSet::new(),
            head_digest: [0; 32],
            last_timestamp: 0,
        })
    }

    pub fn open_strict(
        path: impl AsRef<Path>,
        registry: &AsymmetricKeyRegistry,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.is_file() {
            return Err(AsymmetricError::Invalid(format!(
                "asymmetric authorization ledger missing: {}",
                path.display(),
            )));
        }
        let bytes = fs::read(&path)?;
        let mut ledger = Self {
            path,
            events: Vec::new(),
            used_nonces: BTreeSet::new(),
            head_digest: [0; 32],
            last_timestamp: 0,
        };
        ledger.replay(&bytes, registry)?;
        Ok(ledger)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn events(&self) -> &[AsymmetricAuthorization] {
        &self.events
    }

    pub fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }


    pub fn authorize_with_provider(
        &mut self,
        registry: &AsymmetricKeyRegistry,
        provider: &dyn crate::SigningProvider,
        requirement: crate::ProviderRequirement,
        domain_code: u8,
        required_role_mask: u16,
        subject_digest: [u8; 32],
        key_id: &str,
        provider_key_name: &str,
        logical_timestamp: u64,
        nonce: &str,
    ) -> Result<AuthorizationReceipt> {
        validate_identifier("key_id", key_id)?;
        validate_identifier("provider_key_name", provider_key_name)?;
        validate_identifier("nonce", nonce)?;
        if domain_code == 0
            || required_role_mask == 0
            || subject_digest == [0; 32]
            || logical_timestamp == 0
        {
            return Err(AsymmetricError::Invalid(
                "invalid asymmetric authorization fields".to_string(),
            ));
        }
        let capabilities = crate::enforce_provider_requirement(provider, requirement)?;
        let state = registry.get(key_id).ok_or_else(|| {
            AsymmetricError::Invalid(format!("asymmetric key not found: {key_id}"))
        })?;
        if !state.has_role(required_role_mask)
            || state.provider_name != capabilities.provider_name
            || state.provider_key_name != provider_key_name
        {
            return Err(AsymmetricError::Invalid(
                "provider or role does not match active registry state".to_string(),
            ));
        }
        let live_public_blob = provider.export_public(provider_key_name)?;
        if sha256(&live_public_blob) != state.public_key_digest
            || live_public_blob != state.public_blob
        {
            return Err(AsymmetricError::Integrity(
                "provider public key does not match registry".to_string(),
            ));
        }
        let authorization_digest = authorization_message_digest(
            domain_code,
            required_role_mask,
            subject_digest,
            registry.head_digest(),
            state.public_key_digest,
            logical_timestamp,
            key_id,
            nonce,
        )?;
        let signature = provider.sign(provider_key_name, &authorization_digest)?;
        if !provider.verify(&state.public_blob, &authorization_digest, &signature)? {
            return Err(AsymmetricError::Integrity(
                "provider authorization signature failed".to_string(),
            ));
        }
        let event_id = authorization_event_id(authorization_digest, signature);
        let event = AsymmetricAuthorization {
            sequence: 0,
            domain_code,
            required_role_mask,
            logical_timestamp,
            key_id: key_id.to_string(),
            nonce: nonce.to_string(),
            subject_digest,
            key_registry_head: registry.head_digest(),
            public_key_digest: state.public_key_digest,
            authorization_digest,
            authorization_event_id: event_id,
            signature,
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        };
        let appended = self.append(event, registry)?;
        Ok(AuthorizationReceipt {
            changed: true,
            sequence: appended.sequence,
            key_id: appended.key_id,
            authorization_digest: appended.authorization_digest,
            authorization_event_id: appended.authorization_event_id,
            frame_digest: appended.frame_digest,
        })
    }

    pub fn authorize(
        &mut self,
        registry: &AsymmetricKeyRegistry,
        domain_code: u8,
        required_role_mask: u16,
        subject_digest: [u8; 32],
        key_id: &str,
        provider_key_name: &str,
        logical_timestamp: u64,
        nonce: &str,
    ) -> Result<AuthorizationReceipt> {
        validate_identifier("key_id", key_id)?;
        validate_identifier(
            "provider_key_name",
            provider_key_name,
        )?;
        validate_identifier("nonce", nonce)?;
        if domain_code == 0
            || required_role_mask == 0
            || subject_digest == [0; 32]
            || logical_timestamp == 0
        {
            return Err(AsymmetricError::Invalid(
                "invalid asymmetric authorization fields"
                    .to_string(),
            ));
        }
        let state = registry.get(key_id)
            .ok_or_else(|| AsymmetricError::Invalid(format!(
                "asymmetric key not found: {key_id}",
            )))?;
        if !state.has_role(required_role_mask) {
            return Err(AsymmetricError::Invalid(
                "asymmetric key lacks required active role"
                    .to_string(),
            ));
        }
        if state.provider_key_name != provider_key_name {
            return Err(AsymmetricError::Invalid(
                "provider key name does not match registry state"
                    .to_string(),
            ));
        }
        let live_public_blob = export_public_blob(
            &state.provider_name,
            provider_key_name,
        )?;
        if sha256(&live_public_blob) != state.public_key_digest
            || live_public_blob != state.public_blob
        {
            return Err(AsymmetricError::Integrity(
                "provider public key does not match registry"
                    .to_string(),
            ));
        }
        let authorization_digest =
            authorization_message_digest(
                domain_code,
                required_role_mask,
                subject_digest,
                registry.head_digest(),
                state.public_key_digest,
                logical_timestamp,
                key_id,
                nonce,
            )?;
        let signature = sign_digest(
            &state.provider_name,
            provider_key_name,
            &authorization_digest,
        )?;
        if !verify_digest(
            &state.public_blob,
            &authorization_digest,
            &signature,
        )? {
            return Err(AsymmetricError::Integrity(
                "asymmetric authorization signature failed"
                    .to_string(),
            ));
        }
        let event_id = authorization_event_id(
            authorization_digest,
            signature,
        );
        let event = AsymmetricAuthorization {
            sequence: 0,
            domain_code,
            required_role_mask,
            logical_timestamp,
            key_id: key_id.to_string(),
            nonce: nonce.to_string(),
            subject_digest,
            key_registry_head: registry.head_digest(),
            public_key_digest: state.public_key_digest,
            authorization_digest,
            authorization_event_id: event_id,
            signature,
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        };
        let appended = self.append(event, registry)?;
        Ok(AuthorizationReceipt {
            changed: true,
            sequence: appended.sequence,
            key_id: appended.key_id,
            authorization_digest:
                appended.authorization_digest,
            authorization_event_id:
                appended.authorization_event_id,
            frame_digest: appended.frame_digest,
        })
    }

    pub fn verify_sequence(
        &self,
        sequence: u64,
        registry: &AsymmetricKeyRegistry,
    ) -> Result<bool> {
        let event = self.events.iter()
            .find(|event| event.sequence == sequence)
            .ok_or_else(|| AsymmetricError::Invalid(format!(
                "authorization sequence not found: {sequence}",
            )))?;
        verify_event(event, registry)
    }

    fn append(
        &mut self,
        mut event: AsymmetricAuthorization,
        registry: &AsymmetricKeyRegistry,
    ) -> Result<AsymmetricAuthorization> {
        if event.logical_timestamp <= self.last_timestamp {
            return Err(AsymmetricError::Invalid(
                "authorization timestamps must be strictly increasing"
                    .to_string(),
            ));
        }
        let nonce_key = (
            event.key_id.clone(),
            event.nonce.clone(),
        );
        if self.used_nonces.contains(&nonce_key) {
            return Err(AsymmetricError::Invalid(
                "authorization nonce already used".to_string(),
            ));
        }
        event.sequence = self.events.len() as u64 + 1;
        event.previous_digest = self.head_digest;
        if !verify_event(&event, registry)? {
            return Err(AsymmetricError::Integrity(
                "authorization event verification failed"
                    .to_string(),
            ));
        }
        let payload = encode_payload(&event)?;
        let payload_digest = sha256(&payload);
        let frame_digest = compute_frame_digest(
            event.sequence,
            event.previous_digest,
            payload_digest,
        );
        event.frame_digest = frame_digest;
        let frame = encode_frame(
            event.sequence,
            event.previous_digest,
            payload_digest,
            frame_digest,
            &payload,
        )?;
        append_fsync(&self.path, &frame)?;
        self.used_nonces.insert(nonce_key);
        self.last_timestamp = event.logical_timestamp;
        self.head_digest = event.frame_digest;
        self.events.push(event.clone());
        Ok(event)
    }

    fn replay(
        &mut self,
        bytes: &[u8],
        registry: &AsymmetricKeyRegistry,
    ) -> Result<()> {
        for frame in decode_frames(bytes)? {
            let mut event = decode_payload(&frame.payload)?;
            event.sequence = frame.sequence;
            event.previous_digest = frame.previous_digest;
            event.frame_digest = frame.frame_digest;
            if event.logical_timestamp <= self.last_timestamp {
                return Err(AsymmetricError::Invalid(
                    "authorization timestamp order mismatch"
                        .to_string(),
                ));
            }
            let nonce_key = (
                event.key_id.clone(),
                event.nonce.clone(),
            );
            if self.used_nonces.contains(&nonce_key) {
                return Err(AsymmetricError::Invalid(
                    "authorization duplicate nonce".to_string(),
                ));
            }
            if !verify_event(&event, registry)? {
                return Err(AsymmetricError::Integrity(
                    "authorization replay signature failed"
                        .to_string(),
                ));
            }
            self.used_nonces.insert(nonce_key);
            self.last_timestamp = event.logical_timestamp;
            self.head_digest = event.frame_digest;
            self.events.push(event);
        }
        Ok(())
    }
}

pub fn authorization_message_digest(
    domain_code: u8,
    required_role_mask: u16,
    subject_digest: [u8; 32],
    key_registry_head: [u8; 32],
    public_key_digest: [u8; 32],
    logical_timestamp: u64,
    key_id: &str,
    nonce: &str,
) -> Result<[u8; 32]> {
    validate_identifier("key_id", key_id)?;
    validate_identifier("nonce", nonce)?;
    if domain_code == 0
        || required_role_mask == 0
        || subject_digest == [0; 32]
        || key_registry_head == [0; 32]
        || public_key_digest == [0; 32]
        || logical_timestamp == 0
    {
        return Err(AsymmetricError::Invalid(
            "invalid authorization digest fields".to_string(),
        ));
    }
    let key = key_id.as_bytes();
    let nonce_bytes = nonce.as_bytes();
    let mut output = Vec::new();
    output.extend_from_slice(&AUTHORIZATION_DOMAIN);
    output.push(domain_code);
    output.push(1);
    output.extend_from_slice(
        &required_role_mask.to_le_bytes(),
    );
    output.extend_from_slice(&subject_digest);
    output.extend_from_slice(&key_registry_head);
    output.extend_from_slice(&public_key_digest);
    output.extend_from_slice(
        &logical_timestamp.to_le_bytes(),
    );
    output.extend_from_slice(&(key.len() as u32).to_le_bytes());
    output.extend_from_slice(
        &(nonce_bytes.len() as u32).to_le_bytes(),
    );
    output.extend_from_slice(key);
    output.extend_from_slice(nonce_bytes);
    Ok(sha256(&output))
}

fn authorization_event_id(
    authorization_digest: [u8; 32],
    signature: [u8; 64],
) -> [u8; 32] {
    let mut output = Vec::new();
    output.extend_from_slice(&EVENT_ID_DOMAIN);
    output.extend_from_slice(&authorization_digest);
    output.extend_from_slice(&signature);
    sha256(&output)
}

fn verify_event(
    event: &AsymmetricAuthorization,
    registry: &AsymmetricKeyRegistry,
) -> Result<bool> {
    validate_identifier("key_id", &event.key_id)?;
    validate_identifier("nonce", &event.nonce)?;
    if event.domain_code == 0
        || event.required_role_mask == 0
        || event.logical_timestamp == 0
        || event.subject_digest == [0; 32]
        || event.key_registry_head == [0; 32]
        || event.public_key_digest == [0; 32]
        || event.signature == [0; 64]
    {
        return Err(AsymmetricError::Invalid(
            "authorization event invariant mismatch"
                .to_string(),
        ));
    }
    let state = registry.state_at_head(
        &event.key_registry_head,
        &event.key_id,
    )
    .ok_or_else(|| AsymmetricError::Invalid(
        "authorization references unknown registry head/key"
            .to_string(),
    ))?;
    if !state.has_role(event.required_role_mask)
        || state.public_key_digest
            != event.public_key_digest
    {
        return Err(AsymmetricError::Invalid(
            "authorization key state/role mismatch"
                .to_string(),
        ));
    }
    let expected_digest = authorization_message_digest(
        event.domain_code,
        event.required_role_mask,
        event.subject_digest,
        event.key_registry_head,
        event.public_key_digest,
        event.logical_timestamp,
        &event.key_id,
        &event.nonce,
    )?;
    if expected_digest != event.authorization_digest {
        return Err(AsymmetricError::Integrity(
            "authorization message digest mismatch"
                .to_string(),
        ));
    }
    if authorization_event_id(
        event.authorization_digest,
        event.signature,
    ) != event.authorization_event_id
    {
        return Err(AsymmetricError::Integrity(
            "authorization event ID mismatch".to_string(),
        ));
    }
    verify_digest(
        &state.public_blob,
        &event.authorization_digest,
        &event.signature,
    )
}

fn encode_payload(
    event: &AsymmetricAuthorization,
) -> Result<Vec<u8>> {
    let key = event.key_id.as_bytes();
    let nonce = event.nonce.as_bytes();
    let mut output = Vec::new();
    output.extend_from_slice(&LEDGER_PAYLOAD_MAGIC);
    output.push(event.domain_code);
    output.push(1);
    output.extend_from_slice(
        &event.required_role_mask.to_le_bytes(),
    );
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(
        &event.logical_timestamp.to_le_bytes(),
    );
    output.extend_from_slice(&(key.len() as u32).to_le_bytes());
    output.extend_from_slice(
        &(nonce.len() as u32).to_le_bytes(),
    );
    output.extend_from_slice(&0u64.to_le_bytes());
    output.extend_from_slice(&event.subject_digest);
    output.extend_from_slice(&event.key_registry_head);
    output.extend_from_slice(&event.public_key_digest);
    output.extend_from_slice(
        &event.authorization_digest,
    );
    output.extend_from_slice(
        &event.authorization_event_id,
    );
    output.extend_from_slice(&event.signature);
    output.extend_from_slice(&[0; 16]);
    debug_assert_eq!(output.len(), EVENT_FIXED_BYTES);
    output.extend_from_slice(key);
    output.extend_from_slice(nonce);
    Ok(output)
}

fn decode_payload(
    payload: &[u8],
) -> Result<AsymmetricAuthorization> {
    if payload.len() < EVENT_FIXED_BYTES
        || payload[0..8] != LEDGER_PAYLOAD_MAGIC
    {
        return Err(AsymmetricError::Invalid(
            "authorization payload header mismatch"
                .to_string(),
        ));
    }
    let domain_code = payload[8];
    if payload[9] != 1
        || read_u32(payload, 12)? != 0
        || read_u64(payload, 32)? != 0
        || payload[264..280] != [0; 16]
    {
        return Err(AsymmetricError::Invalid(
            "authorization payload reserved/algorithm mismatch"
                .to_string(),
        ));
    }
    let required_role_mask = read_u16(payload, 10)?;
    let logical_timestamp = read_u64(payload, 16)?;
    let key_len = read_u32(payload, 24)? as usize;
    let nonce_len = read_u32(payload, 28)? as usize;
    let subject_digest = read_digest(payload, 40)?;
    let key_registry_head = read_digest(payload, 72)?;
    let public_key_digest = read_digest(payload, 104)?;
    let authorization_digest = read_digest(payload, 136)?;
    let authorization_event_id = read_digest(payload, 168)?;
    let signature = read_signature(payload, 200)?;
    let mut cursor = EVENT_FIXED_BYTES;
    let key_id = read_string(
        payload,
        &mut cursor,
        key_len,
        "key_id",
    )?;
    let nonce = read_string(
        payload,
        &mut cursor,
        nonce_len,
        "nonce",
    )?;
    if cursor != payload.len() {
        return Err(AsymmetricError::Invalid(
            "authorization payload trailing bytes"
                .to_string(),
        ));
    }
    Ok(AsymmetricAuthorization {
        sequence: 0,
        domain_code,
        required_role_mask,
        logical_timestamp,
        key_id,
        nonce,
        subject_digest,
        key_registry_head,
        public_key_digest,
        authorization_digest,
        authorization_event_id,
        signature,
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
        return Err(AsymmetricError::Invalid(
            "authorization payload too large".to_string(),
        ));
    }
    let mut output = Vec::new();
    output.extend_from_slice(&LEDGER_MAGIC);
    output.extend_from_slice(&1u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(
        &(FRAME_HEADER_BYTES as u32).to_le_bytes(),
    );
    output.extend_from_slice(&sequence.to_le_bytes());
    output.extend_from_slice(
        &(payload.len() as u64).to_le_bytes(),
    );
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
            return Err(AsymmetricError::Truncated {
                context: "asymmetric authorization ledger",
                offset,
                remaining_bytes: remaining,
            });
        }
        let header = &bytes[offset..offset + FRAME_HEADER_BYTES];
        if header[0..8] != LEDGER_MAGIC
            || read_u16(header, 8)? != 1
            || read_u16(header, 10)? != 0
            || read_u32(header, 12)? as usize
                != FRAME_HEADER_BYTES
            || header[128..144] != [0; 16]
        {
            return Err(AsymmetricError::Invalid(
                "authorization frame header mismatch"
                    .to_string(),
            ));
        }
        let sequence = read_u64(header, 16)?;
        if sequence != frames.len() as u64 + 1 {
            return Err(AsymmetricError::Invalid(
                "authorization frame sequence mismatch"
                    .to_string(),
            ));
        }
        let payload_len = usize::try_from(
            read_u64(header, 24)?,
        )
        .map_err(|_| AsymmetricError::Invalid(
            "authorization payload length overflow"
                .to_string(),
        ))?;
        if payload_len > MAX_PAYLOAD_BYTES {
            return Err(AsymmetricError::Invalid(
                "authorization payload exceeds maximum"
                    .to_string(),
            ));
        }
        let previous_digest = read_digest(header, 32)?;
        if previous_digest != head {
            return Err(AsymmetricError::Integrity(
                "authorization previous digest mismatch"
                    .to_string(),
            ));
        }
        let expected_payload_digest =
            read_digest(header, 64)?;
        let expected_frame_digest =
            read_digest(header, 96)?;
        let payload_start = offset + FRAME_HEADER_BYTES;
        let frame_end = payload_start
            .checked_add(payload_len)
            .ok_or_else(|| AsymmetricError::Invalid(
                "authorization frame length overflow"
                    .to_string(),
            ))?;
        if frame_end > bytes.len() {
            return Err(AsymmetricError::Truncated {
                context: "asymmetric authorization ledger",
                offset,
                remaining_bytes: remaining,
            });
        }
        let payload = bytes[payload_start..frame_end].to_vec();
        let actual_payload_digest = sha256(&payload);
        if actual_payload_digest != expected_payload_digest {
            return Err(AsymmetricError::Integrity(
                "authorization payload digest mismatch"
                    .to_string(),
            ));
        }
        let actual_frame_digest = compute_frame_digest(
            sequence,
            previous_digest,
            expected_payload_digest,
        );
        if actual_frame_digest != expected_frame_digest {
            return Err(AsymmetricError::Integrity(
                "authorization frame digest mismatch"
                    .to_string(),
            ));
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
    let mut output = Vec::new();
    output.extend_from_slice(&LEDGER_FRAME_DOMAIN);
    output.extend_from_slice(&sequence.to_le_bytes());
    output.extend_from_slice(&previous_digest);
    output.extend_from_slice(&payload_digest);
    sha256(&output)
}

fn create_empty_file(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(AsymmetricError::Invalid(format!(
            "authorization ledger already exists: {}",
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
        return Err(AsymmetricError::Invalid(format!(
            "{name} too long",
        )));
    }
    let end = cursor.checked_add(length).ok_or_else(|| {
        AsymmetricError::Invalid(
            "authorization string length overflow"
                .to_string(),
        )
    })?;
    let value = bytes.get(*cursor..end).ok_or_else(|| {
        AsymmetricError::Invalid(format!(
            "truncated authorization {name}",
        ))
    })?;
    *cursor = end;
    String::from_utf8(value.to_vec()).map_err(|_| {
        AsymmetricError::Invalid(format!(
            "authorization {name} is not UTF-8",
        ))
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes.get(offset..offset + 2).ok_or_else(|| {
        AsymmetricError::Invalid("truncated u16".to_string())
    })?;
    Ok(u16::from_le_bytes(value.try_into().expect("checked")))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes.get(offset..offset + 4).ok_or_else(|| {
        AsymmetricError::Invalid("truncated u32".to_string())
    })?;
    Ok(u32::from_le_bytes(value.try_into().expect("checked")))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let value = bytes.get(offset..offset + 8).ok_or_else(|| {
        AsymmetricError::Invalid("truncated u64".to_string())
    })?;
    Ok(u64::from_le_bytes(value.try_into().expect("checked")))
}

fn read_digest(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; 32]> {
    let value = bytes.get(offset..offset + 32).ok_or_else(|| {
        AsymmetricError::Invalid(
            "truncated digest".to_string(),
        )
    })?;
    Ok(value.try_into().expect("checked digest"))
}

fn read_signature(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; 64]> {
    let value = bytes.get(offset..offset + 64).ok_or_else(|| {
        AsymmetricError::Invalid(
            "truncated signature".to_string(),
        )
    })?;
    Ok(value.try_into().expect("checked signature"))
}
