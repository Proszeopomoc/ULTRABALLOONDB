use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ultraballoondb_storage::sha256;

use crate::crypto::{
    constant_time_equal, key_fingerprint, key_register_subject,
    key_revoke_subject, sign_authorization, signature_message,
    validate_identifier,
};
use crate::{AuthError, Result};

pub const ROLE_KEY_ADMIN: u16 = 0x0001;
pub const ROLE_POLICY_ADMIN: u16 = 0x0002;
pub const ROLE_TRUST_OPERATOR: u16 = 0x0004;
pub const ROLE_AUDITOR: u16 = 0x0008;
pub const ROLE_ALL: u16 = ROLE_KEY_ADMIN
    | ROLE_POLICY_ADMIN
    | ROLE_TRUST_OPERATOR
    | ROLE_AUDITOR;

pub const DOMAIN_KEY_BOOTSTRAP: u8 = 1;
pub const DOMAIN_KEY_REGISTER: u8 = 2;
pub const DOMAIN_KEY_REVOKE: u8 = 3;
pub const DOMAIN_POLICY_REGISTER: u8 = 4;
pub const DOMAIN_TRUST_COMMIT: u8 = 5;

const KEY_LEDGER_MAGIC: [u8; 8] = *b"UBKEY01\0";
const KEY_PAYLOAD_MAGIC: [u8; 8] = *b"UBKEYP1\0";
const AUTH_LEDGER_MAGIC: [u8; 8] = *b"UBAUTH01";
const AUTH_PAYLOAD_MAGIC: [u8; 8] = *b"UBAUTP1\0";
const KEY_FRAME_DOMAIN: [u8; 8] = *b"UBKEYFR1";
const AUTH_FRAME_DOMAIN: [u8; 8] = *b"UBAUTFR1";
const FRAME_HEADER_BYTES: usize = 144;
const KEY_FIXED_BYTES: usize = 168;
const AUTH_FIXED_BYTES: usize = 168;
const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyEventKind {
    Bootstrap = 1,
    Register = 2,
    Revoke = 3,
}

impl KeyEventKind {
    fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Bootstrap),
            2 => Ok(Self::Register),
            3 => Ok(Self::Revoke),
            _ => Err(AuthError::Invalid(format!(
                "unknown key event kind {value}",
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "BOOTSTRAP",
            Self::Register => "REGISTER",
            Self::Revoke => "REVOKE",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyState {
    pub key_id: String,
    pub fingerprint: [u8; 32],
    pub role_mask: u16,
    pub active: bool,
    pub registered_sequence: u64,
    pub revoked_sequence: Option<u64>,
}

impl KeyState {
    pub fn has_role(&self, role: u16) -> bool {
        self.active && self.role_mask & role == role
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEvent {
    pub sequence: u64,
    pub kind: KeyEventKind,
    pub target_key_id: String,
    pub target_fingerprint: [u8; 32],
    pub target_role_mask: u16,
    pub signer_key_id: String,
    pub signer_fingerprint: [u8; 32],
    pub required_role: u16,
    pub domain_code: u8,
    pub logical_timestamp: u64,
    pub nonce: String,
    pub subject_digest: [u8; 32],
    pub signature: [u8; 32],
    pub previous_digest: [u8; 32],
    pub frame_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationProof {
    pub domain_code: u8,
    pub required_role: u16,
    pub logical_timestamp: u64,
    pub subject_digest: [u8; 32],
    pub signer_key_id: String,
    pub signer_fingerprint: [u8; 32],
    pub key_registry_head: [u8; 32],
    pub nonce: String,
    pub signature: [u8; 32],
}

impl AuthorizationProof {
    pub fn event_id(&self) -> Result<[u8; 32]> {
        let payload = encode_authorization_payload(self)?;
        Ok(sha256(&payload))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationRecord {
    pub sequence: u64,
    pub proof: AuthorizationProof,
    pub event_id: [u8; 32],
    pub previous_digest: [u8; 32],
    pub frame_digest: [u8; 32],
}

#[derive(Debug)]
pub struct KeyRegistry {
    path: PathBuf,
    events: Vec<KeyEvent>,
    states: BTreeMap<String, KeyState>,
    used_nonces: BTreeSet<(String, String)>,
    head_digest: [u8; 32],
    last_timestamp: u64,
}

impl KeyRegistry {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        create_empty_file(&path)?;
        Ok(Self {
            path,
            events: Vec::new(),
            states: BTreeMap::new(),
            used_nonces: BTreeSet::new(),
            head_digest: [0; 32],
            last_timestamp: 0,
        })
    }

    pub fn open_strict(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.is_file() {
            return Err(AuthError::Invalid(format!(
                "key registry missing: {}",
                path.display(),
            )));
        }
        let bytes = fs::read(&path)?;
        let mut registry = Self {
            path,
            events: Vec::new(),
            states: BTreeMap::new(),
            used_nonces: BTreeSet::new(),
            head_digest: [0; 32],
            last_timestamp: 0,
        };
        registry.replay(&bytes)?;
        Ok(registry)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn events(&self) -> &[KeyEvent] {
        &self.events
    }

    pub fn states(&self) -> &BTreeMap<String, KeyState> {
        &self.states
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn active_key_count(&self) -> usize {
        self.states.values().filter(|state| state.active).count()
    }

    pub fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }

    pub fn get(&self, key_id: &str) -> Option<&KeyState> {
        self.states.get(key_id)
    }

    pub fn bootstrap(
        &mut self,
        key_id: &str,
        role_mask: u16,
        secret: &[u8],
        logical_timestamp: u64,
        nonce: &str,
    ) -> Result<KeyEvent> {
        if !self.events.is_empty() {
            return Err(AuthError::Invalid(
                "key registry bootstrap is allowed only once".to_string(),
            ));
        }
        validate_role_mask(role_mask)?;
        if role_mask & ROLE_KEY_ADMIN == 0 {
            return Err(AuthError::Invalid(
                "bootstrap key must include KEY_ADMIN".to_string(),
            ));
        }
        let fingerprint = key_fingerprint(secret)?;
        let subject_digest = key_register_subject(
            key_id,
            fingerprint,
            role_mask,
        )?;
        let (signer_fingerprint, signature) = sign_authorization(
            secret,
            DOMAIN_KEY_BOOTSTRAP,
            0,
            logical_timestamp,
            subject_digest,
            self.head_digest,
            key_id,
            nonce,
        )?;
        if signer_fingerprint != fingerprint {
            return Err(AuthError::Invalid(
                "bootstrap fingerprint mismatch".to_string(),
            ));
        }
        let event = KeyEvent {
            sequence: 0,
            kind: KeyEventKind::Bootstrap,
            target_key_id: key_id.to_string(),
            target_fingerprint: fingerprint,
            target_role_mask: role_mask,
            signer_key_id: key_id.to_string(),
            signer_fingerprint: fingerprint,
            required_role: 0,
            domain_code: DOMAIN_KEY_BOOTSTRAP,
            logical_timestamp,
            nonce: nonce.to_string(),
            subject_digest,
            signature,
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        };
        self.append(event)
    }

    pub fn register_key(
        &mut self,
        target_key_id: &str,
        target_role_mask: u16,
        target_secret: &[u8],
        signer_key_id: &str,
        signer_secret: &[u8],
        logical_timestamp: u64,
        nonce: &str,
    ) -> Result<KeyEvent> {
        validate_role_mask(target_role_mask)?;
        if self.states.contains_key(target_key_id) {
            return Err(AuthError::Invalid(format!(
                "key ID is already registered: {target_key_id}",
            )));
        }
        let target_fingerprint = key_fingerprint(target_secret)?;
        let subject_digest = key_register_subject(
            target_key_id,
            target_fingerprint,
            target_role_mask,
        )?;
        let signer = self.verify_secret_role(
            signer_key_id,
            signer_secret,
            ROLE_KEY_ADMIN,
        )?;
        let (signer_fingerprint, signature) = sign_authorization(
            signer_secret,
            DOMAIN_KEY_REGISTER,
            ROLE_KEY_ADMIN,
            logical_timestamp,
            subject_digest,
            self.head_digest,
            signer_key_id,
            nonce,
        )?;
        if signer_fingerprint != signer.fingerprint {
            return Err(AuthError::Invalid(
                "signer fingerprint changed during registration".to_string(),
            ));
        }
        self.append(KeyEvent {
            sequence: 0,
            kind: KeyEventKind::Register,
            target_key_id: target_key_id.to_string(),
            target_fingerprint,
            target_role_mask,
            signer_key_id: signer_key_id.to_string(),
            signer_fingerprint,
            required_role: ROLE_KEY_ADMIN,
            domain_code: DOMAIN_KEY_REGISTER,
            logical_timestamp,
            nonce: nonce.to_string(),
            subject_digest,
            signature,
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        })
    }

    pub fn revoke_key(
        &mut self,
        target_key_id: &str,
        signer_key_id: &str,
        signer_secret: &[u8],
        logical_timestamp: u64,
        nonce: &str,
    ) -> Result<KeyEvent> {
        let target = self.states.get(target_key_id).cloned().ok_or_else(|| {
            AuthError::Invalid(format!("unknown target key: {target_key_id}"))
        })?;
        if !target.active {
            return Err(AuthError::Invalid(format!(
                "target key is already revoked: {target_key_id}",
            )));
        }
        let signer = self.verify_secret_role(
            signer_key_id,
            signer_secret,
            ROLE_KEY_ADMIN,
        )?;
        if target.has_role(ROLE_KEY_ADMIN) {
            let remaining_admins = self.states.values().filter(|state| {
                state.active
                    && state.key_id != target_key_id
                    && state.has_role(ROLE_KEY_ADMIN)
            }).count();
            if remaining_admins == 0 {
                return Err(AuthError::Invalid(
                    "cannot revoke the last active KEY_ADMIN".to_string(),
                ));
            }
        }
        let subject_digest = key_revoke_subject(
            target_key_id,
            target.fingerprint,
        )?;
        let (signer_fingerprint, signature) = sign_authorization(
            signer_secret,
            DOMAIN_KEY_REVOKE,
            ROLE_KEY_ADMIN,
            logical_timestamp,
            subject_digest,
            self.head_digest,
            signer_key_id,
            nonce,
        )?;
        if signer_fingerprint != signer.fingerprint {
            return Err(AuthError::Invalid(
                "signer fingerprint changed during revocation".to_string(),
            ));
        }
        self.append(KeyEvent {
            sequence: 0,
            kind: KeyEventKind::Revoke,
            target_key_id: target_key_id.to_string(),
            target_fingerprint: target.fingerprint,
            target_role_mask: 0,
            signer_key_id: signer_key_id.to_string(),
            signer_fingerprint,
            required_role: ROLE_KEY_ADMIN,
            domain_code: DOMAIN_KEY_REVOKE,
            logical_timestamp,
            nonce: nonce.to_string(),
            subject_digest,
            signature,
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        })
    }

    pub fn authorize(
        &self,
        domain_code: u8,
        required_role: u16,
        subject_digest: [u8; 32],
        signer_key_id: &str,
        signer_secret: &[u8],
        logical_timestamp: u64,
        nonce: &str,
    ) -> Result<AuthorizationProof> {
        if !matches!(
            domain_code,
            DOMAIN_POLICY_REGISTER | DOMAIN_TRUST_COMMIT
        ) {
            return Err(AuthError::Invalid(format!(
                "unsupported authorization domain {domain_code}",
            )));
        }
        let signer = self.verify_secret_role(
            signer_key_id,
            signer_secret,
            required_role,
        )?;
        let (fingerprint, signature) = sign_authorization(
            signer_secret,
            domain_code,
            required_role,
            logical_timestamp,
            subject_digest,
            self.head_digest,
            signer_key_id,
            nonce,
        )?;
        if fingerprint != signer.fingerprint {
            return Err(AuthError::Invalid(
                "signer fingerprint changed during authorization".to_string(),
            ));
        }
        Ok(AuthorizationProof {
            domain_code,
            required_role,
            logical_timestamp,
            subject_digest,
            signer_key_id: signer_key_id.to_string(),
            signer_fingerprint: fingerprint,
            key_registry_head: self.head_digest,
            nonce: nonce.to_string(),
            signature,
        })
    }

    pub fn verify_proof_with_secret(
        &self,
        proof: &AuthorizationProof,
        secret: &[u8],
    ) -> Result<()> {
        if proof.key_registry_head != self.head_digest {
            return Err(AuthError::Invalid(
                "authorization is not bound to current key registry head"
                    .to_string(),
            ));
        }
        let signer = self.verify_secret_role(
            &proof.signer_key_id,
            secret,
            proof.required_role,
        )?;
        if signer.fingerprint != proof.signer_fingerprint {
            return Err(AuthError::Invalid(
                "authorization signer fingerprint mismatch".to_string(),
            ));
        }
        let message = signature_message(
            proof.domain_code,
            proof.required_role,
            proof.logical_timestamp,
            proof.subject_digest,
            proof.signer_fingerprint,
            proof.key_registry_head,
            &proof.signer_key_id,
            &proof.nonce,
        )?;
        let expected = crate::crypto::hmac_sha256(secret, &message)?;
        if !constant_time_equal(&expected, &proof.signature) {
            return Err(AuthError::Invalid(
                "authorization signature mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn verify_secret_role(
        &self,
        key_id: &str,
        secret: &[u8],
        required_role: u16,
    ) -> Result<&KeyState> {
        validate_role_mask(required_role)?;
        let state = self.states.get(key_id).ok_or_else(|| {
            AuthError::Invalid(format!("unknown signer key: {key_id}"))
        })?;
        if !state.active {
            return Err(AuthError::Invalid(format!(
                "signer key is revoked: {key_id}",
            )));
        }
        if !state.has_role(required_role) {
            return Err(AuthError::Invalid(format!(
                "signer key lacks required role mask {required_role}",
            )));
        }
        let fingerprint = key_fingerprint(secret)?;
        if !constant_time_equal(&fingerprint, &state.fingerprint) {
            return Err(AuthError::Invalid(format!(
                "secret fingerprint does not match key ID {key_id}",
            )));
        }
        Ok(state)
    }

    fn append(&mut self, mut event: KeyEvent) -> Result<KeyEvent> {
        validate_key_event(self, &event, false)?;
        let sequence = (self.events.len() as u64)
            .checked_add(1)
            .ok_or_else(|| AuthError::Invalid(
                "key event sequence overflow".to_string(),
            ))?;
        event.sequence = sequence;
        event.previous_digest = self.head_digest;
        let payload = encode_key_payload(&event)?;
        let payload_digest = sha256(&payload);
        let frame_digest = compute_frame_digest(
            KEY_FRAME_DOMAIN,
            sequence,
            self.head_digest,
            payload_digest,
        );
        event.frame_digest = frame_digest;
        let frame = encode_frame(
            KEY_LEDGER_MAGIC,
            sequence,
            self.head_digest,
            payload_digest,
            frame_digest,
            &payload,
        )?;
        append_fsync(&self.path, &frame)?;
        apply_key_event(&mut self.states, &event)?;
        self.used_nonces.insert((
            event.signer_key_id.clone(),
            event.nonce.clone(),
        ));
        self.last_timestamp = event.logical_timestamp;
        self.head_digest = frame_digest;
        self.events.push(event.clone());
        Ok(event)
    }

    fn replay(&mut self, bytes: &[u8]) -> Result<()> {
        let frames = decode_frames(
            "key registry",
            KEY_LEDGER_MAGIC,
            KEY_FRAME_DOMAIN,
            bytes,
        )?;
        for frame in frames {
            let mut event = decode_key_payload(&frame.payload)?;
            event.sequence = frame.sequence;
            event.previous_digest = frame.previous_digest;
            event.frame_digest = frame.frame_digest;
            validate_key_event(self, &event, true)?;
            apply_key_event(&mut self.states, &event)?;
            self.used_nonces.insert((
                event.signer_key_id.clone(),
                event.nonce.clone(),
            ));
            self.last_timestamp = event.logical_timestamp;
            self.head_digest = frame.frame_digest;
            self.events.push(event);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct AuthorizationLedger {
    path: PathBuf,
    records: Vec<AuthorizationRecord>,
    event_ids: BTreeSet<[u8; 32]>,
    used_nonces: BTreeSet<(String, String)>,
    head_digest: [u8; 32],
    last_timestamp: u64,
}

impl AuthorizationLedger {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        create_empty_file(&path)?;
        Ok(Self {
            path,
            records: Vec::new(),
            event_ids: BTreeSet::new(),
            used_nonces: BTreeSet::new(),
            head_digest: [0; 32],
            last_timestamp: 0,
        })
    }

    pub fn open_strict(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.is_file() {
            return Err(AuthError::Invalid(format!(
                "authorization ledger missing: {}",
                path.display(),
            )));
        }
        let bytes = fs::read(&path)?;
        let mut ledger = Self {
            path,
            records: Vec::new(),
            event_ids: BTreeSet::new(),
            used_nonces: BTreeSet::new(),
            head_digest: [0; 32],
            last_timestamp: 0,
        };
        ledger.replay(&bytes)?;
        Ok(ledger)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn records(&self) -> &[AuthorizationRecord] {
        &self.records
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }

    pub fn contains_subject(
        &self,
        domain_code: u8,
        subject_digest: [u8; 32],
    ) -> bool {
        self.records.iter().any(|record| {
            record.proof.domain_code == domain_code
                && record.proof.subject_digest == subject_digest
        })
    }

    pub fn append_once(
        &mut self,
        registry: &KeyRegistry,
        proof: AuthorizationProof,
        secret: &[u8],
    ) -> Result<(AuthorizationRecord, bool)> {
        registry.verify_proof_with_secret(&proof, secret)?;
        validate_authorization_proof(&proof)?;
        let event_id = proof.event_id()?;
        if let Some(existing) = self.records.iter().find(|record| {
            record.event_id == event_id
        }) {
            if existing.proof != proof {
                return Err(AuthError::Invalid(
                    "authorization event ID collision".to_string(),
                ));
            }
            return Ok((existing.clone(), false));
        }
        if self.used_nonces.contains(&(
            proof.signer_key_id.clone(),
            proof.nonce.clone(),
        )) {
            return Err(AuthError::Invalid(format!(
                "authorization nonce already used by signer: {}",
                proof.nonce,
            )));
        }
        if proof.logical_timestamp <= self.last_timestamp {
            return Err(AuthError::Invalid(
                "authorization timestamp must be strictly increasing"
                    .to_string(),
            ));
        }
        let sequence = (self.records.len() as u64)
            .checked_add(1)
            .ok_or_else(|| AuthError::Invalid(
                "authorization sequence overflow".to_string(),
            ))?;
        let payload = encode_authorization_payload(&proof)?;
        let payload_digest = sha256(&payload);
        let frame_digest = compute_frame_digest(
            AUTH_FRAME_DOMAIN,
            sequence,
            self.head_digest,
            payload_digest,
        );
        let frame = encode_frame(
            AUTH_LEDGER_MAGIC,
            sequence,
            self.head_digest,
            payload_digest,
            frame_digest,
            &payload,
        )?;
        append_fsync(&self.path, &frame)?;
        let record = AuthorizationRecord {
            sequence,
            proof,
            event_id,
            previous_digest: self.head_digest,
            frame_digest,
        };
        self.used_nonces.insert((
            record.proof.signer_key_id.clone(),
            record.proof.nonce.clone(),
        ));
        self.event_ids.insert(event_id);
        self.last_timestamp = record.proof.logical_timestamp;
        self.head_digest = frame_digest;
        self.records.push(record.clone());
        Ok((record, true))
    }

    fn replay(&mut self, bytes: &[u8]) -> Result<()> {
        let frames = decode_frames(
            "authorization ledger",
            AUTH_LEDGER_MAGIC,
            AUTH_FRAME_DOMAIN,
            bytes,
        )?;
        for frame in frames {
            let proof = decode_authorization_payload(&frame.payload)?;
            validate_authorization_proof(&proof)?;
            if proof.logical_timestamp <= self.last_timestamp {
                return Err(AuthError::Invalid(
                    "authorization timestamps are not strictly increasing"
                        .to_string(),
                ));
            }
            if !self.used_nonces.insert((
                proof.signer_key_id.clone(),
                proof.nonce.clone(),
            )) {
                return Err(AuthError::Invalid(
                    "duplicate authorization nonce".to_string(),
                ));
            }
            let event_id = proof.event_id()?;
            if !self.event_ids.insert(event_id) {
                return Err(AuthError::Invalid(
                    "duplicate authorization event".to_string(),
                ));
            }
            self.last_timestamp = proof.logical_timestamp;
            self.head_digest = frame.frame_digest;
            self.records.push(AuthorizationRecord {
                sequence: frame.sequence,
                proof,
                event_id,
                previous_digest: frame.previous_digest,
                frame_digest: frame.frame_digest,
            });
        }
        Ok(())
    }
}

fn validate_key_event(
    registry: &KeyRegistry,
    event: &KeyEvent,
    replay: bool,
) -> Result<()> {
    validate_identifier("target_key_id", &event.target_key_id)?;
    validate_identifier("signer_key_id", &event.signer_key_id)?;
    validate_identifier("nonce", &event.nonce)?;
    if event.logical_timestamp == 0
        || event.logical_timestamp <= registry.last_timestamp
    {
        return Err(AuthError::Invalid(
            "key event timestamp must be strictly increasing".to_string(),
        ));
    }
    if registry.used_nonces.contains(&(
        event.signer_key_id.clone(),
        event.nonce.clone(),
    )) {
        return Err(AuthError::Invalid(
            "duplicate key-event nonce".to_string(),
        ));
    }
    if event.signature == [0; 32]
        || event.target_fingerprint == [0; 32]
        || event.signer_fingerprint == [0; 32]
    {
        return Err(AuthError::Invalid(
            "key event contains zero digest/signature".to_string(),
        ));
    }

    match event.kind {
        KeyEventKind::Bootstrap => {
            if !registry.events.is_empty()
                || event.domain_code != DOMAIN_KEY_BOOTSTRAP
                || event.required_role != 0
                || event.target_key_id != event.signer_key_id
                || event.target_fingerprint != event.signer_fingerprint
            {
                return Err(AuthError::Invalid(
                    "invalid bootstrap key event".to_string(),
                ));
            }
            validate_role_mask(event.target_role_mask)?;
            if event.target_role_mask & ROLE_KEY_ADMIN == 0 {
                return Err(AuthError::Invalid(
                    "bootstrap key lacks KEY_ADMIN".to_string(),
                ));
            }
            let expected = key_register_subject(
                &event.target_key_id,
                event.target_fingerprint,
                event.target_role_mask,
            )?;
            if expected != event.subject_digest {
                return Err(AuthError::Invalid(
                    "bootstrap subject digest mismatch".to_string(),
                ));
            }
        }
        KeyEventKind::Register => {
            if event.domain_code != DOMAIN_KEY_REGISTER
                || event.required_role != ROLE_KEY_ADMIN
                || registry.states.contains_key(&event.target_key_id)
            {
                return Err(AuthError::Invalid(
                    "invalid key registration event".to_string(),
                ));
            }
            validate_role_mask(event.target_role_mask)?;
            let signer = registry.states
                .get(&event.signer_key_id)
                .ok_or_else(|| AuthError::Invalid(
                    "registration signer is unknown".to_string(),
                ))?;
            if !signer.has_role(ROLE_KEY_ADMIN)
                || signer.fingerprint != event.signer_fingerprint
            {
                return Err(AuthError::Invalid(
                    "registration signer is not active KEY_ADMIN".to_string(),
                ));
            }
            let expected = key_register_subject(
                &event.target_key_id,
                event.target_fingerprint,
                event.target_role_mask,
            )?;
            if expected != event.subject_digest {
                return Err(AuthError::Invalid(
                    "registration subject digest mismatch".to_string(),
                ));
            }
        }
        KeyEventKind::Revoke => {
            if event.domain_code != DOMAIN_KEY_REVOKE
                || event.required_role != ROLE_KEY_ADMIN
                || event.target_role_mask != 0
            {
                return Err(AuthError::Invalid(
                    "invalid key revocation event".to_string(),
                ));
            }
            let signer = registry.states
                .get(&event.signer_key_id)
                .ok_or_else(|| AuthError::Invalid(
                    "revocation signer is unknown".to_string(),
                ))?;
            if !signer.has_role(ROLE_KEY_ADMIN)
                || signer.fingerprint != event.signer_fingerprint
            {
                return Err(AuthError::Invalid(
                    "revocation signer is not active KEY_ADMIN".to_string(),
                ));
            }
            let target = registry.states
                .get(&event.target_key_id)
                .ok_or_else(|| AuthError::Invalid(
                    "revocation target is unknown".to_string(),
                ))?;
            if !target.active
                || target.fingerprint != event.target_fingerprint
            {
                return Err(AuthError::Invalid(
                    "revocation target is not active/matching".to_string(),
                ));
            }
            if target.has_role(ROLE_KEY_ADMIN) {
                let remaining = registry.states.values().filter(|state| {
                    state.active
                        && state.key_id != event.target_key_id
                        && state.has_role(ROLE_KEY_ADMIN)
                }).count();
                if remaining == 0 {
                    return Err(AuthError::Invalid(
                        "revocation would remove last KEY_ADMIN".to_string(),
                    ));
                }
            }
            let expected = key_revoke_subject(
                &event.target_key_id,
                event.target_fingerprint,
            )?;
            if expected != event.subject_digest {
                return Err(AuthError::Invalid(
                    "revocation subject digest mismatch".to_string(),
                ));
            }
        }
    }

    if replay {
        // Cryptographic verification requires the secret and is performed at
        // mutation time. Replay still binds signer fingerprint, role, nonce,
        // subject and signature structurally.
    }
    Ok(())
}

fn apply_key_event(
    states: &mut BTreeMap<String, KeyState>,
    event: &KeyEvent,
) -> Result<()> {
    match event.kind {
        KeyEventKind::Bootstrap | KeyEventKind::Register => {
            if states.insert(
                event.target_key_id.clone(),
                KeyState {
                    key_id: event.target_key_id.clone(),
                    fingerprint: event.target_fingerprint,
                    role_mask: event.target_role_mask,
                    active: true,
                    registered_sequence: event.sequence,
                    revoked_sequence: None,
                },
            ).is_some() {
                return Err(AuthError::Invalid(
                    "key state duplicate insertion".to_string(),
                ));
            }
        }
        KeyEventKind::Revoke => {
            let state = states.get_mut(&event.target_key_id)
                .ok_or_else(|| AuthError::Invalid(
                    "revocation state missing".to_string(),
                ))?;
            state.active = false;
            state.revoked_sequence = Some(event.sequence);
        }
    }
    Ok(())
}

fn validate_authorization_proof(proof: &AuthorizationProof) -> Result<()> {
    validate_identifier("signer_key_id", &proof.signer_key_id)?;
    validate_identifier("nonce", &proof.nonce)?;
    if proof.logical_timestamp == 0 {
        return Err(AuthError::Invalid(
            "authorization timestamp must be greater than zero".to_string(),
        ));
    }
    validate_role_mask(proof.required_role)?;
    if !matches!(
        proof.domain_code,
        DOMAIN_POLICY_REGISTER | DOMAIN_TRUST_COMMIT
    ) {
        return Err(AuthError::Invalid(
            "unsupported authorization domain".to_string(),
        ));
    }
    if proof.domain_code == DOMAIN_POLICY_REGISTER
        && proof.required_role != ROLE_POLICY_ADMIN
    {
        return Err(AuthError::Invalid(
            "POLICY_REGISTER requires POLICY_ADMIN".to_string(),
        ));
    }
    if proof.domain_code == DOMAIN_TRUST_COMMIT
        && proof.required_role != ROLE_TRUST_OPERATOR
    {
        return Err(AuthError::Invalid(
            "TRUST_COMMIT requires TRUST_OPERATOR".to_string(),
        ));
    }
    if proof.subject_digest == [0; 32]
        || proof.signer_fingerprint == [0; 32]
        || proof.key_registry_head == [0; 32]
        || proof.signature == [0; 32]
    {
        return Err(AuthError::Invalid(
            "authorization contains zero digest/signature".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_role_mask(role_mask: u16) -> Result<()> {
    if role_mask == 0 || role_mask & !ROLE_ALL != 0 {
        return Err(AuthError::Invalid(format!(
            "invalid role mask {role_mask}",
        )));
    }
    Ok(())
}

pub fn role_names(role_mask: u16) -> Result<Vec<&'static str>> {
    validate_role_mask(role_mask)?;
    let mut names = Vec::new();
    if role_mask & ROLE_KEY_ADMIN != 0 {
        names.push("KEY_ADMIN");
    }
    if role_mask & ROLE_POLICY_ADMIN != 0 {
        names.push("POLICY_ADMIN");
    }
    if role_mask & ROLE_TRUST_OPERATOR != 0 {
        names.push("TRUST_OPERATOR");
    }
    if role_mask & ROLE_AUDITOR != 0 {
        names.push("AUDITOR");
    }
    Ok(names)
}

pub fn domain_name(code: u8) -> Result<&'static str> {
    match code {
        DOMAIN_KEY_BOOTSTRAP => Ok("KEY_BOOTSTRAP"),
        DOMAIN_KEY_REGISTER => Ok("KEY_REGISTER"),
        DOMAIN_KEY_REVOKE => Ok("KEY_REVOKE"),
        DOMAIN_POLICY_REGISTER => Ok("POLICY_REGISTER"),
        DOMAIN_TRUST_COMMIT => Ok("TRUST_COMMIT"),
        _ => Err(AuthError::Invalid(format!(
            "unknown authorization domain {code}",
        ))),
    }
}

fn encode_key_payload(event: &KeyEvent) -> Result<Vec<u8>> {
    let target = event.target_key_id.as_bytes();
    let signer = event.signer_key_id.as_bytes();
    let nonce = event.nonce.as_bytes();
    let mut output = Vec::new();
    output.extend_from_slice(&KEY_PAYLOAD_MAGIC);
    output.push(event.kind as u8);
    output.push(event.domain_code);
    output.extend_from_slice(&event.target_role_mask.to_le_bytes());
    output.extend_from_slice(&event.required_role.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&event.logical_timestamp.to_le_bytes());
    output.extend_from_slice(&(target.len() as u32).to_le_bytes());
    output.extend_from_slice(&(signer.len() as u32).to_le_bytes());
    output.extend_from_slice(&(nonce.len() as u32).to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&event.target_fingerprint);
    output.extend_from_slice(&event.subject_digest);
    output.extend_from_slice(&event.signer_fingerprint);
    output.extend_from_slice(&event.signature);
    debug_assert_eq!(output.len(), KEY_FIXED_BYTES);
    output.extend_from_slice(target);
    output.extend_from_slice(signer);
    output.extend_from_slice(nonce);
    Ok(output)
}

fn decode_key_payload(payload: &[u8]) -> Result<KeyEvent> {
    if payload.len() < KEY_FIXED_BYTES
        || payload[0..8] != KEY_PAYLOAD_MAGIC
    {
        return Err(AuthError::Invalid(
            "key payload header mismatch".to_string(),
        ));
    }
    let kind = KeyEventKind::from_code(payload[8])?;
    let domain_code = payload[9];
    let target_role_mask = read_u16(payload, 10)?;
    let required_role = read_u16(payload, 12)?;
    if read_u16(payload, 14)? != 0 {
        return Err(AuthError::Invalid(
            "key payload reserved field non-zero".to_string(),
        ));
    }
    let logical_timestamp = read_u64(payload, 16)?;
    let target_len = read_u32(payload, 24)? as usize;
    let signer_len = read_u32(payload, 28)? as usize;
    let nonce_len = read_u32(payload, 32)? as usize;
    if read_u32(payload, 36)? != 0 {
        return Err(AuthError::Invalid(
            "key payload reserved u32 non-zero".to_string(),
        ));
    }
    let target_fingerprint = read_digest(payload, 40)?;
    let subject_digest = read_digest(payload, 72)?;
    let signer_fingerprint = read_digest(payload, 104)?;
    let signature = read_digest(payload, 136)?;
    let mut cursor = KEY_FIXED_BYTES;
    let target_key_id = read_string(
        payload, &mut cursor, target_len, "target_key_id"
    )?;
    let signer_key_id = read_string(
        payload, &mut cursor, signer_len, "signer_key_id"
    )?;
    let nonce = read_string(
        payload, &mut cursor, nonce_len, "nonce"
    )?;
    if cursor != payload.len() {
        return Err(AuthError::Invalid(
            "key payload trailing bytes".to_string(),
        ));
    }
    Ok(KeyEvent {
        sequence: 0,
        kind,
        target_key_id,
        target_fingerprint,
        target_role_mask,
        signer_key_id,
        signer_fingerprint,
        required_role,
        domain_code,
        logical_timestamp,
        nonce,
        subject_digest,
        signature,
        previous_digest: [0; 32],
        frame_digest: [0; 32],
    })
}

fn encode_authorization_payload(
    proof: &AuthorizationProof,
) -> Result<Vec<u8>> {
    validate_authorization_proof(proof)?;
    let key_id = proof.signer_key_id.as_bytes();
    let nonce = proof.nonce.as_bytes();
    let mut output = Vec::new();
    output.extend_from_slice(&AUTH_PAYLOAD_MAGIC);
    output.push(proof.domain_code);
    output.push(0);
    output.extend_from_slice(&proof.required_role.to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&proof.logical_timestamp.to_le_bytes());
    output.extend_from_slice(&(key_id.len() as u32).to_le_bytes());
    output.extend_from_slice(&(nonce.len() as u32).to_le_bytes());
    output.extend_from_slice(&proof.subject_digest);
    output.extend_from_slice(&proof.signer_fingerprint);
    output.extend_from_slice(&proof.key_registry_head);
    output.extend_from_slice(&proof.signature);
    output.extend_from_slice(&0u64.to_le_bytes());
    debug_assert_eq!(output.len(), AUTH_FIXED_BYTES);
    output.extend_from_slice(key_id);
    output.extend_from_slice(nonce);
    Ok(output)
}

fn decode_authorization_payload(
    payload: &[u8],
) -> Result<AuthorizationProof> {
    if payload.len() < AUTH_FIXED_BYTES
        || payload[0..8] != AUTH_PAYLOAD_MAGIC
    {
        return Err(AuthError::Invalid(
            "authorization payload header mismatch".to_string(),
        ));
    }
    let domain_code = payload[8];
    if payload[9] != 0 {
        return Err(AuthError::Invalid(
            "authorization reserved byte non-zero".to_string(),
        ));
    }
    let required_role = read_u16(payload, 10)?;
    if read_u32(payload, 12)? != 0 {
        return Err(AuthError::Invalid(
            "authorization reserved u32 non-zero".to_string(),
        ));
    }
    let logical_timestamp = read_u64(payload, 16)?;
    let key_len = read_u32(payload, 24)? as usize;
    let nonce_len = read_u32(payload, 28)? as usize;
    let subject_digest = read_digest(payload, 32)?;
    let signer_fingerprint = read_digest(payload, 64)?;
    let key_registry_head = read_digest(payload, 96)?;
    let signature = read_digest(payload, 128)?;
    if read_u64(payload, 160)? != 0 {
        return Err(AuthError::Invalid(
            "authorization reserved u64 non-zero".to_string(),
        ));
    }
    let mut cursor = AUTH_FIXED_BYTES;
    let signer_key_id = read_string(
        payload, &mut cursor, key_len, "signer_key_id"
    )?;
    let nonce = read_string(
        payload, &mut cursor, nonce_len, "nonce"
    )?;
    if cursor != payload.len() {
        return Err(AuthError::Invalid(
            "authorization payload trailing bytes".to_string(),
        ));
    }
    let proof = AuthorizationProof {
        domain_code,
        required_role,
        logical_timestamp,
        subject_digest,
        signer_key_id,
        signer_fingerprint,
        key_registry_head,
        nonce,
        signature,
    };
    validate_authorization_proof(&proof)?;
    Ok(proof)
}

struct Frame {
    sequence: u64,
    previous_digest: [u8; 32],
    frame_digest: [u8; 32],
    payload: Vec<u8>,
}

fn encode_frame(
    magic: [u8; 8],
    sequence: u64,
    previous_digest: [u8; 32],
    payload_digest: [u8; 32],
    frame_digest: [u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(AuthError::Invalid(
            "ledger payload exceeds maximum".to_string(),
        ));
    }
    let mut output = Vec::new();
    output.extend_from_slice(&magic);
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

fn decode_frames(
    context: &'static str,
    magic: [u8; 8],
    domain: [u8; 8],
    bytes: &[u8],
) -> Result<Vec<Frame>> {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    let mut head = [0u8; 32];
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if remaining < FRAME_HEADER_BYTES {
            return Err(AuthError::TruncatedTail {
                context,
                offset,
                remaining_bytes: remaining,
            });
        }
        let header = &bytes[offset..offset + FRAME_HEADER_BYTES];
        if header[0..8] != magic
            || read_u16(header, 8)? != 1
            || read_u16(header, 10)? != 0
            || read_u32(header, 12)? as usize != FRAME_HEADER_BYTES
        {
            return Err(AuthError::Invalid(format!(
                "{context} frame header mismatch",
            )));
        }
        let sequence = read_u64(header, 16)?;
        if sequence != frames.len() as u64 + 1 {
            return Err(AuthError::Invalid(format!(
                "{context} sequence mismatch",
            )));
        }
        let payload_len = usize::try_from(read_u64(header, 24)?)
            .map_err(|_| AuthError::Invalid(
                "payload length overflow".to_string(),
            ))?;
        if payload_len > MAX_PAYLOAD_BYTES {
            return Err(AuthError::Invalid(
                "payload length exceeds maximum".to_string(),
            ));
        }
        let previous_digest = read_digest(header, 32)?;
        let expected_payload_digest = read_digest(header, 64)?;
        let expected_frame_digest = read_digest(header, 96)?;
        if header[128..144] != [0; 16] {
            return Err(AuthError::Invalid(
                "frame reserved bytes non-zero".to_string(),
            ));
        }
        if previous_digest != head {
            return Err(AuthError::Integrity {
                context: format!("{context} previous digest"),
                expected: head,
                actual: previous_digest,
            });
        }
        let payload_start = offset + FRAME_HEADER_BYTES;
        let frame_end = payload_start
            .checked_add(payload_len)
            .ok_or_else(|| AuthError::Invalid(
                "frame length overflow".to_string(),
            ))?;
        if frame_end > bytes.len() {
            return Err(AuthError::TruncatedTail {
                context,
                offset,
                remaining_bytes: remaining,
            });
        }
        let payload = bytes[payload_start..frame_end].to_vec();
        let actual_payload_digest = sha256(&payload);
        if actual_payload_digest != expected_payload_digest {
            return Err(AuthError::Integrity {
                context: format!("{context} payload"),
                expected: expected_payload_digest,
                actual: actual_payload_digest,
            });
        }
        let actual_frame_digest = compute_frame_digest(
            domain,
            sequence,
            previous_digest,
            expected_payload_digest,
        );
        if actual_frame_digest != expected_frame_digest {
            return Err(AuthError::Integrity {
                context: format!("{context} frame"),
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
    domain: [u8; 8],
    sequence: u64,
    previous_digest: [u8; 32],
    payload_digest: [u8; 32],
) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&domain);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    #[test]
    fn bootstrap_register_revoke() {
        let root = std::env::temp_dir().join(format!(
            "ubdb-auth-test-{}",
            std::process::id(),
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join("keys.ubkey");

        let mut registry = KeyRegistry::create(&path).unwrap();
        registry.bootstrap(
            "root",
            ROLE_ALL,
            &secret(1),
            1,
            "nonce-1",
        ).unwrap();
        registry.register_key(
            "operator",
            ROLE_TRUST_OPERATOR,
            &secret(2),
            "root",
            &secret(1),
            2,
            "nonce-2",
        ).unwrap();
        registry.revoke_key(
            "operator",
            "root",
            &secret(1),
            3,
            "nonce-3",
        ).unwrap();
        assert_eq!(registry.event_count(), 3);
        assert!(!registry.get("operator").unwrap().active);

        let reopened = KeyRegistry::open_strict(&path).unwrap();
        assert_eq!(reopened.event_count(), 3);
        assert!(!reopened.get("operator").unwrap().active);
        let _ = fs::remove_dir_all(&root);
    }
}
