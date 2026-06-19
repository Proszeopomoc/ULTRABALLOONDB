use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ultraballoondb_storage::sha256;

use crate::{
    create_persisted_key, sign_digest, validate_identifier,
    validate_public_blob,
    verify_digest, AsymmetricError, Result, SOFTWARE_KSP,
};

const REGISTRY_MAGIC: [u8; 8] = *b"UBAKY01\0";
const REGISTRY_PAYLOAD_MAGIC: [u8; 8] = *b"UBAKP01\0";
const REGISTRY_FRAME_DOMAIN: [u8; 8] = *b"UBAKYFR1";
const REGISTRY_SUBJECT_DOMAIN: [u8; 8] = *b"UBAKSUB1";
const FRAME_HEADER_BYTES: usize = 144;
const EVENT_FIXED_BYTES: usize = 328;
const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AsymmetricKeyEventKind {
    Enroll = 1,
    Rotate = 2,
    Revoke = 3,
}

impl AsymmetricKeyEventKind {
    fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Enroll),
            2 => Ok(Self::Rotate),
            3 => Ok(Self::Revoke),
            _ => Err(AsymmetricError::Invalid(format!(
                "unknown asymmetric key event kind {value}",
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enroll => "ENROLL",
            Self::Rotate => "ROTATE",
            Self::Revoke => "REVOKE",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsymmetricKeyEvent {
    pub sequence: u64,
    pub kind: AsymmetricKeyEventKind,
    pub role_mask: u16,
    pub logical_timestamp: u64,
    pub generation: u64,
    pub key_id: String,
    pub provider_name: String,
    pub provider_key_name: String,
    pub public_blob: Vec<u8>,
    pub public_key_digest: [u8; 32],
    pub previous_public_key_digest: [u8; 32],
    pub provider_key_name_digest: [u8; 32],
    pub subject_digest: [u8; 32],
    pub signature_old: [u8; 64],
    pub signature_new: [u8; 64],
    pub nonce: String,
    pub previous_digest: [u8; 32],
    pub frame_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsymmetricKeyState {
    pub key_id: String,
    pub provider_name: String,
    pub provider_key_name: String,
    pub role_mask: u16,
    pub generation: u64,
    pub public_blob: Vec<u8>,
    pub public_key_digest: [u8; 32],
    pub active: bool,
    pub last_event_sequence: u64,
}

impl AsymmetricKeyState {
    pub fn has_role(&self, required_role_mask: u16) -> bool {
        self.active
            && required_role_mask != 0
            && self.role_mask & required_role_mask
                == required_role_mask
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEventReceipt {
    pub changed: bool,
    pub sequence: u64,
    pub event_kind: AsymmetricKeyEventKind,
    pub key_id: String,
    pub generation: u64,
    pub public_key_digest: [u8; 32],
    pub frame_digest: [u8; 32],
    pub private_export_rejected: bool,
}

#[derive(Debug)]
pub struct AsymmetricKeyRegistry {
    path: PathBuf,
    events: Vec<AsymmetricKeyEvent>,
    states: BTreeMap<String, AsymmetricKeyState>,
    states_by_head:
        BTreeMap<[u8; 32], BTreeMap<String, AsymmetricKeyState>>,
    used_nonces: BTreeSet<(String, String)>,
    head_digest: [u8; 32],
    last_timestamp: u64,
}

impl AsymmetricKeyRegistry {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        create_empty_file(&path)?;
        let mut states_by_head = BTreeMap::new();
        states_by_head.insert([0; 32], BTreeMap::new());
        Ok(Self {
            path,
            events: Vec::new(),
            states: BTreeMap::new(),
            states_by_head,
            used_nonces: BTreeSet::new(),
            head_digest: [0; 32],
            last_timestamp: 0,
        })
    }

    pub fn open_strict(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.is_file() {
            return Err(AsymmetricError::Invalid(format!(
                "asymmetric key registry missing: {}",
                path.display(),
            )));
        }
        let bytes = fs::read(&path)?;
        let mut states_by_head = BTreeMap::new();
        states_by_head.insert([0; 32], BTreeMap::new());
        let mut registry = Self {
            path,
            events: Vec::new(),
            states: BTreeMap::new(),
            states_by_head,
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

    pub fn events(&self) -> &[AsymmetricKeyEvent] {
        &self.events
    }

    pub fn states(
        &self,
    ) -> &BTreeMap<String, AsymmetricKeyState> {
        &self.states
    }

    pub fn get(&self, key_id: &str) -> Option<&AsymmetricKeyState> {
        self.states.get(key_id)
    }

    pub fn state_at_head(
        &self,
        head: &[u8; 32],
        key_id: &str,
    ) -> Option<&AsymmetricKeyState> {
        self.states_by_head
            .get(head)
            .and_then(|states| states.get(key_id))
    }

    pub fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn active_key_count(&self) -> usize {
        self.states.values().filter(|state| state.active).count()
    }


    pub fn enroll_new_key_with_provider(
        &mut self,
        provider: &dyn crate::SigningProvider,
        requirement: crate::ProviderRequirement,
        key_id: &str,
        role_mask: u16,
        provider_key_name: &str,
        logical_timestamp: u64,
        nonce: &str,
    ) -> Result<KeyEventReceipt> {
        validate_identifier("key_id", key_id)?;
        validate_identifier("provider_key_name", provider_key_name)?;
        validate_identifier("nonce", nonce)?;
        if role_mask == 0 || self.states.contains_key(key_id) {
            return Err(AsymmetricError::Invalid(
                "role mask zero or key ID already exists".to_string(),
            ));
        }
        let capabilities = crate::enforce_provider_requirement(provider, requirement)?;
        let material = provider.create_key(provider_key_name)?;
        if material.provider_name != capabilities.provider_name
            || !material.private_export_rejected
        {
            return Err(AsymmetricError::Integrity(
                "provider material does not match admitted capabilities".to_string(),
            ));
        }
        validate_public_blob(&material.public_blob)?;
        let public_key_digest = sha256(&material.public_blob);
        let subject_digest = registry_event_subject_digest(
            AsymmetricKeyEventKind::Enroll,
            role_mask,
            logical_timestamp,
            1,
            key_id,
            &capabilities.provider_name,
            provider_key_name,
            public_key_digest,
            [0; 32],
            nonce,
        )?;
        let signature_new = provider.sign(provider_key_name, &subject_digest)?;
        if !provider.verify(&material.public_blob, &subject_digest, &signature_new)? {
            return Err(AsymmetricError::Integrity(
                "provider enrollment proof failed".to_string(),
            ));
        }
        let event = AsymmetricKeyEvent {
            sequence: 0,
            kind: AsymmetricKeyEventKind::Enroll,
            role_mask,
            logical_timestamp,
            generation: 1,
            key_id: key_id.to_string(),
            provider_name: capabilities.provider_name,
            provider_key_name: provider_key_name.to_string(),
            public_blob: material.public_blob,
            public_key_digest,
            previous_public_key_digest: [0; 32],
            provider_key_name_digest: sha256(provider_key_name.as_bytes()),
            subject_digest,
            signature_old: [0; 64],
            signature_new,
            nonce: nonce.to_string(),
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        };
        let appended = self.append(event)?;
        Ok(KeyEventReceipt {
            changed: true,
            sequence: appended.sequence,
            event_kind: appended.kind,
            key_id: appended.key_id,
            generation: appended.generation,
            public_key_digest: appended.public_key_digest,
            frame_digest: appended.frame_digest,
            private_export_rejected: material.private_export_rejected,
        })
    }

    pub fn rotate_to_new_key_with_providers(
        &mut self,
        old_provider: &dyn crate::SigningProvider,
        new_provider: &dyn crate::SigningProvider,
        new_requirement: crate::ProviderRequirement,
        key_id: &str,
        old_provider_key_name: &str,
        new_provider_key_name: &str,
        logical_timestamp: u64,
        nonce: &str,
    ) -> Result<KeyEventReceipt> {
        validate_identifier("key_id", key_id)?;
        validate_identifier("old_provider_key_name", old_provider_key_name)?;
        validate_identifier("new_provider_key_name", new_provider_key_name)?;
        validate_identifier("nonce", nonce)?;
        let current = self.states.get(key_id).cloned().ok_or_else(|| {
            AsymmetricError::Invalid(format!("asymmetric key not found: {key_id}"))
        })?;
        if !current.active
            || current.provider_name != old_provider.capabilities().provider_name
            || current.provider_key_name != old_provider_key_name
        {
            return Err(AsymmetricError::Invalid(
                "old provider does not match active registry state".to_string(),
            ));
        }
        let new_capabilities = crate::enforce_provider_requirement(new_provider, new_requirement)?;
        let material = new_provider.create_key(new_provider_key_name)?;
        if material.provider_name != new_capabilities.provider_name
            || !material.private_export_rejected
        {
            return Err(AsymmetricError::Integrity(
                "new provider material mismatch".to_string(),
            ));
        }
        let new_public_digest = sha256(&material.public_blob);
        if new_public_digest == current.public_key_digest {
            return Err(AsymmetricError::Invalid(
                "rotation public key did not change".to_string(),
            ));
        }
        let generation = current.generation.checked_add(1).ok_or_else(|| {
            AsymmetricError::Invalid("key generation overflow".to_string())
        })?;
        let subject_digest = registry_event_subject_digest(
            AsymmetricKeyEventKind::Rotate,
            current.role_mask,
            logical_timestamp,
            generation,
            key_id,
            &new_capabilities.provider_name,
            new_provider_key_name,
            new_public_digest,
            current.public_key_digest,
            nonce,
        )?;
        let signature_old = old_provider.sign(old_provider_key_name, &subject_digest)?;
        let signature_new = new_provider.sign(new_provider_key_name, &subject_digest)?;
        if !old_provider.verify(&current.public_blob, &subject_digest, &signature_old)?
            || !new_provider.verify(&material.public_blob, &subject_digest, &signature_new)?
        {
            return Err(AsymmetricError::Integrity(
                "provider-neutral dual-proof rotation failed".to_string(),
            ));
        }
        let event = AsymmetricKeyEvent {
            sequence: 0,
            kind: AsymmetricKeyEventKind::Rotate,
            role_mask: current.role_mask,
            logical_timestamp,
            generation,
            key_id: key_id.to_string(),
            provider_name: new_capabilities.provider_name,
            provider_key_name: new_provider_key_name.to_string(),
            public_blob: material.public_blob,
            public_key_digest: new_public_digest,
            previous_public_key_digest: current.public_key_digest,
            provider_key_name_digest: sha256(new_provider_key_name.as_bytes()),
            subject_digest,
            signature_old,
            signature_new,
            nonce: nonce.to_string(),
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        };
        let appended = self.append(event)?;
        Ok(KeyEventReceipt {
            changed: true,
            sequence: appended.sequence,
            event_kind: appended.kind,
            key_id: appended.key_id,
            generation: appended.generation,
            public_key_digest: appended.public_key_digest,
            frame_digest: appended.frame_digest,
            private_export_rejected: material.private_export_rejected,
        })
    }

    pub fn revoke_with_provider(
        &mut self,
        provider: &dyn crate::SigningProvider,
        key_id: &str,
        provider_key_name: &str,
        logical_timestamp: u64,
        nonce: &str,
    ) -> Result<KeyEventReceipt> {
        validate_identifier("key_id", key_id)?;
        validate_identifier("provider_key_name", provider_key_name)?;
        validate_identifier("nonce", nonce)?;
        let current = self.states.get(key_id).cloned().ok_or_else(|| {
            AsymmetricError::Invalid(format!("asymmetric key not found: {key_id}"))
        })?;
        if !current.active
            || current.provider_name != provider.capabilities().provider_name
            || current.provider_key_name != provider_key_name
        {
            return Err(AsymmetricError::Invalid(
                "provider does not match active registry state".to_string(),
            ));
        }
        let subject_digest = registry_event_subject_digest(
            AsymmetricKeyEventKind::Revoke,
            current.role_mask,
            logical_timestamp,
            current.generation,
            key_id,
            &current.provider_name,
            provider_key_name,
            current.public_key_digest,
            current.public_key_digest,
            nonce,
        )?;
        let signature_old = provider.sign(provider_key_name, &subject_digest)?;
        if !provider.verify(&current.public_blob, &subject_digest, &signature_old)? {
            return Err(AsymmetricError::Integrity(
                "provider revocation proof failed".to_string(),
            ));
        }
        let event = AsymmetricKeyEvent {
            sequence: 0,
            kind: AsymmetricKeyEventKind::Revoke,
            role_mask: current.role_mask,
            logical_timestamp,
            generation: current.generation,
            key_id: key_id.to_string(),
            provider_name: current.provider_name.clone(),
            provider_key_name: current.provider_key_name.clone(),
            public_blob: current.public_blob.clone(),
            public_key_digest: current.public_key_digest,
            previous_public_key_digest: current.public_key_digest,
            provider_key_name_digest: sha256(provider_key_name.as_bytes()),
            subject_digest,
            signature_old,
            signature_new: [0; 64],
            nonce: nonce.to_string(),
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        };
        let appended = self.append(event)?;
        Ok(KeyEventReceipt {
            changed: true,
            sequence: appended.sequence,
            event_kind: appended.kind,
            key_id: appended.key_id,
            generation: appended.generation,
            public_key_digest: appended.public_key_digest,
            frame_digest: appended.frame_digest,
            private_export_rejected: true,
        })
    }

    pub fn enroll_new_provider_key(
        &mut self,
        key_id: &str,
        role_mask: u16,
        provider_key_name: &str,
        logical_timestamp: u64,
        nonce: &str,
    ) -> Result<KeyEventReceipt> {
        validate_identifier("key_id", key_id)?;
        validate_identifier(
            "provider_key_name",
            provider_key_name,
        )?;
        validate_identifier("nonce", nonce)?;
        if role_mask == 0 {
            return Err(AsymmetricError::Invalid(
                "role mask cannot be zero".to_string(),
            ));
        }
        if self.states.contains_key(key_id) {
            return Err(AsymmetricError::Invalid(format!(
                "asymmetric key ID already exists: {key_id}",
            )));
        }
        let material = create_persisted_key(
            SOFTWARE_KSP,
            provider_key_name,
        )?;
        let public_key_digest = sha256(&material.public_blob);
        let subject_digest = registry_event_subject_digest(
            AsymmetricKeyEventKind::Enroll,
            role_mask,
            logical_timestamp,
            1,
            key_id,
            SOFTWARE_KSP,
            provider_key_name,
            public_key_digest,
            [0; 32],
            nonce,
        )?;
        let signature_new = sign_digest(
            SOFTWARE_KSP,
            provider_key_name,
            &subject_digest,
        )?;
        if !verify_digest(
            &material.public_blob,
            &subject_digest,
            &signature_new,
        )? {
            return Err(AsymmetricError::Integrity(
                "new key enrollment proof failed verification"
                    .to_string(),
            ));
        }
        let event = AsymmetricKeyEvent {
            sequence: 0,
            kind: AsymmetricKeyEventKind::Enroll,
            role_mask,
            logical_timestamp,
            generation: 1,
            key_id: key_id.to_string(),
            provider_name: SOFTWARE_KSP.to_string(),
            provider_key_name: provider_key_name.to_string(),
            public_blob: material.public_blob,
            public_key_digest,
            previous_public_key_digest: [0; 32],
            provider_key_name_digest: sha256(
                provider_key_name.as_bytes(),
            ),
            subject_digest,
            signature_old: [0; 64],
            signature_new,
            nonce: nonce.to_string(),
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        };
        let appended = self.append(event)?;
        Ok(KeyEventReceipt {
            changed: true,
            sequence: appended.sequence,
            event_kind: appended.kind,
            key_id: appended.key_id,
            generation: appended.generation,
            public_key_digest: appended.public_key_digest,
            frame_digest: appended.frame_digest,
            private_export_rejected:
                material.private_export_rejected,
        })
    }

    pub fn rotate_to_new_provider_key(
        &mut self,
        key_id: &str,
        old_provider_key_name: &str,
        new_provider_key_name: &str,
        logical_timestamp: u64,
        nonce: &str,
    ) -> Result<KeyEventReceipt> {
        validate_identifier("key_id", key_id)?;
        validate_identifier(
            "old_provider_key_name",
            old_provider_key_name,
        )?;
        validate_identifier(
            "new_provider_key_name",
            new_provider_key_name,
        )?;
        validate_identifier("nonce", nonce)?;
        let current = self.states.get(key_id)
            .cloned()
            .ok_or_else(|| AsymmetricError::Invalid(format!(
                "asymmetric key not found: {key_id}",
            )))?;
        if !current.active {
            return Err(AsymmetricError::Invalid(
                "cannot rotate a revoked key".to_string(),
            ));
        }
        if current.provider_name != SOFTWARE_KSP
            || current.provider_key_name
                != old_provider_key_name
        {
            return Err(AsymmetricError::Invalid(
                "old provider key does not match registry state"
                    .to_string(),
            ));
        }
        let material = create_persisted_key(
            SOFTWARE_KSP,
            new_provider_key_name,
        )?;
        let new_public_digest = sha256(&material.public_blob);
        if new_public_digest == current.public_key_digest {
            return Err(AsymmetricError::Invalid(
                "rotation public key did not change".to_string(),
            ));
        }
        let generation = current.generation
            .checked_add(1)
            .ok_or_else(|| AsymmetricError::Invalid(
                "key generation overflow".to_string(),
            ))?;
        let subject_digest = registry_event_subject_digest(
            AsymmetricKeyEventKind::Rotate,
            current.role_mask,
            logical_timestamp,
            generation,
            key_id,
            SOFTWARE_KSP,
            new_provider_key_name,
            new_public_digest,
            current.public_key_digest,
            nonce,
        )?;
        let signature_old = sign_digest(
            SOFTWARE_KSP,
            old_provider_key_name,
            &subject_digest,
        )?;
        let signature_new = sign_digest(
            SOFTWARE_KSP,
            new_provider_key_name,
            &subject_digest,
        )?;
        if !verify_digest(
            &current.public_blob,
            &subject_digest,
            &signature_old,
        )? || !verify_digest(
            &material.public_blob,
            &subject_digest,
            &signature_new,
        )? {
            return Err(AsymmetricError::Integrity(
                "dual-proof key rotation verification failed"
                    .to_string(),
            ));
        }
        let event = AsymmetricKeyEvent {
            sequence: 0,
            kind: AsymmetricKeyEventKind::Rotate,
            role_mask: current.role_mask,
            logical_timestamp,
            generation,
            key_id: key_id.to_string(),
            provider_name: SOFTWARE_KSP.to_string(),
            provider_key_name:
                new_provider_key_name.to_string(),
            public_blob: material.public_blob,
            public_key_digest: new_public_digest,
            previous_public_key_digest:
                current.public_key_digest,
            provider_key_name_digest: sha256(
                new_provider_key_name.as_bytes(),
            ),
            subject_digest,
            signature_old,
            signature_new,
            nonce: nonce.to_string(),
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        };
        let appended = self.append(event)?;
        Ok(KeyEventReceipt {
            changed: true,
            sequence: appended.sequence,
            event_kind: appended.kind,
            key_id: appended.key_id,
            generation: appended.generation,
            public_key_digest: appended.public_key_digest,
            frame_digest: appended.frame_digest,
            private_export_rejected:
                material.private_export_rejected,
        })
    }

    pub fn revoke(
        &mut self,
        key_id: &str,
        provider_key_name: &str,
        logical_timestamp: u64,
        nonce: &str,
    ) -> Result<KeyEventReceipt> {
        validate_identifier("key_id", key_id)?;
        validate_identifier(
            "provider_key_name",
            provider_key_name,
        )?;
        validate_identifier("nonce", nonce)?;
        let current = self.states.get(key_id)
            .cloned()
            .ok_or_else(|| AsymmetricError::Invalid(format!(
                "asymmetric key not found: {key_id}",
            )))?;
        if !current.active {
            return Err(AsymmetricError::Invalid(
                "key is already revoked".to_string(),
            ));
        }
        if current.provider_key_name != provider_key_name {
            return Err(AsymmetricError::Invalid(
                "provider key does not match active registry state"
                    .to_string(),
            ));
        }
        let subject_digest = registry_event_subject_digest(
            AsymmetricKeyEventKind::Revoke,
            current.role_mask,
            logical_timestamp,
            current.generation,
            key_id,
            &current.provider_name,
            provider_key_name,
            current.public_key_digest,
            current.public_key_digest,
            nonce,
        )?;
        let signature_old = sign_digest(
            &current.provider_name,
            provider_key_name,
            &subject_digest,
        )?;
        if !verify_digest(
            &current.public_blob,
            &subject_digest,
            &signature_old,
        )? {
            return Err(AsymmetricError::Integrity(
                "key revocation proof failed verification"
                    .to_string(),
            ));
        }
        let event = AsymmetricKeyEvent {
            sequence: 0,
            kind: AsymmetricKeyEventKind::Revoke,
            role_mask: current.role_mask,
            logical_timestamp,
            generation: current.generation,
            key_id: key_id.to_string(),
            provider_name: current.provider_name.clone(),
            provider_key_name:
                current.provider_key_name.clone(),
            public_blob: current.public_blob.clone(),
            public_key_digest: current.public_key_digest,
            previous_public_key_digest:
                current.public_key_digest,
            provider_key_name_digest: sha256(
                provider_key_name.as_bytes(),
            ),
            subject_digest,
            signature_old,
            signature_new: [0; 64],
            nonce: nonce.to_string(),
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        };
        let appended = self.append(event)?;
        Ok(KeyEventReceipt {
            changed: true,
            sequence: appended.sequence,
            event_kind: appended.kind,
            key_id: appended.key_id,
            generation: appended.generation,
            public_key_digest: appended.public_key_digest,
            frame_digest: appended.frame_digest,
            private_export_rejected: true,
        })
    }

    fn append(
        &mut self,
        mut event: AsymmetricKeyEvent,
    ) -> Result<AsymmetricKeyEvent> {
        if event.logical_timestamp <= self.last_timestamp {
            return Err(AsymmetricError::Invalid(
                "key event timestamps must be strictly increasing"
                    .to_string(),
            ));
        }
        let nonce_key = (
            event.key_id.clone(),
            event.nonce.clone(),
        );
        if self.used_nonces.contains(&nonce_key) {
            return Err(AsymmetricError::Invalid(
                "key event nonce already used".to_string(),
            ));
        }
        event.sequence = self.events.len() as u64 + 1;
        event.previous_digest = self.head_digest;
        validate_event(&self.states, &event)?;
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
        apply_event(&mut self.states, &event)?;
        self.used_nonces.insert(nonce_key);
        self.last_timestamp = event.logical_timestamp;
        self.head_digest = event.frame_digest;
        self.events.push(event.clone());
        self.states_by_head.insert(
            self.head_digest,
            self.states.clone(),
        );
        Ok(event)
    }

    fn replay(&mut self, bytes: &[u8]) -> Result<()> {
        for frame in decode_frames(bytes)? {
            let mut event = decode_payload(&frame.payload)?;
            event.sequence = frame.sequence;
            event.previous_digest = frame.previous_digest;
            event.frame_digest = frame.frame_digest;
            if event.logical_timestamp <= self.last_timestamp {
                return Err(AsymmetricError::Invalid(
                    "key registry timestamp order mismatch"
                        .to_string(),
                ));
            }
            let nonce_key = (
                event.key_id.clone(),
                event.nonce.clone(),
            );
            if self.used_nonces.contains(&nonce_key) {
                return Err(AsymmetricError::Invalid(
                    "key registry duplicate nonce".to_string(),
                ));
            }
            validate_event(&self.states, &event)?;
            apply_event(&mut self.states, &event)?;
            self.used_nonces.insert(nonce_key);
            self.last_timestamp = event.logical_timestamp;
            self.head_digest = event.frame_digest;
            self.events.push(event);
            self.states_by_head.insert(
                self.head_digest,
                self.states.clone(),
            );
        }
        Ok(())
    }
}

pub fn registry_event_subject_digest(
    kind: AsymmetricKeyEventKind,
    role_mask: u16,
    logical_timestamp: u64,
    generation: u64,
    key_id: &str,
    provider_name: &str,
    provider_key_name: &str,
    public_key_digest: [u8; 32],
    previous_public_key_digest: [u8; 32],
    nonce: &str,
) -> Result<[u8; 32]> {
    validate_identifier("key_id", key_id)?;
    validate_identifier("provider_name", provider_name)?;
    validate_identifier(
        "provider_key_name",
        provider_key_name,
    )?;
    validate_identifier("nonce", nonce)?;
    if role_mask == 0
        || logical_timestamp == 0
        || generation == 0
        || public_key_digest == [0; 32]
    {
        return Err(AsymmetricError::Invalid(
            "invalid registry subject fields".to_string(),
        ));
    }
    let key = key_id.as_bytes();
    let provider = provider_name.as_bytes();
    let provider_key = provider_key_name.as_bytes();
    let nonce_bytes = nonce.as_bytes();
    let mut output = Vec::new();
    output.extend_from_slice(&REGISTRY_SUBJECT_DOMAIN);
    output.push(kind as u8);
    output.push(1);
    output.extend_from_slice(&role_mask.to_le_bytes());
    output.extend_from_slice(
        &logical_timestamp.to_le_bytes(),
    );
    output.extend_from_slice(&generation.to_le_bytes());
    output.extend_from_slice(&public_key_digest);
    output.extend_from_slice(
        &previous_public_key_digest,
    );
    output.extend_from_slice(&(key.len() as u32).to_le_bytes());
    output.extend_from_slice(
        &(provider.len() as u32).to_le_bytes(),
    );
    output.extend_from_slice(
        &(provider_key.len() as u32).to_le_bytes(),
    );
    output.extend_from_slice(
        &(nonce_bytes.len() as u32).to_le_bytes(),
    );
    output.extend_from_slice(key);
    output.extend_from_slice(provider);
    output.extend_from_slice(provider_key);
    output.extend_from_slice(nonce_bytes);
    Ok(sha256(&output))
}

fn validate_event(
    states: &BTreeMap<String, AsymmetricKeyState>,
    event: &AsymmetricKeyEvent,
) -> Result<()> {
    validate_identifier("key_id", &event.key_id)?;
    validate_identifier(
        "provider_name",
        &event.provider_name,
    )?;
    validate_identifier(
        "provider_key_name",
        &event.provider_key_name,
    )?;
    validate_identifier("nonce", &event.nonce)?;
    validate_public_blob(&event.public_blob)?;
    if event.role_mask == 0
        || event.logical_timestamp == 0
        || event.generation == 0
        || event.public_key_digest
            != sha256(&event.public_blob)
        || event.provider_key_name_digest
            != sha256(event.provider_key_name.as_bytes())
    {
        return Err(AsymmetricError::Invalid(
            "asymmetric key event invariant mismatch"
                .to_string(),
        ));
    }
    let expected_subject = registry_event_subject_digest(
        event.kind,
        event.role_mask,
        event.logical_timestamp,
        event.generation,
        &event.key_id,
        &event.provider_name,
        &event.provider_key_name,
        event.public_key_digest,
        event.previous_public_key_digest,
        &event.nonce,
    )?;
    if expected_subject != event.subject_digest {
        return Err(AsymmetricError::Integrity(
            "asymmetric key event subject mismatch"
                .to_string(),
        ));
    }

    match event.kind {
        AsymmetricKeyEventKind::Enroll => {
            if states.contains_key(&event.key_id)
                || event.generation != 1
                || event.previous_public_key_digest != [0; 32]
                || event.signature_old != [0; 64]
                || event.signature_new == [0; 64]
                || !verify_digest(
                    &event.public_blob,
                    &event.subject_digest,
                    &event.signature_new,
                )?
            {
                return Err(AsymmetricError::Invalid(
                    "invalid ENROLL event".to_string(),
                ));
            }
        }
        AsymmetricKeyEventKind::Rotate => {
            let current = states.get(&event.key_id)
                .ok_or_else(|| AsymmetricError::Invalid(
                    "ROTATE references unknown key".to_string(),
                ))?;
            if !current.active
                || event.role_mask != current.role_mask
                || event.generation != current.generation + 1
                || event.previous_public_key_digest
                    != current.public_key_digest
                || event.public_key_digest
                    == current.public_key_digest
                || event.signature_old == [0; 64]
                || event.signature_new == [0; 64]
                || !verify_digest(
                    &current.public_blob,
                    &event.subject_digest,
                    &event.signature_old,
                )?
                || !verify_digest(
                    &event.public_blob,
                    &event.subject_digest,
                    &event.signature_new,
                )?
            {
                return Err(AsymmetricError::Invalid(
                    "invalid ROTATE event".to_string(),
                ));
            }
        }
        AsymmetricKeyEventKind::Revoke => {
            let current = states.get(&event.key_id)
                .ok_or_else(|| AsymmetricError::Invalid(
                    "REVOKE references unknown key".to_string(),
                ))?;
            if !current.active
                || event.role_mask != current.role_mask
                || event.generation != current.generation
                || event.provider_key_name
                    != current.provider_key_name
                || event.public_key_digest
                    != current.public_key_digest
                || event.previous_public_key_digest
                    != current.public_key_digest
                || event.public_blob != current.public_blob
                || event.signature_old == [0; 64]
                || event.signature_new != [0; 64]
                || !verify_digest(
                    &current.public_blob,
                    &event.subject_digest,
                    &event.signature_old,
                )?
            {
                return Err(AsymmetricError::Invalid(
                    "invalid REVOKE event".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn apply_event(
    states: &mut BTreeMap<String, AsymmetricKeyState>,
    event: &AsymmetricKeyEvent,
) -> Result<()> {
    match event.kind {
        AsymmetricKeyEventKind::Enroll
        | AsymmetricKeyEventKind::Rotate => {
            states.insert(
                event.key_id.clone(),
                AsymmetricKeyState {
                    key_id: event.key_id.clone(),
                    provider_name: event.provider_name.clone(),
                    provider_key_name:
                        event.provider_key_name.clone(),
                    role_mask: event.role_mask,
                    generation: event.generation,
                    public_blob: event.public_blob.clone(),
                    public_key_digest:
                        event.public_key_digest,
                    active: true,
                    last_event_sequence: event.sequence,
                },
            );
        }
        AsymmetricKeyEventKind::Revoke => {
            let state = states.get_mut(&event.key_id)
                .ok_or_else(|| AsymmetricError::Invalid(
                    "revoked state disappeared".to_string(),
                ))?;
            state.active = false;
            state.last_event_sequence = event.sequence;
        }
    }
    Ok(())
}

fn encode_payload(
    event: &AsymmetricKeyEvent,
) -> Result<Vec<u8>> {
    let key = event.key_id.as_bytes();
    let provider = event.provider_name.as_bytes();
    let provider_key = event.provider_key_name.as_bytes();
    let nonce = event.nonce.as_bytes();
    if event.public_blob.len() > MAX_PAYLOAD_BYTES {
        return Err(AsymmetricError::Invalid(
            "public blob too large".to_string(),
        ));
    }
    let mut output = Vec::new();
    output.extend_from_slice(&REGISTRY_PAYLOAD_MAGIC);
    output.push(event.kind as u8);
    output.push(1);
    output.push(1);
    output.push(u8::from(
        event.kind != AsymmetricKeyEventKind::Revoke,
    ));
    output.extend_from_slice(&event.role_mask.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(
        &event.logical_timestamp.to_le_bytes(),
    );
    output.extend_from_slice(&event.generation.to_le_bytes());
    output.extend_from_slice(&(key.len() as u32).to_le_bytes());
    output.extend_from_slice(
        &(provider.len() as u32).to_le_bytes(),
    );
    output.extend_from_slice(
        &(provider_key.len() as u32).to_le_bytes(),
    );
    output.extend_from_slice(
        &(event.public_blob.len() as u32).to_le_bytes(),
    );
    output.extend_from_slice(
        &(nonce.len() as u32).to_le_bytes(),
    );
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&event.public_key_digest);
    output.extend_from_slice(
        &event.previous_public_key_digest,
    );
    output.extend_from_slice(
        &event.provider_key_name_digest,
    );
    output.extend_from_slice(&event.subject_digest);
    output.extend_from_slice(&event.signature_old);
    output.extend_from_slice(&event.signature_new);
    output.extend_from_slice(&[0; 16]);
    debug_assert_eq!(output.len(), EVENT_FIXED_BYTES);
    output.extend_from_slice(key);
    output.extend_from_slice(provider);
    output.extend_from_slice(provider_key);
    output.extend_from_slice(&event.public_blob);
    output.extend_from_slice(nonce);
    Ok(output)
}

fn decode_payload(
    payload: &[u8],
) -> Result<AsymmetricKeyEvent> {
    if payload.len() < EVENT_FIXED_BYTES
        || payload[0..8] != REGISTRY_PAYLOAD_MAGIC
    {
        return Err(AsymmetricError::Invalid(
            "registry payload header mismatch".to_string(),
        ));
    }
    let kind = AsymmetricKeyEventKind::from_code(payload[8])?;
    if payload[9] != 1
        || payload[10] != 1
        || payload[11] > 1
        || payload[14..16] != [0; 2]
        || payload[312..328] != [0; 16]
    {
        return Err(AsymmetricError::Invalid(
            "registry payload algorithm/provider/reserved mismatch"
                .to_string(),
        ));
    }
    let role_mask = read_u16(payload, 12)?;
    let logical_timestamp = read_u64(payload, 16)?;
    let generation = read_u64(payload, 24)?;
    let key_len = read_u32(payload, 32)? as usize;
    let provider_len = read_u32(payload, 36)? as usize;
    let provider_key_len = read_u32(payload, 40)? as usize;
    let public_blob_len = read_u32(payload, 44)? as usize;
    let nonce_len = read_u32(payload, 48)? as usize;
    if read_u32(payload, 52)? != 0 {
        return Err(AsymmetricError::Invalid(
            "registry payload reserved value non-zero"
                .to_string(),
        ));
    }
    let public_key_digest = read_digest(payload, 56)?;
    let previous_public_key_digest =
        read_digest(payload, 88)?;
    let provider_key_name_digest =
        read_digest(payload, 120)?;
    let subject_digest = read_digest(payload, 152)?;
    let signature_old = read_signature(payload, 184)?;
    let signature_new = read_signature(payload, 248)?;
    let mut cursor = EVENT_FIXED_BYTES;
    let key_id = read_string(
        payload,
        &mut cursor,
        key_len,
        "key_id",
    )?;
    let provider_name = read_string(
        payload,
        &mut cursor,
        provider_len,
        "provider_name",
    )?;
    let provider_key_name = read_string(
        payload,
        &mut cursor,
        provider_key_len,
        "provider_key_name",
    )?;
    let public_end = cursor
        .checked_add(public_blob_len)
        .ok_or_else(|| AsymmetricError::Invalid(
            "public blob length overflow".to_string(),
        ))?;
    let public_blob = payload.get(cursor..public_end)
        .ok_or_else(|| AsymmetricError::Invalid(
            "truncated public blob".to_string(),
        ))?
        .to_vec();
    cursor = public_end;
    let nonce = read_string(
        payload,
        &mut cursor,
        nonce_len,
        "nonce",
    )?;
    if cursor != payload.len() {
        return Err(AsymmetricError::Invalid(
            "registry payload trailing bytes".to_string(),
        ));
    }
    Ok(AsymmetricKeyEvent {
        sequence: 0,
        kind,
        role_mask,
        logical_timestamp,
        generation,
        key_id,
        provider_name,
        provider_key_name,
        public_blob,
        public_key_digest,
        previous_public_key_digest,
        provider_key_name_digest,
        subject_digest,
        signature_old,
        signature_new,
        nonce,
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
            "registry payload too large".to_string(),
        ));
    }
    let mut output = Vec::new();
    output.extend_from_slice(&REGISTRY_MAGIC);
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
                context: "asymmetric key registry",
                offset,
                remaining_bytes: remaining,
            });
        }
        let header = &bytes[offset..offset + FRAME_HEADER_BYTES];
        if header[0..8] != REGISTRY_MAGIC
            || read_u16(header, 8)? != 1
            || read_u16(header, 10)? != 0
            || read_u32(header, 12)? as usize
                != FRAME_HEADER_BYTES
            || header[128..144] != [0; 16]
        {
            return Err(AsymmetricError::Invalid(
                "registry frame header mismatch".to_string(),
            ));
        }
        let sequence = read_u64(header, 16)?;
        if sequence != frames.len() as u64 + 1 {
            return Err(AsymmetricError::Invalid(
                "registry frame sequence mismatch".to_string(),
            ));
        }
        let payload_len = usize::try_from(
            read_u64(header, 24)?,
        )
        .map_err(|_| AsymmetricError::Invalid(
            "registry payload length overflow".to_string(),
        ))?;
        if payload_len > MAX_PAYLOAD_BYTES {
            return Err(AsymmetricError::Invalid(
                "registry payload exceeds maximum".to_string(),
            ));
        }
        let previous_digest = read_digest(header, 32)?;
        if previous_digest != head {
            return Err(AsymmetricError::Integrity(
                "registry previous digest mismatch".to_string(),
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
                "registry frame length overflow".to_string(),
            ))?;
        if frame_end > bytes.len() {
            return Err(AsymmetricError::Truncated {
                context: "asymmetric key registry",
                offset,
                remaining_bytes: remaining,
            });
        }
        let payload = bytes[payload_start..frame_end].to_vec();
        let actual_payload_digest = sha256(&payload);
        if actual_payload_digest != expected_payload_digest {
            return Err(AsymmetricError::Integrity(
                "registry payload digest mismatch".to_string(),
            ));
        }
        let actual_frame_digest = compute_frame_digest(
            sequence,
            previous_digest,
            expected_payload_digest,
        );
        if actual_frame_digest != expected_frame_digest {
            return Err(AsymmetricError::Integrity(
                "registry frame digest mismatch".to_string(),
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
    output.extend_from_slice(&REGISTRY_FRAME_DOMAIN);
    output.extend_from_slice(&sequence.to_le_bytes());
    output.extend_from_slice(&previous_digest);
    output.extend_from_slice(&payload_digest);
    sha256(&output)
}

fn create_empty_file(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(AsymmetricError::Invalid(format!(
            "registry already exists: {}",
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
            "registry string length overflow".to_string(),
        )
    })?;
    let value = bytes.get(*cursor..end).ok_or_else(|| {
        AsymmetricError::Invalid(format!(
            "truncated registry {name}",
        ))
    })?;
    *cursor = end;
    String::from_utf8(value.to_vec()).map_err(|_| {
        AsymmetricError::Invalid(format!(
            "registry {name} is not UTF-8",
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
