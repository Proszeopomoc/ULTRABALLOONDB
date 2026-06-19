use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ultraballoondb_storage::sha256;
use ultraballoondb_trust_asymmetric::{
    AsymmetricAuthorization, AsymmetricAuthorizationLedger,
    AsymmetricKeyRegistry, ProviderRequirement, DOMAIN_FEDERATION_BUNDLE,
    DOMAIN_POLICY_REGISTER, DOMAIN_POLICY_REVOKE, SOFTWARE_KSP,
};

pub const VERSION: &str =
    "V00R3T6C_HARDWARE_PROVIDER_ABSTRACTION_AND_ENTERPRISE_POLICY_FEDERATION_R01";
pub const FEDERATION_FILE_NAME: &str = "enterprise-federation.ubfed";

const FILE_MAGIC: [u8; 8] = *b"UBFED01\0";
const PAYLOAD_MAGIC: [u8; 8] = *b"UBFEP01\0";
const FRAME_DOMAIN: [u8; 8] = *b"UBFEDFR1";
const POLICY_DOMAIN: [u8; 8] = *b"UBFPLCY1";
const AUTHORITY_DOMAIN: [u8; 8] = *b"UBFAUTH1";
const BUNDLE_DOMAIN: [u8; 8] = *b"UBFBNDL1";
const FRAME_HEADER_BYTES: usize = 144;
const MAX_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub enum FederationError {
    Io(std::io::Error),
    Invalid(String),
    Integrity(String),
    Truncated { context: &'static str, offset: usize },
}

impl fmt::Display for FederationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Invalid(message) => write!(f, "invalid federation operation: {message}"),
            Self::Integrity(message) => write!(f, "federation integrity error: {message}"),
            Self::Truncated { context, offset } => {
                write!(f, "truncated {context} at offset {offset}")
            }
        }
    }
}

impl std::error::Error for FederationError {}
impl From<std::io::Error> for FederationError {
    fn from(value: std::io::Error) -> Self { Self::Io(value) }
}

pub type Result<T> = std::result::Result<T, FederationError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FederationEventKind {
    NamespacePolicySet = 1,
    AuthorityEnroll = 2,
    AuthorityRevoke = 3,
    BundleAccept = 4,
}

impl FederationEventKind {
    fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::NamespacePolicySet),
            2 => Ok(Self::AuthorityEnroll),
            3 => Ok(Self::AuthorityRevoke),
            4 => Ok(Self::BundleAccept),
            _ => Err(FederationError::Invalid(format!("unknown event kind {code}"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NamespacePolicySet => "NAMESPACE_POLICY_SET",
            Self::AuthorityEnroll => "AUTHORITY_ENROLL",
            Self::AuthorityRevoke => "AUTHORITY_REVOKE",
            Self::BundleAccept => "BUNDLE_ACCEPT",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespacePolicy {
    pub namespace: String,
    pub policy_version: u64,
    pub controller_key_id: String,
    pub controller_role_mask: u16,
    pub authority_role_mask: u16,
    pub quorum_weight: u32,
    pub provider_requirement: ProviderRequirement,
    pub policy_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityState {
    pub namespace: String,
    pub key_id: String,
    pub role_mask: u16,
    pub weight: u32,
    pub active: bool,
    pub last_event_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedBundleState {
    pub namespace: String,
    pub policy_version: u64,
    pub bundle_version: u64,
    pub bundle_digest: [u8; 32],
    pub event_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationEvent {
    pub sequence: u64,
    pub kind: FederationEventKind,
    pub logical_timestamp: u64,
    pub namespace: String,
    pub key_id: String,
    pub controller_key_id: String,
    pub controller_role_mask: u16,
    pub authority_role_mask: u16,
    pub weight: u32,
    pub quorum_weight: u32,
    pub provider_requirement: ProviderRequirement,
    pub policy_version: u64,
    pub bundle_version: u64,
    pub policy_digest: [u8; 32],
    pub parent_bundle_digest: [u8; 32],
    pub bundle_digest: [u8; 32],
    pub subject_digest: [u8; 32],
    pub controller_authorization_sequence: u64,
    pub approval_sequences: Vec<u64>,
    pub previous_digest: [u8; 32],
    pub frame_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationReceipt {
    pub changed: bool,
    pub sequence: u64,
    pub event_kind: FederationEventKind,
    pub namespace: String,
    pub subject_digest: [u8; 32],
    pub frame_digest: [u8; 32],
}

#[derive(Debug)]
pub struct EnterpriseFederationLedger {
    path: PathBuf,
    events: Vec<FederationEvent>,
    policies: BTreeMap<String, NamespacePolicy>,
    authorities: BTreeMap<(String, String), AuthorityState>,
    accepted: BTreeMap<String, AcceptedBundleState>,
    used_authorization_ids: BTreeSet<[u8; 32]>,
    head_digest: [u8; 32],
    last_timestamp: u64,
}

impl EnterpriseFederationLedger {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
        OpenOptions::new().create_new(true).write(true).open(&path)?.sync_all()?;
        Ok(Self::empty(path))
    }

    pub fn open_strict(
        path: impl AsRef<Path>,
        registry: &AsymmetricKeyRegistry,
        authorizations: &AsymmetricAuthorizationLedger,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.is_file() {
            return Err(FederationError::Invalid(format!(
                "federation ledger missing: {}", path.display()
            )));
        }
        let bytes = fs::read(&path)?;
        let mut ledger = Self::empty(path);
        ledger.replay(&bytes, registry, authorizations)?;
        Ok(ledger)
    }

    fn empty(path: PathBuf) -> Self {
        Self {
            path,
            events: Vec::new(),
            policies: BTreeMap::new(),
            authorities: BTreeMap::new(),
            accepted: BTreeMap::new(),
            used_authorization_ids: BTreeSet::new(),
            head_digest: [0; 32],
            last_timestamp: 0,
        }
    }

    pub fn path(&self) -> &Path { &self.path }
    pub fn events(&self) -> &[FederationEvent] { &self.events }
    pub fn policies(&self) -> &BTreeMap<String, NamespacePolicy> { &self.policies }
    pub fn authorities(&self) -> &BTreeMap<(String, String), AuthorityState> { &self.authorities }
    pub fn accepted_bundles(&self) -> &BTreeMap<String, AcceptedBundleState> { &self.accepted }
    pub fn head_digest(&self) -> [u8; 32] { self.head_digest }
    pub fn event_count(&self) -> usize { self.events.len() }
    pub fn active_authority_count(&self) -> usize {
        self.authorities.values().filter(|state| state.active).count()
    }
    pub fn accepted_namespace_bundle_count(&self) -> usize { self.accepted.len() }

    #[allow(clippy::too_many_arguments)]
    pub fn set_namespace_policy(
        &mut self,
        registry: &AsymmetricKeyRegistry,
        authorizations: &AsymmetricAuthorizationLedger,
        namespace: &str,
        policy_version: u64,
        controller_key_id: &str,
        controller_role_mask: u16,
        authority_role_mask: u16,
        quorum_weight: u32,
        provider_requirement: ProviderRequirement,
        controller_authorization_sequence: u64,
        logical_timestamp: u64,
    ) -> Result<FederationReceipt> {
        validate_text("namespace", namespace)?;
        validate_text("controller_key_id", controller_key_id)?;
        if self.policies.contains_key(namespace)
            || policy_version != 1
            || controller_role_mask == 0
            || authority_role_mask == 0
            || quorum_weight == 0
        {
            return Err(FederationError::Invalid(
                "namespace policy must be initial version 1 with nonzero roles and quorum"
                    .to_string(),
            ));
        }
        let policy_digest = namespace_policy_digest(
            namespace,
            policy_version,
            controller_key_id,
            controller_role_mask,
            authority_role_mask,
            quorum_weight,
            provider_requirement,
        )?;
        let subject_digest = namespace_policy_subject_digest(policy_digest);
        verify_authorization_reference(
            registry,
            authorizations,
            controller_authorization_sequence,
            DOMAIN_POLICY_REGISTER,
            controller_role_mask,
            subject_digest,
            Some(controller_key_id),
        )?;
        let event = FederationEvent {
            sequence: 0,
            kind: FederationEventKind::NamespacePolicySet,
            logical_timestamp,
            namespace: namespace.to_string(),
            key_id: String::new(),
            controller_key_id: controller_key_id.to_string(),
            controller_role_mask,
            authority_role_mask,
            weight: 0,
            quorum_weight,
            provider_requirement,
            policy_version,
            bundle_version: 0,
            policy_digest,
            parent_bundle_digest: [0; 32],
            bundle_digest: [0; 32],
            subject_digest,
            controller_authorization_sequence,
            approval_sequences: Vec::new(),
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        };
        self.append(event, registry, authorizations)
    }

    pub fn enroll_authority(
        &mut self,
        registry: &AsymmetricKeyRegistry,
        authorizations: &AsymmetricAuthorizationLedger,
        namespace: &str,
        key_id: &str,
        weight: u32,
        controller_authorization_sequence: u64,
        logical_timestamp: u64,
    ) -> Result<FederationReceipt> {
        validate_text("namespace", namespace)?;
        validate_text("key_id", key_id)?;
        if weight == 0 {
            return Err(FederationError::Invalid("authority weight cannot be zero".to_string()));
        }
        let policy = self.policies.get(namespace).cloned().ok_or_else(|| {
            FederationError::Invalid(format!("namespace policy not found: {namespace}"))
        })?;
        if self.authorities.get(&(namespace.to_string(), key_id.to_string()))
            .map(|state| state.active).unwrap_or(false)
        {
            return Err(FederationError::Invalid("authority is already active".to_string()));
        }
        let key_state = registry.get(key_id).ok_or_else(|| {
            FederationError::Invalid(format!("authority key not found: {key_id}"))
        })?;
        if !key_state.has_role(policy.authority_role_mask)
            || !provider_name_satisfies(&key_state.provider_name, policy.provider_requirement)
        {
            return Err(FederationError::Invalid(
                "authority key fails role or provider requirement".to_string(),
            ));
        }
        let subject_digest = authority_subject_digest(
            FederationEventKind::AuthorityEnroll,
            namespace,
            key_id,
            weight,
            policy.policy_digest,
        )?;
        verify_authorization_reference(
            registry,
            authorizations,
            controller_authorization_sequence,
            DOMAIN_POLICY_REGISTER,
            policy.controller_role_mask,
            subject_digest,
            Some(&policy.controller_key_id),
        )?;
        let event = FederationEvent {
            sequence: 0,
            kind: FederationEventKind::AuthorityEnroll,
            logical_timestamp,
            namespace: namespace.to_string(),
            key_id: key_id.to_string(),
            controller_key_id: policy.controller_key_id,
            controller_role_mask: policy.controller_role_mask,
            authority_role_mask: policy.authority_role_mask,
            weight,
            quorum_weight: policy.quorum_weight,
            provider_requirement: policy.provider_requirement,
            policy_version: policy.policy_version,
            bundle_version: 0,
            policy_digest: policy.policy_digest,
            parent_bundle_digest: [0; 32],
            bundle_digest: [0; 32],
            subject_digest,
            controller_authorization_sequence,
            approval_sequences: Vec::new(),
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        };
        self.append(event, registry, authorizations)
    }

    pub fn revoke_authority(
        &mut self,
        registry: &AsymmetricKeyRegistry,
        authorizations: &AsymmetricAuthorizationLedger,
        namespace: &str,
        key_id: &str,
        controller_authorization_sequence: u64,
        logical_timestamp: u64,
    ) -> Result<FederationReceipt> {
        let policy = self.policies.get(namespace).cloned().ok_or_else(|| {
            FederationError::Invalid(format!("namespace policy not found: {namespace}"))
        })?;
        let current = self.authorities
            .get(&(namespace.to_string(), key_id.to_string()))
            .cloned()
            .ok_or_else(|| FederationError::Invalid("authority not found".to_string()))?;
        if !current.active {
            return Err(FederationError::Invalid("authority already revoked".to_string()));
        }
        let subject_digest = authority_subject_digest(
            FederationEventKind::AuthorityRevoke,
            namespace,
            key_id,
            current.weight,
            policy.policy_digest,
        )?;
        verify_authorization_reference(
            registry,
            authorizations,
            controller_authorization_sequence,
            DOMAIN_POLICY_REVOKE,
            policy.controller_role_mask,
            subject_digest,
            Some(&policy.controller_key_id),
        )?;
        let event = FederationEvent {
            sequence: 0,
            kind: FederationEventKind::AuthorityRevoke,
            logical_timestamp,
            namespace: namespace.to_string(),
            key_id: key_id.to_string(),
            controller_key_id: policy.controller_key_id,
            controller_role_mask: policy.controller_role_mask,
            authority_role_mask: policy.authority_role_mask,
            weight: current.weight,
            quorum_weight: policy.quorum_weight,
            provider_requirement: policy.provider_requirement,
            policy_version: policy.policy_version,
            bundle_version: 0,
            policy_digest: policy.policy_digest,
            parent_bundle_digest: [0; 32],
            bundle_digest: [0; 32],
            subject_digest,
            controller_authorization_sequence,
            approval_sequences: Vec::new(),
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        };
        self.append(event, registry, authorizations)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn accept_bundle(
        &mut self,
        registry: &AsymmetricKeyRegistry,
        authorizations: &AsymmetricAuthorizationLedger,
        namespace: &str,
        policy_version: u64,
        bundle_version: u64,
        policy_digest: [u8; 32],
        parent_bundle_digest: [u8; 32],
        bundle_digest: [u8; 32],
        approval_sequences: &[u64],
        logical_timestamp: u64,
    ) -> Result<FederationReceipt> {
        let policy = self.policies.get(namespace).cloned().ok_or_else(|| {
            FederationError::Invalid(format!("namespace policy not found: {namespace}"))
        })?;
        if policy_version != policy.policy_version
            || policy_digest != policy.policy_digest
            || bundle_digest == [0; 32]
            || approval_sequences.is_empty()
        {
            return Err(FederationError::Invalid(
                "bundle policy binding or digest is invalid".to_string(),
            ));
        }
        match self.accepted.get(namespace) {
            None if bundle_version == 1 && parent_bundle_digest == [0; 32] => {}
            Some(previous)
                if bundle_version == previous.bundle_version + 1
                    && parent_bundle_digest == previous.bundle_digest => {}
            _ => {
                return Err(FederationError::Invalid(
                    "bundle version or parent digest is not monotonic".to_string(),
                ))
            }
        }
        let subject_digest = bundle_subject_digest(
            namespace,
            policy_version,
            bundle_version,
            policy_digest,
            parent_bundle_digest,
            bundle_digest,
        )?;
        let mut previous_sequence = 0u64;
        let mut keys = BTreeSet::new();
        let mut authorization_ids = BTreeSet::new();
        let mut total_weight = 0u64;
        for sequence in approval_sequences {
            if *sequence <= previous_sequence {
                return Err(FederationError::Invalid(
                    "approval sequences must be strictly increasing".to_string(),
                ));
            }
            previous_sequence = *sequence;
            let authorization = verify_authorization_reference(
                registry,
                authorizations,
                *sequence,
                DOMAIN_FEDERATION_BUNDLE,
                policy.authority_role_mask,
                subject_digest,
                None,
            )?;
            if !keys.insert(authorization.key_id.clone()) {
                return Err(FederationError::Invalid(
                    "one authority key may approve a bundle only once".to_string(),
                ));
            }
            if self.used_authorization_ids.contains(&authorization.authorization_event_id)
                || !authorization_ids.insert(authorization.authorization_event_id)
            {
                return Err(FederationError::Invalid(
                    "authorization event reuse is forbidden".to_string(),
                ));
            }
            let authority = self.authorities
                .get(&(namespace.to_string(), authorization.key_id.clone()))
                .ok_or_else(|| FederationError::Invalid(
                    "bundle approval key is not a namespace authority".to_string()
                ))?;
            if !authority.active {
                return Err(FederationError::Invalid(
                    "bundle approval authority is revoked".to_string(),
                ));
            }
            let key_state = registry.state_at_head(
                &authorization.key_registry_head,
                &authorization.key_id,
            ).ok_or_else(|| FederationError::Integrity(
                "authorization registry head cannot resolve key".to_string()
            ))?;
            if !provider_name_satisfies(&key_state.provider_name, policy.provider_requirement) {
                return Err(FederationError::Invalid(
                    "bundle approval provider violates namespace policy".to_string(),
                ));
            }
            total_weight = total_weight.checked_add(authority.weight as u64)
                .ok_or_else(|| FederationError::Invalid("quorum weight overflow".to_string()))?;
        }
        if total_weight < policy.quorum_weight as u64 {
            return Err(FederationError::Invalid(format!(
                "federation quorum not reached: {total_weight} < {}",
                policy.quorum_weight,
            )));
        }
        let event = FederationEvent {
            sequence: 0,
            kind: FederationEventKind::BundleAccept,
            logical_timestamp,
            namespace: namespace.to_string(),
            key_id: String::new(),
            controller_key_id: policy.controller_key_id,
            controller_role_mask: policy.controller_role_mask,
            authority_role_mask: policy.authority_role_mask,
            weight: 0,
            quorum_weight: policy.quorum_weight,
            provider_requirement: policy.provider_requirement,
            policy_version,
            bundle_version,
            policy_digest,
            parent_bundle_digest,
            bundle_digest,
            subject_digest,
            controller_authorization_sequence: 0,
            approval_sequences: approval_sequences.to_vec(),
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        };
        self.append(event, registry, authorizations)
    }

    fn append(
        &mut self,
        mut event: FederationEvent,
        registry: &AsymmetricKeyRegistry,
        authorizations: &AsymmetricAuthorizationLedger,
    ) -> Result<FederationReceipt> {
        if event.logical_timestamp <= self.last_timestamp {
            return Err(FederationError::Invalid(
                "federation timestamps must be strictly increasing".to_string(),
            ));
        }
        event.sequence = self.events.len() as u64 + 1;
        event.previous_digest = self.head_digest;
        self.validate_event(&event, registry, authorizations)?;
        let payload = encode_payload(&event)?;
        let payload_digest = sha256(&payload);
        event.frame_digest = frame_digest(
            event.sequence,
            event.previous_digest,
            payload_digest,
        );
        let frame = encode_frame(
            event.sequence,
            event.previous_digest,
            payload_digest,
            event.frame_digest,
            &payload,
        )?;
        append_fsync(&self.path, &frame)?;
        self.apply_event(&event, authorizations)?;
        self.last_timestamp = event.logical_timestamp;
        self.head_digest = event.frame_digest;
        self.events.push(event.clone());
        Ok(FederationReceipt {
            changed: true,
            sequence: event.sequence,
            event_kind: event.kind,
            namespace: event.namespace,
            subject_digest: event.subject_digest,
            frame_digest: event.frame_digest,
        })
    }

    fn replay(
        &mut self,
        bytes: &[u8],
        registry: &AsymmetricKeyRegistry,
        authorizations: &AsymmetricAuthorizationLedger,
    ) -> Result<()> {
        for frame in decode_frames(bytes)? {
            let mut event = decode_payload(&frame.payload)?;
            event.sequence = frame.sequence;
            event.previous_digest = frame.previous_digest;
            event.frame_digest = frame.frame_digest;
            if event.sequence != self.events.len() as u64 + 1
                || event.previous_digest != self.head_digest
                || event.logical_timestamp <= self.last_timestamp
            {
                return Err(FederationError::Integrity(
                    "federation replay order mismatch".to_string(),
                ));
            }
            self.validate_event(&event, registry, authorizations)?;
            self.apply_event(&event, authorizations)?;
            self.last_timestamp = event.logical_timestamp;
            self.head_digest = event.frame_digest;
            self.events.push(event);
        }
        Ok(())
    }

    fn validate_event(
        &self,
        event: &FederationEvent,
        registry: &AsymmetricKeyRegistry,
        authorizations: &AsymmetricAuthorizationLedger,
    ) -> Result<()> {
        validate_text("namespace", &event.namespace)?;
        match event.kind {
            FederationEventKind::NamespacePolicySet => {
                if self.policies.contains_key(&event.namespace)
                    || event.policy_version != 1
                    || event.controller_role_mask == 0
                    || event.authority_role_mask == 0
                    || event.quorum_weight == 0
                {
                    return Err(FederationError::Invalid(
                        "invalid initial namespace policy event".to_string(),
                    ));
                }
                let expected_policy = namespace_policy_digest(
                    &event.namespace,
                    event.policy_version,
                    &event.controller_key_id,
                    event.controller_role_mask,
                    event.authority_role_mask,
                    event.quorum_weight,
                    event.provider_requirement,
                )?;
                if expected_policy != event.policy_digest
                    || namespace_policy_subject_digest(expected_policy) != event.subject_digest
                {
                    return Err(FederationError::Integrity(
                        "namespace policy digest mismatch".to_string(),
                    ));
                }
                let controller_authorization = verify_authorization_reference(
                    registry,
                    authorizations,
                    event.controller_authorization_sequence,
                    DOMAIN_POLICY_REGISTER,
                    event.controller_role_mask,
                    event.subject_digest,
                    Some(&event.controller_key_id),
                )?;
                let controller_state = registry.state_at_head(
                    &controller_authorization.key_registry_head,
                    &event.controller_key_id,
                ).ok_or_else(|| FederationError::Integrity(
                    "controller key missing at policy authorization head".to_string()
                ))?;
                if !provider_name_satisfies(
                    &controller_state.provider_name,
                    event.provider_requirement,
                ) {
                    return Err(FederationError::Invalid(
                        "controller provider violates namespace policy".to_string(),
                    ));
                }
            }
            FederationEventKind::AuthorityEnroll => {
                let policy = self.policy_for_event(event)?;
                if event.weight == 0
                    || self.authorities
                        .get(&(event.namespace.clone(), event.key_id.clone()))
                        .map(|state| state.active)
                        .unwrap_or(false)
                {
                    return Err(FederationError::Invalid(
                        "invalid authority enrollment state".to_string(),
                    ));
                }
                let expected = authority_subject_digest(
                    event.kind,
                    &event.namespace,
                    &event.key_id,
                    event.weight,
                    policy.policy_digest,
                )?;
                if expected != event.subject_digest {
                    return Err(FederationError::Integrity(
                        "authority enrollment subject mismatch".to_string(),
                    ));
                }
                let controller_authorization = verify_authorization_reference(
                    registry,
                    authorizations,
                    event.controller_authorization_sequence,
                    DOMAIN_POLICY_REGISTER,
                    policy.controller_role_mask,
                    event.subject_digest,
                    Some(&policy.controller_key_id),
                )?;
                let state = registry.state_at_head(
                    &controller_authorization.key_registry_head,
                    &event.key_id,
                ).ok_or_else(|| {
                    FederationError::Invalid("authority key not found at controller authorization head".to_string())
                })?;
                if !state.has_role(policy.authority_role_mask)
                    || !provider_name_satisfies(
                        &state.provider_name,
                        policy.provider_requirement,
                    )
                {
                    return Err(FederationError::Invalid(
                        "authority key fails namespace policy".to_string(),
                    ));
                }
            }
            FederationEventKind::AuthorityRevoke => {
                let policy = self.policy_for_event(event)?;
                let current = self.authorities
                    .get(&(event.namespace.clone(), event.key_id.clone()))
                    .ok_or_else(|| FederationError::Invalid(
                        "authority to revoke not found".to_string()
                    ))?;
                if !current.active || current.weight != event.weight {
                    return Err(FederationError::Invalid(
                        "authority revoke state mismatch".to_string(),
                    ));
                }
                let expected = authority_subject_digest(
                    event.kind,
                    &event.namespace,
                    &event.key_id,
                    event.weight,
                    policy.policy_digest,
                )?;
                if expected != event.subject_digest {
                    return Err(FederationError::Integrity(
                        "authority revoke subject mismatch".to_string(),
                    ));
                }
                verify_authorization_reference(
                    registry,
                    authorizations,
                    event.controller_authorization_sequence,
                    DOMAIN_POLICY_REVOKE,
                    policy.controller_role_mask,
                    event.subject_digest,
                    Some(&policy.controller_key_id),
                )?;
            }
            FederationEventKind::BundleAccept => {
                let policy = self.policy_for_event(event)?;
                if event.policy_version != policy.policy_version
                    || event.policy_digest != policy.policy_digest
                    || event.bundle_digest == [0; 32]
                {
                    return Err(FederationError::Invalid(
                        "bundle policy binding mismatch".to_string(),
                    ));
                }
                match self.accepted.get(&event.namespace) {
                    None if event.bundle_version == 1
                        && event.parent_bundle_digest == [0; 32] => {}
                    Some(previous)
                        if event.bundle_version == previous.bundle_version + 1
                            && event.parent_bundle_digest == previous.bundle_digest => {}
                    _ => return Err(FederationError::Invalid(
                        "bundle chain mismatch".to_string(),
                    )),
                }
                let expected = bundle_subject_digest(
                    &event.namespace,
                    event.policy_version,
                    event.bundle_version,
                    event.policy_digest,
                    event.parent_bundle_digest,
                    event.bundle_digest,
                )?;
                if expected != event.subject_digest {
                    return Err(FederationError::Integrity(
                        "bundle subject mismatch".to_string(),
                    ));
                }
                let mut prior = 0u64;
                let mut keys = BTreeSet::new();
                let mut ids = BTreeSet::new();
                let mut total = 0u64;
                for sequence in &event.approval_sequences {
                    if *sequence <= prior {
                        return Err(FederationError::Invalid(
                            "bundle approvals are not strictly ordered".to_string(),
                        ));
                    }
                    prior = *sequence;
                    let authorization = verify_authorization_reference(
                        registry,
                        authorizations,
                        *sequence,
                        DOMAIN_FEDERATION_BUNDLE,
                        policy.authority_role_mask,
                        event.subject_digest,
                        None,
                    )?;
                    if !keys.insert(authorization.key_id.clone())
                        || self.used_authorization_ids
                            .contains(&authorization.authorization_event_id)
                        || !ids.insert(authorization.authorization_event_id)
                    {
                        return Err(FederationError::Invalid(
                            "duplicate key or reused authorization".to_string(),
                        ));
                    }
                    let authority = self.authorities
                        .get(&(event.namespace.clone(), authorization.key_id.clone()))
                        .ok_or_else(|| FederationError::Invalid(
                            "approval authority not enrolled".to_string()
                        ))?;
                    if !authority.active {
                        return Err(FederationError::Invalid(
                            "approval authority is revoked".to_string(),
                        ));
                    }
                    let historical = registry.state_at_head(
                        &authorization.key_registry_head,
                        &authorization.key_id,
                    ).ok_or_else(|| FederationError::Integrity(
                        "approval historical key missing".to_string()
                    ))?;
                    if !provider_name_satisfies(
                        &historical.provider_name,
                        policy.provider_requirement,
                    ) {
                        return Err(FederationError::Invalid(
                            "approval provider violates policy".to_string(),
                        ));
                    }
                    total = total.checked_add(authority.weight as u64)
                        .ok_or_else(|| FederationError::Invalid(
                            "quorum weight overflow".to_string()
                        ))?;
                }
                if total < policy.quorum_weight as u64 {
                    return Err(FederationError::Invalid(
                        "bundle quorum not reached".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn policy_for_event(&self, event: &FederationEvent) -> Result<&NamespacePolicy> {
        let policy = self.policies.get(&event.namespace).ok_or_else(|| {
            FederationError::Invalid("namespace policy not found".to_string())
        })?;
        if policy.policy_version != event.policy_version
            || policy.policy_digest != event.policy_digest
            || policy.controller_key_id != event.controller_key_id
            || policy.controller_role_mask != event.controller_role_mask
            || policy.authority_role_mask != event.authority_role_mask
            || policy.quorum_weight != event.quorum_weight
            || policy.provider_requirement != event.provider_requirement
        {
            return Err(FederationError::Integrity(
                "event policy snapshot mismatch".to_string(),
            ));
        }
        Ok(policy)
    }

    fn apply_event(
        &mut self,
        event: &FederationEvent,
        authorizations: &AsymmetricAuthorizationLedger,
    ) -> Result<()> {
        match event.kind {
            FederationEventKind::NamespacePolicySet => {
                self.policies.insert(
                    event.namespace.clone(),
                    NamespacePolicy {
                        namespace: event.namespace.clone(),
                        policy_version: event.policy_version,
                        controller_key_id: event.controller_key_id.clone(),
                        controller_role_mask: event.controller_role_mask,
                        authority_role_mask: event.authority_role_mask,
                        quorum_weight: event.quorum_weight,
                        provider_requirement: event.provider_requirement,
                        policy_digest: event.policy_digest,
                    },
                );
            }
            FederationEventKind::AuthorityEnroll => {
                self.authorities.insert(
                    (event.namespace.clone(), event.key_id.clone()),
                    AuthorityState {
                        namespace: event.namespace.clone(),
                        key_id: event.key_id.clone(),
                        role_mask: event.authority_role_mask,
                        weight: event.weight,
                        active: true,
                        last_event_sequence: event.sequence,
                    },
                );
            }
            FederationEventKind::AuthorityRevoke => {
                let state = self.authorities
                    .get_mut(&(event.namespace.clone(), event.key_id.clone()))
                    .ok_or_else(|| FederationError::Integrity(
                        "authority missing during apply".to_string()
                    ))?;
                state.active = false;
                state.last_event_sequence = event.sequence;
            }
            FederationEventKind::BundleAccept => {
                for sequence in &event.approval_sequences {
                    let authorization = authorization_by_sequence(authorizations, *sequence)?;
                    self.used_authorization_ids.insert(authorization.authorization_event_id);
                }
                self.accepted.insert(
                    event.namespace.clone(),
                    AcceptedBundleState {
                        namespace: event.namespace.clone(),
                        policy_version: event.policy_version,
                        bundle_version: event.bundle_version,
                        bundle_digest: event.bundle_digest,
                        event_sequence: event.sequence,
                    },
                );
            }
        }
        Ok(())
    }
}

fn validate_text(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 1024 || value.chars().any(|c| c.is_control()) {
        return Err(FederationError::Invalid(format!(
            "{name} must contain 1..1024 non-control UTF-8 bytes"
        )));
    }
    Ok(())
}

fn requirement_code(requirement: ProviderRequirement) -> u8 {
    match requirement {
        ProviderRequirement::SoftwareAllowed => 1,
        ProviderRequirement::HardwareRequired => 2,
        ProviderRequirement::TpmRequired => 3,
    }
}

fn requirement_from_code(code: u8) -> Result<ProviderRequirement> {
    match code {
        1 => Ok(ProviderRequirement::SoftwareAllowed),
        2 => Ok(ProviderRequirement::HardwareRequired),
        3 => Ok(ProviderRequirement::TpmRequired),
        _ => Err(FederationError::Invalid(format!(
            "unknown provider requirement {code}"
        ))),
    }
}

fn provider_name_satisfies(name: &str, requirement: ProviderRequirement) -> bool {
    match requirement {
        ProviderRequirement::SoftwareAllowed => !name.is_empty(),
        ProviderRequirement::HardwareRequired => {
            name == "Microsoft Platform Crypto Provider"
                || name == "Microsoft Smart Card Key Storage Provider"
        }
        ProviderRequirement::TpmRequired => name == "Microsoft Platform Crypto Provider",
    }
}

pub fn namespace_policy_digest(
    namespace: &str,
    policy_version: u64,
    controller_key_id: &str,
    controller_role_mask: u16,
    authority_role_mask: u16,
    quorum_weight: u32,
    provider_requirement: ProviderRequirement,
) -> Result<[u8; 32]> {
    validate_text("namespace", namespace)?;
    validate_text("controller_key_id", controller_key_id)?;
    if policy_version == 0
        || controller_role_mask == 0
        || authority_role_mask == 0
        || quorum_weight == 0
    {
        return Err(FederationError::Invalid("invalid namespace policy fields".to_string()));
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&POLICY_DOMAIN);
    bytes.extend_from_slice(&policy_version.to_le_bytes());
    bytes.extend_from_slice(&controller_role_mask.to_le_bytes());
    bytes.extend_from_slice(&authority_role_mask.to_le_bytes());
    bytes.extend_from_slice(&quorum_weight.to_le_bytes());
    bytes.push(requirement_code(provider_requirement));
    bytes.extend_from_slice(&(namespace.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(controller_key_id.len() as u32).to_le_bytes());
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.extend_from_slice(controller_key_id.as_bytes());
    Ok(sha256(&bytes))
}

pub fn namespace_policy_subject_digest(policy_digest: [u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(40);
    bytes.extend_from_slice(&POLICY_DOMAIN);
    bytes.extend_from_slice(&policy_digest);
    sha256(&bytes)
}

pub fn authority_subject_digest(
    kind: FederationEventKind,
    namespace: &str,
    key_id: &str,
    weight: u32,
    policy_digest: [u8; 32],
) -> Result<[u8; 32]> {
    if !matches!(kind, FederationEventKind::AuthorityEnroll | FederationEventKind::AuthorityRevoke)
        || weight == 0
        || policy_digest == [0; 32]
    {
        return Err(FederationError::Invalid("invalid authority subject fields".to_string()));
    }
    validate_text("namespace", namespace)?;
    validate_text("key_id", key_id)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&AUTHORITY_DOMAIN);
    bytes.push(kind as u8);
    bytes.extend_from_slice(&weight.to_le_bytes());
    bytes.extend_from_slice(&policy_digest);
    bytes.extend_from_slice(&(namespace.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(key_id.len() as u32).to_le_bytes());
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.extend_from_slice(key_id.as_bytes());
    Ok(sha256(&bytes))
}

pub fn bundle_subject_digest(
    namespace: &str,
    policy_version: u64,
    bundle_version: u64,
    policy_digest: [u8; 32],
    parent_bundle_digest: [u8; 32],
    bundle_digest: [u8; 32],
) -> Result<[u8; 32]> {
    validate_text("namespace", namespace)?;
    if policy_version == 0 || bundle_version == 0
        || policy_digest == [0; 32] || bundle_digest == [0; 32]
    {
        return Err(FederationError::Invalid("invalid bundle subject fields".to_string()));
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&BUNDLE_DOMAIN);
    bytes.extend_from_slice(&policy_version.to_le_bytes());
    bytes.extend_from_slice(&bundle_version.to_le_bytes());
    bytes.extend_from_slice(&policy_digest);
    bytes.extend_from_slice(&parent_bundle_digest);
    bytes.extend_from_slice(&bundle_digest);
    bytes.extend_from_slice(&(namespace.len() as u32).to_le_bytes());
    bytes.extend_from_slice(namespace.as_bytes());
    Ok(sha256(&bytes))
}

fn authorization_by_sequence(
    authorizations: &AsymmetricAuthorizationLedger,
    sequence: u64,
) -> Result<&AsymmetricAuthorization> {
    authorizations.events().iter().find(|event| event.sequence == sequence)
        .ok_or_else(|| FederationError::Invalid(format!(
            "authorization sequence not found: {sequence}"
        )))
}

fn verify_authorization_reference<'a>(
    registry: &AsymmetricKeyRegistry,
    authorizations: &'a AsymmetricAuthorizationLedger,
    sequence: u64,
    domain_code: u8,
    required_role_mask: u16,
    subject_digest: [u8; 32],
    expected_key_id: Option<&str>,
) -> Result<&'a AsymmetricAuthorization> {
    let event = authorization_by_sequence(authorizations, sequence)?;
    if event.domain_code != domain_code
        || event.required_role_mask != required_role_mask
        || event.subject_digest != subject_digest
        || expected_key_id.map(|key| key != event.key_id).unwrap_or(false)
    {
        return Err(FederationError::Invalid(
            "authorization reference fields do not match federation event".to_string(),
        ));
    }
    let valid = authorizations.verify_sequence(sequence, registry)
        .map_err(|error| FederationError::Integrity(error.to_string()))?;
    if !valid {
        return Err(FederationError::Integrity(
            "authorization reference signature is invalid".to_string(),
        ));
    }
    let state = registry.state_at_head(&event.key_registry_head, &event.key_id)
        .ok_or_else(|| FederationError::Integrity(
            "authorization registry head cannot resolve signer".to_string()
        ))?;
    if !state.has_role(required_role_mask)
        || state.public_key_digest != event.public_key_digest
    {
        return Err(FederationError::Integrity(
            "authorization signer state mismatch".to_string(),
        ));
    }
    Ok(event)
}

fn encode_payload(event: &FederationEvent) -> Result<Vec<u8>> {
    let namespace = event.namespace.as_bytes();
    let key_id = event.key_id.as_bytes();
    let controller = event.controller_key_id.as_bytes();
    for (name, len) in [
        ("namespace", namespace.len()),
        ("key_id", key_id.len()),
        ("controller_key_id", controller.len()),
    ] {
        if len > 1024 {
            return Err(FederationError::Invalid(format!("{name} too long")));
        }
    }
    let mut output = Vec::new();
    output.extend_from_slice(&PAYLOAD_MAGIC);
    output.push(event.kind as u8);
    output.push(requirement_code(event.provider_requirement));
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&event.controller_role_mask.to_le_bytes());
    output.extend_from_slice(&event.authority_role_mask.to_le_bytes());
    output.extend_from_slice(&event.weight.to_le_bytes());
    output.extend_from_slice(&event.quorum_weight.to_le_bytes());
    output.extend_from_slice(&event.logical_timestamp.to_le_bytes());
    output.extend_from_slice(&event.policy_version.to_le_bytes());
    output.extend_from_slice(&event.bundle_version.to_le_bytes());
    output.extend_from_slice(&event.controller_authorization_sequence.to_le_bytes());
    output.extend_from_slice(&(namespace.len() as u32).to_le_bytes());
    output.extend_from_slice(&(key_id.len() as u32).to_le_bytes());
    output.extend_from_slice(&(controller.len() as u32).to_le_bytes());
    output.extend_from_slice(&(event.approval_sequences.len() as u32).to_le_bytes());
    output.extend_from_slice(&event.policy_digest);
    output.extend_from_slice(&event.parent_bundle_digest);
    output.extend_from_slice(&event.bundle_digest);
    output.extend_from_slice(&event.subject_digest);
    output.extend_from_slice(namespace);
    output.extend_from_slice(key_id);
    output.extend_from_slice(controller);
    for sequence in &event.approval_sequences {
        output.extend_from_slice(&sequence.to_le_bytes());
    }
    if output.len() > MAX_PAYLOAD_BYTES {
        return Err(FederationError::Invalid("federation payload too large".to_string()));
    }
    Ok(output)
}

fn decode_payload(bytes: &[u8]) -> Result<FederationEvent> {
    let mut cursor = Cursor::new(bytes, "federation payload");
    if cursor.take(8)? != PAYLOAD_MAGIC {
        return Err(FederationError::Integrity("payload magic mismatch".to_string()));
    }
    let kind = FederationEventKind::from_code(cursor.u8()?)?;
    let provider_requirement = requirement_from_code(cursor.u8()?)?;
    let _reserved = cursor.u16()?;
    let controller_role_mask = cursor.u16()?;
    let authority_role_mask = cursor.u16()?;
    let weight = cursor.u32()?;
    let quorum_weight = cursor.u32()?;
    let logical_timestamp = cursor.u64()?;
    let policy_version = cursor.u64()?;
    let bundle_version = cursor.u64()?;
    let controller_authorization_sequence = cursor.u64()?;
    let namespace_len = cursor.u32()? as usize;
    let key_id_len = cursor.u32()? as usize;
    let controller_len = cursor.u32()? as usize;
    let approval_count = cursor.u32()? as usize;
    if namespace_len > 1024 || key_id_len > 1024 || controller_len > 1024
        || approval_count > 1_000_000
    {
        return Err(FederationError::Invalid("payload length limit exceeded".to_string()));
    }
    let policy_digest = cursor.digest()?;
    let parent_bundle_digest = cursor.digest()?;
    let bundle_digest = cursor.digest()?;
    let subject_digest = cursor.digest()?;
    let namespace = cursor.string(namespace_len)?;
    let key_id = cursor.string(key_id_len)?;
    let controller_key_id = cursor.string(controller_len)?;
    let mut approval_sequences = Vec::with_capacity(approval_count);
    for _ in 0..approval_count { approval_sequences.push(cursor.u64()?); }
    if !cursor.done() {
        return Err(FederationError::Integrity("payload trailing bytes".to_string()));
    }
    Ok(FederationEvent {
        sequence: 0,
        kind,
        logical_timestamp,
        namespace,
        key_id,
        controller_key_id,
        controller_role_mask,
        authority_role_mask,
        weight,
        quorum_weight,
        provider_requirement,
        policy_version,
        bundle_version,
        policy_digest,
        parent_bundle_digest,
        bundle_digest,
        subject_digest,
        controller_authorization_sequence,
        approval_sequences,
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

fn frame_digest(
    sequence: u64,
    previous_digest: [u8; 32],
    payload_digest: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(80);
    bytes.extend_from_slice(&FRAME_DOMAIN);
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(&previous_digest);
    bytes.extend_from_slice(&payload_digest);
    sha256(&bytes)
}

fn encode_frame(
    sequence: u64,
    previous_digest: [u8; 32],
    payload_digest: [u8; 32],
    digest: [u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(FederationError::Invalid("frame payload too large".to_string()));
    }
    let mut output = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    output.extend_from_slice(&FILE_MAGIC);
    output.extend_from_slice(&1u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&(FRAME_HEADER_BYTES as u32).to_le_bytes());
    output.extend_from_slice(&sequence.to_le_bytes());
    output.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    output.extend_from_slice(&previous_digest);
    output.extend_from_slice(&payload_digest);
    output.extend_from_slice(&digest);
    output.extend_from_slice(&[0u8; 16]);
    debug_assert_eq!(output.len(), FRAME_HEADER_BYTES);
    output.extend_from_slice(payload);
    Ok(output)
}

fn decode_frames(bytes: &[u8]) -> Result<Vec<Frame>> {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    let mut expected_sequence = 1u64;
    let mut expected_previous = [0u8; 32];
    while offset < bytes.len() {
        if bytes.len() - offset < FRAME_HEADER_BYTES {
            return Err(FederationError::Truncated { context: "frame header", offset });
        }
        let header = &bytes[offset..offset + FRAME_HEADER_BYTES];
        if header[0..8] != FILE_MAGIC
            || u16::from_le_bytes(header[8..10].try_into().unwrap()) != 1
            || u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize
                != FRAME_HEADER_BYTES
        {
            return Err(FederationError::Integrity("frame header mismatch".to_string()));
        }
        let sequence = u64::from_le_bytes(header[16..24].try_into().unwrap());
        let payload_len = u64::from_le_bytes(header[24..32].try_into().unwrap()) as usize;
        if sequence != expected_sequence || payload_len > MAX_PAYLOAD_BYTES {
            return Err(FederationError::Integrity("frame sequence or size mismatch".to_string()));
        }
        let previous_digest: [u8; 32] = header[32..64].try_into().unwrap();
        let payload_digest: [u8; 32] = header[64..96].try_into().unwrap();
        let stored_frame_digest: [u8; 32] = header[96..128].try_into().unwrap();
        if previous_digest != expected_previous
            || stored_frame_digest != frame_digest(sequence, previous_digest, payload_digest)
        {
            return Err(FederationError::Integrity("frame chain mismatch".to_string()));
        }
        let payload_start = offset + FRAME_HEADER_BYTES;
        let payload_end = payload_start.checked_add(payload_len)
            .ok_or_else(|| FederationError::Invalid("payload offset overflow".to_string()))?;
        if payload_end > bytes.len() {
            return Err(FederationError::Truncated { context: "frame payload", offset: payload_start });
        }
        let payload = bytes[payload_start..payload_end].to_vec();
        if sha256(&payload) != payload_digest {
            return Err(FederationError::Integrity("payload digest mismatch".to_string()));
        }
        frames.push(Frame {
            sequence,
            previous_digest,
            frame_digest: stored_frame_digest,
            payload,
        });
        expected_sequence += 1;
        expected_previous = stored_frame_digest;
        offset = payload_end;
    }
    Ok(frames)
}

fn append_fsync(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().append(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    context: &'static str,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], context: &'static str) -> Self {
        Self { bytes, offset: 0, context }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(count)
            .ok_or_else(|| FederationError::Invalid("cursor overflow".to_string()))?;
        if end > self.bytes.len() {
            return Err(FederationError::Truncated { context: self.context, offset: self.offset });
        }
        let output = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(output)
    }
    fn u8(&mut self) -> Result<u8> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16> { Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32> { Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64> { Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap())) }
    fn digest(&mut self) -> Result<[u8; 32]> { Ok(self.take(32)?.try_into().unwrap()) }
    fn string(&mut self, length: usize) -> Result<String> {
        String::from_utf8(self.take(length)?.to_vec())
            .map_err(|_| FederationError::Invalid("invalid UTF-8 string".to_string()))
    }
    fn done(&self) -> bool { self.offset == self.bytes.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_and_bundle_digests_are_domain_separated() {
        let policy = namespace_policy_digest(
            "enterprise/core",
            1,
            "controller",
            1,
            2,
            2,
            ProviderRequirement::SoftwareAllowed,
        ).unwrap();
        let subject = namespace_policy_subject_digest(policy);
        let bundle = bundle_subject_digest(
            "enterprise/core",
            1,
            1,
            policy,
            [0; 32],
            sha256(b"bundle"),
        ).unwrap();
        assert_ne!(policy, subject);
        assert_ne!(subject, bundle);
    }

    #[test]
    fn event_payload_round_trip() {
        let event = FederationEvent {
            sequence: 0,
            kind: FederationEventKind::BundleAccept,
            logical_timestamp: 7,
            namespace: "enterprise/core".to_string(),
            key_id: String::new(),
            controller_key_id: "controller".to_string(),
            controller_role_mask: 1,
            authority_role_mask: 2,
            weight: 0,
            quorum_weight: 2,
            provider_requirement: ProviderRequirement::SoftwareAllowed,
            policy_version: 1,
            bundle_version: 2,
            policy_digest: sha256(b"policy"),
            parent_bundle_digest: sha256(b"parent"),
            bundle_digest: sha256(b"bundle"),
            subject_digest: sha256(b"subject"),
            controller_authorization_sequence: 0,
            approval_sequences: vec![7, 9],
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        };
        let decoded = decode_payload(&encode_payload(&event).unwrap()).unwrap();
        assert_eq!(event, decoded);
    }

    #[test]
    fn software_provider_does_not_satisfy_hardware_policy_name_check() {
        assert!(provider_name_satisfies(
            SOFTWARE_KSP,
            ProviderRequirement::SoftwareAllowed,
        ));
        assert!(!provider_name_satisfies(
            SOFTWARE_KSP,
            ProviderRequirement::HardwareRequired,
        ));
        assert!(!provider_name_satisfies(
            SOFTWARE_KSP,
            ProviderRequirement::TpmRequired,
        ));
    }
}
