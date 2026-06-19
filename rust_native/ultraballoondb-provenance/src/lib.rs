use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ultraballoondb_storage::sha256;
use ultraballoondb_trust_asymmetric::{
    AsymmetricAuthorizationLedger, AsymmetricKeyRegistry,
};
use ultraballoondb_trust_federation::{EnterpriseFederationLedger, FederationEventKind};

pub const VERSION: &str = "V00R3P0_PROVENANCE_CORE_R01";
pub const PROVENANCE_FILE_NAME: &str = "provenance-core.ubprov";
pub const DOMAIN_PROVENANCE_RECORD: u8 = 9;

const FILE_MAGIC: [u8; 8] = *b"UBPROV1\0";
const PAYLOAD_MAGIC: [u8; 8] = *b"UBPRP01\0";
const SUBJECT_DOMAIN: [u8; 8] = *b"UBPRSUB1";
const ID_DOMAIN: [u8; 8] = *b"UBPRID01";
const FRAME_DOMAIN: [u8; 8] = *b"UBPRFR01";
const FORMAT_VERSION: u16 = 1;
const FRAME_HEADER_BYTES: usize = 164;
const MAX_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const MAX_PARENTS: usize = 1024;

#[derive(Debug)]
pub enum ProvenanceError {
    Io(std::io::Error),
    Invalid(String),
    Integrity(String),
    Trust(String),
    Truncated { context: &'static str, offset: usize },
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Invalid(message) => write!(f, "invalid provenance operation: {message}"),
            Self::Integrity(message) => write!(f, "provenance integrity error: {message}"),
            Self::Trust(message) => write!(f, "provenance trust error: {message}"),
            Self::Truncated { context, offset } => {
                write!(f, "truncated {context} at offset {offset}")
            }
        }
    }
}

impl std::error::Error for ProvenanceError {}
impl From<std::io::Error> for ProvenanceError {
    fn from(value: std::io::Error) -> Self { Self::Io(value) }
}

pub type Result<T> = std::result::Result<T, ProvenanceError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProvenanceKind {
    Source = 1,
    Imported = 2,
    Derived = 3,
}

impl ProvenanceKind {
    fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Source),
            2 => Ok(Self::Imported),
            3 => Ok(Self::Derived),
            _ => Err(ProvenanceError::Invalid(format!("unknown provenance kind {code}"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Source => "SOURCE",
            Self::Imported => "IMPORTED",
            Self::Derived => "DERIVED",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceInput {
    pub kind: ProvenanceKind,
    pub logical_timestamp: u64,
    pub namespace: String,
    pub object_id: String,
    pub object_kind: String,
    pub object_version: u64,
    pub actor_key_id: String,
    pub source_locator_digest: [u8; 32],
    pub content_digest: [u8; 32],
    pub operation_digest: [u8; 32],
    pub transformation_digest: [u8; 32],
    pub federation_policy_version: u64,
    pub federation_policy_digest: [u8; 32],
    pub federation_bundle_version: u64,
    pub federation_bundle_digest: [u8; 32],
    pub authorization_sequence: u64,
    pub parent_provenance_ids: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceEvent {
    pub sequence: u64,
    pub kind: ProvenanceKind,
    pub logical_timestamp: u64,
    pub namespace: String,
    pub object_id: String,
    pub object_kind: String,
    pub object_version: u64,
    pub actor_key_id: String,
    pub source_locator_digest: [u8; 32],
    pub content_digest: [u8; 32],
    pub operation_digest: [u8; 32],
    pub transformation_digest: [u8; 32],
    pub federation_policy_version: u64,
    pub federation_policy_digest: [u8; 32],
    pub federation_bundle_version: u64,
    pub federation_bundle_digest: [u8; 32],
    pub authorization_sequence: u64,
    pub authorization_event_id: [u8; 32],
    pub authorization_frame_digest: [u8; 32],
    pub parent_provenance_ids: Vec<[u8; 32]>,
    pub subject_digest: [u8; 32],
    pub provenance_id: [u8; 32],
    pub previous_digest: [u8; 32],
    pub frame_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceReceipt {
    pub sequence: u64,
    pub provenance_id: [u8; 32],
    pub frame_digest: [u8; 32],
    pub object_version: u64,
}

#[derive(Debug)]
pub struct ProvenanceLedger {
    path: PathBuf,
    events: Vec<ProvenanceEvent>,
    by_id: BTreeMap<[u8; 32], usize>,
    latest_object_versions: BTreeMap<(String, String), u64>,
    used_authorization_sequences: BTreeSet<u64>,
    head_digest: [u8; 32],
    last_timestamp: u64,
}

impl ProvenanceLedger {
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
        federation: &EnterpriseFederationLedger,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.is_file() {
            return Err(ProvenanceError::Invalid(format!(
                "provenance ledger missing: {}", path.display()
            )));
        }
        let bytes = fs::read(&path)?;
        let mut ledger = Self::empty(path);
        ledger.replay(&bytes, registry, authorizations, federation)?;
        Ok(ledger)
    }

    fn empty(path: PathBuf) -> Self {
        Self {
            path,
            events: Vec::new(),
            by_id: BTreeMap::new(),
            latest_object_versions: BTreeMap::new(),
            used_authorization_sequences: BTreeSet::new(),
            head_digest: [0; 32],
            last_timestamp: 0,
        }
    }

    pub fn path(&self) -> &Path { &self.path }
    pub fn events(&self) -> &[ProvenanceEvent] { &self.events }
    pub fn event_count(&self) -> usize { self.events.len() }
    pub fn head_digest(&self) -> [u8; 32] { self.head_digest }
    pub fn get(&self, provenance_id: &[u8; 32]) -> Option<&ProvenanceEvent> {
        self.by_id.get(provenance_id).and_then(|index| self.events.get(*index))
    }

    pub fn latest_object_version(&self, namespace: &str, object_id: &str) -> Option<u64> {
        self.latest_object_versions
            .get(&(namespace.to_string(), object_id.to_string()))
            .copied()
    }

    pub fn lineage(&self, provenance_id: [u8; 32]) -> Result<Vec<ProvenanceEvent>> {
        if !self.by_id.contains_key(&provenance_id) {
            return Err(ProvenanceError::Invalid("provenance id not found".to_string()));
        }
        let mut visited = BTreeSet::new();
        let mut ordered = Vec::new();
        self.collect_lineage(provenance_id, &mut visited, &mut ordered)?;
        Ok(ordered)
    }

    fn collect_lineage(
        &self,
        provenance_id: [u8; 32],
        visited: &mut BTreeSet<[u8; 32]>,
        ordered: &mut Vec<ProvenanceEvent>,
    ) -> Result<()> {
        if !visited.insert(provenance_id) { return Ok(()); }
        let event = self.get(&provenance_id).ok_or_else(|| {
            ProvenanceError::Integrity("lineage parent missing".to_string())
        })?;
        for parent in &event.parent_provenance_ids {
            self.collect_lineage(*parent, visited, ordered)?;
        }
        ordered.push(event.clone());
        Ok(())
    }

    pub fn append_authorized(
        &mut self,
        registry: &AsymmetricKeyRegistry,
        authorizations: &AsymmetricAuthorizationLedger,
        federation: &EnterpriseFederationLedger,
        input: ProvenanceInput,
    ) -> Result<ProvenanceReceipt> {
        let sequence = self.events.len() as u64 + 1;
        let previous_digest = self.head_digest;
        let event = build_event(
            sequence,
            previous_digest,
            input,
            registry,
            authorizations,
            federation,
        )?;
        self.validate_state_transition(&event)?;
        let payload = encode_payload(&event)?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(ProvenanceError::Invalid("provenance payload too large".to_string()));
        }
        let payload_digest = sha256(&payload);
        let frame_digest = compute_frame_digest(
            event.sequence,
            event.logical_timestamp,
            event.previous_digest,
            event.provenance_id,
            payload_digest,
        );
        let mut event = event;
        event.frame_digest = frame_digest;
        let frame = encode_frame(&event, payload_digest, &payload)?;
        append_fsync(&self.path, &frame)?;
        let receipt = ProvenanceReceipt {
            sequence: event.sequence,
            provenance_id: event.provenance_id,
            frame_digest: event.frame_digest,
            object_version: event.object_version,
        };
        self.apply_event(event);
        Ok(receipt)
    }

    fn validate_state_transition(&self, event: &ProvenanceEvent) -> Result<()> {
        if event.logical_timestamp <= self.last_timestamp {
            return Err(ProvenanceError::Invalid(
                "provenance timestamps must be strictly increasing".to_string(),
            ));
        }
        if self.by_id.contains_key(&event.provenance_id) {
            return Err(ProvenanceError::Invalid("duplicate provenance id".to_string()));
        }
        if self.used_authorization_sequences.contains(&event.authorization_sequence) {
            return Err(ProvenanceError::Invalid(
                "authorization sequence already used by provenance".to_string(),
            ));
        }
        let key = (event.namespace.clone(), event.object_id.clone());
        let expected_version = self.latest_object_versions.get(&key).copied().unwrap_or(0) + 1;
        if event.object_version != expected_version {
            return Err(ProvenanceError::Invalid(format!(
                "object version mismatch expected={expected_version} actual={}",
                event.object_version,
            )));
        }
        for parent in &event.parent_provenance_ids {
            if !self.by_id.contains_key(parent) {
                return Err(ProvenanceError::Invalid(
                    "parent provenance id must reference an earlier event".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn apply_event(&mut self, event: ProvenanceEvent) {
        let index = self.events.len();
        self.by_id.insert(event.provenance_id, index);
        self.latest_object_versions.insert(
            (event.namespace.clone(), event.object_id.clone()),
            event.object_version,
        );
        self.used_authorization_sequences.insert(event.authorization_sequence);
        self.last_timestamp = event.logical_timestamp;
        self.head_digest = event.frame_digest;
        self.events.push(event);
    }

    fn replay(
        &mut self,
        bytes: &[u8],
        registry: &AsymmetricKeyRegistry,
        authorizations: &AsymmetricAuthorizationLedger,
        federation: &EnterpriseFederationLedger,
    ) -> Result<()> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            if bytes.len() - offset < FRAME_HEADER_BYTES {
                return Err(ProvenanceError::Truncated { context: "provenance frame header", offset });
            }
            let header = &bytes[offset..offset + FRAME_HEADER_BYTES];
            if header[0..8] != FILE_MAGIC {
                return Err(ProvenanceError::Integrity(format!("frame magic mismatch at {offset}")));
            }
            let format_version = u16::from_le_bytes([header[8], header[9]]);
            if format_version != FORMAT_VERSION || header[11] != 0 {
                return Err(ProvenanceError::Integrity("unsupported frame header".to_string()));
            }
            let kind = ProvenanceKind::from_code(header[10])?;
            let sequence = read_u64_at(header, 12)?;
            let logical_timestamp = read_u64_at(header, 20)?;
            let payload_len = read_u32_at(header, 28)? as usize;
            if read_u32_at(header, 32)? != 0 || payload_len > MAX_PAYLOAD_BYTES {
                return Err(ProvenanceError::Integrity("invalid frame length/reserved field".to_string()));
            }
            let previous_digest = array32(&header[36..68])?;
            let payload_digest = array32(&header[68..100])?;
            let provenance_id = array32(&header[100..132])?;
            let frame_digest = array32(&header[132..164])?;
            let payload_start = offset + FRAME_HEADER_BYTES;
            let payload_end = payload_start.checked_add(payload_len).ok_or_else(|| {
                ProvenanceError::Integrity("payload length overflow".to_string())
            })?;
            if payload_end > bytes.len() {
                return Err(ProvenanceError::Truncated { context: "provenance payload", offset: payload_start });
            }
            let payload = &bytes[payload_start..payload_end];
            if sha256(payload) != payload_digest {
                return Err(ProvenanceError::Integrity("payload digest mismatch".to_string()));
            }
            let mut event = decode_payload(kind, sequence, logical_timestamp, previous_digest, provenance_id, frame_digest, payload)?;
            if event.sequence != self.events.len() as u64 + 1 || event.previous_digest != self.head_digest {
                return Err(ProvenanceError::Integrity("sequence or previous digest mismatch".to_string()));
            }
            verify_event_trust(&event, registry, authorizations, federation)?;
            let expected_subject = provenance_subject_digest(&event_to_input(&event))?;
            if event.subject_digest != expected_subject {
                return Err(ProvenanceError::Integrity("subject digest mismatch".to_string()));
            }
            let expected_id = provenance_id_digest(expected_subject, event.authorization_event_id);
            if event.provenance_id != expected_id {
                return Err(ProvenanceError::Integrity("provenance id mismatch".to_string()));
            }
            let expected_frame = compute_frame_digest(
                event.sequence,
                event.logical_timestamp,
                event.previous_digest,
                event.provenance_id,
                payload_digest,
            );
            if event.frame_digest != expected_frame {
                return Err(ProvenanceError::Integrity("frame digest mismatch".to_string()));
            }
            self.validate_state_transition(&event)?;
            event.frame_digest = expected_frame;
            self.apply_event(event);
            offset = payload_end;
        }
        Ok(())
    }
}

pub fn provenance_subject_digest(input: &ProvenanceInput) -> Result<[u8; 32]> {
    validate_input_shape(input)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&SUBJECT_DOMAIN);
    bytes.push(input.kind as u8);
    put_u64(&mut bytes, input.logical_timestamp);
    put_string(&mut bytes, &input.namespace)?;
    put_string(&mut bytes, &input.object_id)?;
    put_string(&mut bytes, &input.object_kind)?;
    put_u64(&mut bytes, input.object_version);
    put_string(&mut bytes, &input.actor_key_id)?;
    bytes.extend_from_slice(&input.source_locator_digest);
    bytes.extend_from_slice(&input.content_digest);
    bytes.extend_from_slice(&input.operation_digest);
    bytes.extend_from_slice(&input.transformation_digest);
    put_u64(&mut bytes, input.federation_policy_version);
    bytes.extend_from_slice(&input.federation_policy_digest);
    put_u64(&mut bytes, input.federation_bundle_version);
    bytes.extend_from_slice(&input.federation_bundle_digest);
    put_u32(&mut bytes, input.parent_provenance_ids.len() as u32);
    for parent in &input.parent_provenance_ids { bytes.extend_from_slice(parent); }
    Ok(sha256(&bytes))
}

fn build_event(
    sequence: u64,
    previous_digest: [u8; 32],
    input: ProvenanceInput,
    registry: &AsymmetricKeyRegistry,
    authorizations: &AsymmetricAuthorizationLedger,
    federation: &EnterpriseFederationLedger,
) -> Result<ProvenanceEvent> {
    validate_input_shape(&input)?;
    if input.authorization_sequence == 0 {
        return Err(ProvenanceError::Invalid("authorization sequence must be nonzero".to_string()));
    }
    let authorization = authorizations.events().iter()
        .find(|event| event.sequence == input.authorization_sequence)
        .ok_or_else(|| ProvenanceError::Trust(format!(
            "authorization sequence not found: {}", input.authorization_sequence
        )))?;
    let subject_digest = provenance_subject_digest(&input)?;
    if authorization.domain_code != DOMAIN_PROVENANCE_RECORD
        || authorization.subject_digest != subject_digest
        || authorization.key_id != input.actor_key_id
    {
        return Err(ProvenanceError::Trust(
            "authorization domain, subject, or actor mismatch".to_string(),
        ));
    }
    if !authorizations.verify_sequence(input.authorization_sequence, registry)
        .map_err(|error| ProvenanceError::Trust(error.to_string()))?
    {
        return Err(ProvenanceError::Trust("authorization signature verification failed".to_string()));
    }
    verify_federation_binding(&input, authorization.required_role_mask, federation)?;
    let provenance_id = provenance_id_digest(subject_digest, authorization.authorization_event_id);
    Ok(ProvenanceEvent {
        sequence,
        kind: input.kind,
        logical_timestamp: input.logical_timestamp,
        namespace: input.namespace,
        object_id: input.object_id,
        object_kind: input.object_kind,
        object_version: input.object_version,
        actor_key_id: input.actor_key_id,
        source_locator_digest: input.source_locator_digest,
        content_digest: input.content_digest,
        operation_digest: input.operation_digest,
        transformation_digest: input.transformation_digest,
        federation_policy_version: input.federation_policy_version,
        federation_policy_digest: input.federation_policy_digest,
        federation_bundle_version: input.federation_bundle_version,
        federation_bundle_digest: input.federation_bundle_digest,
        authorization_sequence: input.authorization_sequence,
        authorization_event_id: authorization.authorization_event_id,
        authorization_frame_digest: authorization.frame_digest,
        parent_provenance_ids: input.parent_provenance_ids,
        subject_digest,
        provenance_id,
        previous_digest,
        frame_digest: [0; 32],
    })
}

fn verify_event_trust(
    event: &ProvenanceEvent,
    registry: &AsymmetricKeyRegistry,
    authorizations: &AsymmetricAuthorizationLedger,
    federation: &EnterpriseFederationLedger,
) -> Result<()> {
    let authorization = authorizations.events().iter()
        .find(|candidate| candidate.sequence == event.authorization_sequence)
        .ok_or_else(|| ProvenanceError::Trust("authorization sequence missing during replay".to_string()))?;
    if authorization.domain_code != DOMAIN_PROVENANCE_RECORD
        || authorization.key_id != event.actor_key_id
        || authorization.subject_digest != event.subject_digest
        || authorization.authorization_event_id != event.authorization_event_id
        || authorization.frame_digest != event.authorization_frame_digest
    {
        return Err(ProvenanceError::Trust("authorization binding mismatch during replay".to_string()));
    }
    if !authorizations.verify_sequence(event.authorization_sequence, registry)
        .map_err(|error| ProvenanceError::Trust(error.to_string()))?
    {
        return Err(ProvenanceError::Trust("authorization replay verification failed".to_string()));
    }
    verify_federation_binding(&event_to_input(event), authorization.required_role_mask, federation)
}

fn verify_federation_binding(
    input: &ProvenanceInput,
    authorization_role_mask: u16,
    federation: &EnterpriseFederationLedger,
) -> Result<()> {
    let policy = federation.policies().get(&input.namespace).ok_or_else(|| {
        ProvenanceError::Trust("namespace federation policy missing".to_string())
    })?;
    if policy.policy_version != input.federation_policy_version
        || policy.policy_digest != input.federation_policy_digest
        || authorization_role_mask != policy.authority_role_mask
    {
        return Err(ProvenanceError::Trust("federation policy binding mismatch".to_string()));
    }
    let accepted_historically = federation.events().iter().any(|event| {
        event.kind == FederationEventKind::BundleAccept
            && event.namespace == input.namespace
            && event.policy_version == input.federation_policy_version
            && event.bundle_version == input.federation_bundle_version
            && event.policy_digest == input.federation_policy_digest
            && event.bundle_digest == input.federation_bundle_digest
    });
    if !accepted_historically {
        return Err(ProvenanceError::Trust(
            "historically accepted federation bundle binding missing".to_string(),
        ));
    }
    Ok(())
}

fn validate_input_shape(input: &ProvenanceInput) -> Result<()> {
    validate_text("namespace", &input.namespace)?;
    validate_text("object_id", &input.object_id)?;
    validate_text("object_kind", &input.object_kind)?;
    validate_text("actor_key_id", &input.actor_key_id)?;
    if input.logical_timestamp == 0
        || input.object_version == 0
        || input.content_digest == [0; 32]
        || input.operation_digest == [0; 32]
        || input.federation_policy_version == 0
        || input.federation_policy_digest == [0; 32]
        || input.federation_bundle_version == 0
        || input.federation_bundle_digest == [0; 32]
        || input.parent_provenance_ids.len() > MAX_PARENTS
    {
        return Err(ProvenanceError::Invalid("required provenance field missing".to_string()));
    }
    let mut previous: Option<[u8; 32]> = None;
    for parent in &input.parent_provenance_ids {
        if *parent == [0; 32] || previous.is_some_and(|value| value >= *parent) {
            return Err(ProvenanceError::Invalid(
                "parent provenance ids must be nonzero, unique, and strictly sorted".to_string(),
            ));
        }
        previous = Some(*parent);
    }
    match input.kind {
        ProvenanceKind::Source | ProvenanceKind::Imported => {
            if input.source_locator_digest == [0; 32]
                || input.transformation_digest != [0; 32]
                || !input.parent_provenance_ids.is_empty()
            {
                return Err(ProvenanceError::Invalid(
                    "source/imported provenance requires source digest, zero transform, and no parents".to_string(),
                ));
            }
        }
        ProvenanceKind::Derived => {
            if input.transformation_digest == [0; 32]
                || input.parent_provenance_ids.is_empty()
            {
                return Err(ProvenanceError::Invalid(
                    "derived provenance requires transformation digest and parents".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_text(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 255
        || !value.bytes().all(|byte| byte.is_ascii_graphic() && byte != b'\\')
    {
        return Err(ProvenanceError::Invalid(format!("invalid {field}")));
    }
    Ok(())
}

fn provenance_id_digest(subject_digest: [u8; 32], authorization_event_id: [u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(72);
    bytes.extend_from_slice(&ID_DOMAIN);
    bytes.extend_from_slice(&subject_digest);
    bytes.extend_from_slice(&authorization_event_id);
    sha256(&bytes)
}

fn compute_frame_digest(
    sequence: u64,
    logical_timestamp: u64,
    previous_digest: [u8; 32],
    provenance_id: [u8; 32],
    payload_digest: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(120);
    bytes.extend_from_slice(&FRAME_DOMAIN);
    put_u64(&mut bytes, sequence);
    put_u64(&mut bytes, logical_timestamp);
    bytes.extend_from_slice(&previous_digest);
    bytes.extend_from_slice(&provenance_id);
    bytes.extend_from_slice(&payload_digest);
    sha256(&bytes)
}

fn event_to_input(event: &ProvenanceEvent) -> ProvenanceInput {
    ProvenanceInput {
        kind: event.kind,
        logical_timestamp: event.logical_timestamp,
        namespace: event.namespace.clone(),
        object_id: event.object_id.clone(),
        object_kind: event.object_kind.clone(),
        object_version: event.object_version,
        actor_key_id: event.actor_key_id.clone(),
        source_locator_digest: event.source_locator_digest,
        content_digest: event.content_digest,
        operation_digest: event.operation_digest,
        transformation_digest: event.transformation_digest,
        federation_policy_version: event.federation_policy_version,
        federation_policy_digest: event.federation_policy_digest,
        federation_bundle_version: event.federation_bundle_version,
        federation_bundle_digest: event.federation_bundle_digest,
        authorization_sequence: event.authorization_sequence,
        parent_provenance_ids: event.parent_provenance_ids.clone(),
    }
}

fn encode_payload(event: &ProvenanceEvent) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&PAYLOAD_MAGIC);
    put_string(&mut bytes, &event.namespace)?;
    put_string(&mut bytes, &event.object_id)?;
    put_string(&mut bytes, &event.object_kind)?;
    put_string(&mut bytes, &event.actor_key_id)?;
    put_u64(&mut bytes, event.object_version);
    bytes.extend_from_slice(&event.source_locator_digest);
    bytes.extend_from_slice(&event.content_digest);
    bytes.extend_from_slice(&event.operation_digest);
    bytes.extend_from_slice(&event.transformation_digest);
    put_u64(&mut bytes, event.federation_policy_version);
    bytes.extend_from_slice(&event.federation_policy_digest);
    put_u64(&mut bytes, event.federation_bundle_version);
    bytes.extend_from_slice(&event.federation_bundle_digest);
    put_u64(&mut bytes, event.authorization_sequence);
    bytes.extend_from_slice(&event.authorization_event_id);
    bytes.extend_from_slice(&event.authorization_frame_digest);
    put_u32(&mut bytes, event.parent_provenance_ids.len() as u32);
    for parent in &event.parent_provenance_ids { bytes.extend_from_slice(parent); }
    bytes.extend_from_slice(&event.subject_digest);
    Ok(bytes)
}

fn decode_payload(
    kind: ProvenanceKind,
    sequence: u64,
    logical_timestamp: u64,
    previous_digest: [u8; 32],
    provenance_id: [u8; 32],
    frame_digest: [u8; 32],
    payload: &[u8],
) -> Result<ProvenanceEvent> {
    let mut cursor = Cursor::new(payload);
    if cursor.take(8)? != PAYLOAD_MAGIC {
        return Err(ProvenanceError::Integrity("payload magic mismatch".to_string()));
    }
    let namespace = cursor.string()?;
    let object_id = cursor.string()?;
    let object_kind = cursor.string()?;
    let actor_key_id = cursor.string()?;
    let object_version = cursor.u64()?;
    let source_locator_digest = cursor.digest()?;
    let content_digest = cursor.digest()?;
    let operation_digest = cursor.digest()?;
    let transformation_digest = cursor.digest()?;
    let federation_policy_version = cursor.u64()?;
    let federation_policy_digest = cursor.digest()?;
    let federation_bundle_version = cursor.u64()?;
    let federation_bundle_digest = cursor.digest()?;
    let authorization_sequence = cursor.u64()?;
    let authorization_event_id = cursor.digest()?;
    let authorization_frame_digest = cursor.digest()?;
    let parent_count = cursor.u32()? as usize;
    if parent_count > MAX_PARENTS {
        return Err(ProvenanceError::Integrity("too many provenance parents".to_string()));
    }
    let mut parent_provenance_ids = Vec::with_capacity(parent_count);
    for _ in 0..parent_count { parent_provenance_ids.push(cursor.digest()?); }
    let subject_digest = cursor.digest()?;
    if !cursor.finished() {
        return Err(ProvenanceError::Integrity("payload trailing bytes".to_string()));
    }
    Ok(ProvenanceEvent {
        sequence,
        kind,
        logical_timestamp,
        namespace,
        object_id,
        object_kind,
        object_version,
        actor_key_id,
        source_locator_digest,
        content_digest,
        operation_digest,
        transformation_digest,
        federation_policy_version,
        federation_policy_digest,
        federation_bundle_version,
        federation_bundle_digest,
        authorization_sequence,
        authorization_event_id,
        authorization_frame_digest,
        parent_provenance_ids,
        subject_digest,
        provenance_id,
        previous_digest,
        frame_digest,
    })
}

fn encode_frame(event: &ProvenanceEvent, payload_digest: [u8; 32], payload: &[u8]) -> Result<Vec<u8>> {
    let payload_len = u32::try_from(payload.len()).map_err(|_| {
        ProvenanceError::Invalid("payload length exceeds u32".to_string())
    })?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(&FILE_MAGIC);
    frame.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    frame.push(event.kind as u8);
    frame.push(0);
    put_u64(&mut frame, event.sequence);
    put_u64(&mut frame, event.logical_timestamp);
    put_u32(&mut frame, payload_len);
    put_u32(&mut frame, 0);
    frame.extend_from_slice(&event.previous_digest);
    frame.extend_from_slice(&payload_digest);
    frame.extend_from_slice(&event.provenance_id);
    frame.extend_from_slice(&event.frame_digest);
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn append_fsync(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().append(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) { bytes.extend_from_slice(&value.to_le_bytes()); }
fn put_u32(bytes: &mut Vec<u8>, value: u32) { bytes.extend_from_slice(&value.to_le_bytes()); }
fn put_string(bytes: &mut Vec<u8>, value: &str) -> Result<()> {
    validate_text("encoded text", value)?;
    let len = u16::try_from(value.len()).map_err(|_| {
        ProvenanceError::Invalid("encoded text too long".to_string())
    })?;
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn read_u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    let slice = bytes.get(offset..offset + 8).ok_or(ProvenanceError::Truncated {
        context: "u64", offset,
    })?;
    Ok(u64::from_le_bytes(slice.try_into().map_err(|_| {
        ProvenanceError::Integrity("invalid u64".to_string())
    })?))
}
fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    let slice = bytes.get(offset..offset + 4).ok_or(ProvenanceError::Truncated {
        context: "u32", offset,
    })?;
    Ok(u32::from_le_bytes(slice.try_into().map_err(|_| {
        ProvenanceError::Integrity("invalid u32".to_string())
    })?))
}
fn array32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| ProvenanceError::Integrity("invalid digest length".to_string()))
}

struct Cursor<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(len).ok_or_else(|| {
            ProvenanceError::Integrity("cursor overflow".to_string())
        })?;
        let slice = self.bytes.get(self.offset..end).ok_or(ProvenanceError::Truncated {
            context: "provenance payload field", offset: self.offset,
        })?;
        self.offset = end;
        Ok(slice)
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| {
            ProvenanceError::Integrity("invalid payload u64".to_string())
        })?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| {
            ProvenanceError::Integrity("invalid payload u32".to_string())
        })?))
    }
    fn string(&mut self) -> Result<String> {
        let len = u16::from_le_bytes(self.take(2)?.try_into().map_err(|_| {
            ProvenanceError::Integrity("invalid string length".to_string())
        })?) as usize;
        let value = std::str::from_utf8(self.take(len)?).map_err(|_| {
            ProvenanceError::Integrity("invalid UTF-8".to_string())
        })?.to_string();
        validate_text("decoded text", &value)?;
        Ok(value)
    }
    fn digest(&mut self) -> Result<[u8; 32]> { array32(self.take(32)?) }
    fn finished(&self) -> bool { self.offset == self.bytes.len() }
}
