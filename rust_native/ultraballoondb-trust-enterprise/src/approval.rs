use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ultraballoondb_storage::sha256;
use ultraballoondb_trust_auth::{
    key_fingerprint, KeyRegistry, DOMAIN_KEY_ROTATE,
    DOMAIN_POLICY_REGISTER, DOMAIN_POLICY_REVOKE,
    DOMAIN_TRUST_COMMIT, ROLE_KEY_ADMIN, ROLE_POLICY_ADMIN,
    ROLE_TRUST_OPERATOR,
};

use crate::crypto::{
    enterprise_signature_message, request_id as compute_request_id,
    sign_enterprise_event, validate_identifier,
};
use crate::profile::EnterpriseProfile;
use crate::{EnterpriseError, Result};

const APPROVAL_MAGIC: [u8; 8] = *b"UBAPR01\0";
const APPROVAL_PAYLOAD_MAGIC: [u8; 8] = *b"UBAPP01\0";
const APPROVAL_FRAME_DOMAIN: [u8; 8] = *b"UBAPRFR1";
const FRAME_HEADER_BYTES: usize = 144;
const APPROVAL_FIXED_BYTES: usize = 320;
const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ApprovalEventKind {
    Request = 1,
    Approve = 2,
    Finalize = 3,
}

impl ApprovalEventKind {
    fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Approve),
            3 => Ok(Self::Finalize),
            _ => Err(EnterpriseError::Invalid(format!(
                "unknown approval event kind {value}",
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "REQUEST",
            Self::Approve => "APPROVE",
            Self::Finalize => "FINALIZE",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalEvent {
    pub sequence: u64,
    pub kind: ApprovalEventKind,
    pub domain_code: u8,
    pub threshold: u16,
    pub approver_role_mask: u16,
    pub requester_excluded: bool,
    pub distinct_approvers: bool,
    pub one_time_finalization: bool,
    pub logical_timestamp: u64,
    pub created_at: u64,
    pub expires_at: u64,
    pub request_id: [u8; 32],
    pub profile_digest: [u8; 32],
    pub subject_digest: [u8; 32],
    pub requester_key_id: String,
    pub requester_fingerprint: [u8; 32],
    pub actor_key_id: String,
    pub actor_fingerprint: [u8; 32],
    pub key_registry_head: [u8; 32],
    pub operation_reference: [u8; 32],
    pub nonce: String,
    pub signature: [u8; 32],
    pub previous_digest: [u8; 32],
    pub frame_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequestState {
    pub request: ApprovalEvent,
    pub approvals: BTreeMap<String, ApprovalEvent>,
    pub finalization: Option<ApprovalEvent>,
}

impl ApprovalRequestState {
    pub fn approval_count(&self) -> usize {
        self.approvals.len()
    }

    pub fn status_at(&self, logical_timestamp: u64) -> &'static str {
        if self.finalization.is_some() {
            "FINALIZED"
        } else if logical_timestamp > self.request.expires_at {
            "EXPIRED"
        } else if self.approval_count()
            >= self.request.threshold as usize
        {
            "READY"
        } else {
            "PENDING"
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequestReceipt {
    pub changed: bool,
    pub request_id: [u8; 32],
    pub sequence: u64,
    pub expires_at: u64,
    pub threshold: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalSignatureReceipt {
    pub changed: bool,
    pub request_id: [u8; 32],
    pub sequence: u64,
    pub approval_count: usize,
    pub threshold: u16,
    pub ready: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalFinalizationReceipt {
    pub changed: bool,
    pub request_id: [u8; 32],
    pub sequence: u64,
    pub operation_reference: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalValidation {
    pub request_id: [u8; 32],
    pub domain_code: u8,
    pub subject_digest: [u8; 32],
    pub requester_key_id: String,
    pub approval_count: usize,
    pub threshold: u16,
    pub expires_at: u64,
}

#[derive(Debug)]
pub struct ApprovalLedger {
    path: PathBuf,
    events: Vec<ApprovalEvent>,
    states: BTreeMap<[u8; 32], ApprovalRequestState>,
    used_nonces: BTreeSet<(String, String)>,
    head_digest: [u8; 32],
    last_timestamp: u64,
}

impl ApprovalLedger {
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
            return Err(EnterpriseError::Invalid(format!(
                "approval ledger missing: {}",
                path.display(),
            )));
        }
        let bytes = fs::read(&path)?;
        let mut ledger = Self {
            path,
            events: Vec::new(),
            states: BTreeMap::new(),
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

    pub fn events(&self) -> &[ApprovalEvent] {
        &self.events
    }

    pub fn states(
        &self,
    ) -> &BTreeMap<[u8; 32], ApprovalRequestState> {
        &self.states
    }

    pub fn get(
        &self,
        request_id: &[u8; 32],
    ) -> Option<&ApprovalRequestState> {
        self.states.get(request_id)
    }

    pub fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn request_count(&self) -> usize {
        self.states.len()
    }

    pub fn approval_count(&self) -> usize {
        self.events.iter().filter(|event| {
            event.kind == ApprovalEventKind::Approve
        }).count()
    }

    pub fn finalization_count(&self) -> usize {
        self.events.iter().filter(|event| {
            event.kind == ApprovalEventKind::Finalize
        }).count()
    }

    pub fn expired_count_at(
        &self,
        logical_timestamp: u64,
    ) -> usize {
        self.states.values().filter(|state| {
            state.finalization.is_none()
                && logical_timestamp > state.request.expires_at
        }).count()
    }

    pub fn request(
        &mut self,
        profile: &EnterpriseProfile,
        registry: &KeyRegistry,
        domain_code: u8,
        subject_digest: [u8; 32],
        requester_key_id: &str,
        requester_secret: &[u8],
        created_at: u64,
        expires_at: u64,
        nonce: &str,
    ) -> Result<ApprovalRequestReceipt> {
        profile.validate_static_contract()?;
        validate_identifier("requester_key_id", requester_key_id)?;
        validate_identifier("nonce", nonce)?;
        if !profile.covers_domain(domain_code) {
            return Err(EnterpriseError::Invalid(format!(
                "domain {domain_code} is not protected by enterprise profile",
            )));
        }
        if subject_digest == [0; 32]
            || created_at == 0
            || expires_at <= created_at
            || expires_at - created_at
                > profile.max_logical_ttl
            || created_at <= self.last_timestamp
            || created_at < profile.activated_at
        {
            return Err(EnterpriseError::Invalid(
                "invalid enterprise approval request time/digest"
                    .to_string(),
            ));
        }
        let role = requester_role_for_domain(domain_code)?;
        let requester = registry.get(requester_key_id).ok_or_else(|| {
            EnterpriseError::Invalid(format!(
                "approval requester is unknown: {requester_key_id}",
            ))
        })?;
        if !requester.has_role(role) {
            return Err(EnterpriseError::Invalid(format!(
                "approval requester lacks required role {role}",
            )));
        }
        let requester_fingerprint = key_fingerprint(
            requester_secret,
        )
        .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
        if requester_fingerprint != requester.fingerprint {
            return Err(EnterpriseError::Invalid(
                "approval requester secret mismatch".to_string(),
            ));
        }
        let request_id = compute_request_id(
            profile.profile_digest,
            domain_code,
            subject_digest,
            requester_fingerprint,
            created_at,
            expires_at,
            registry.head_digest(),
            requester_key_id,
            nonce,
        )?;
        if let Some(existing) = self.states.get(&request_id) {
            let request = &existing.request;
            if request.domain_code == domain_code
                && request.subject_digest == subject_digest
                && request.requester_key_id == requester_key_id
                && request.created_at == created_at
                && request.expires_at == expires_at
            {
                return Ok(ApprovalRequestReceipt {
                    changed: false,
                    request_id,
                    sequence: request.sequence,
                    expires_at,
                    threshold: request.threshold,
                });
            }
            return Err(EnterpriseError::Invalid(
                "approval request ID collision".to_string(),
            ));
        }

        let message = enterprise_signature_message(
            ApprovalEventKind::Request as u8,
            request_id,
            profile.profile_digest,
            subject_digest,
            [0; 32],
            created_at,
            expires_at,
            requester_fingerprint,
            registry.head_digest(),
            requester_key_id,
            requester_key_id,
            nonce,
        )?;
        let (actor_fingerprint, signature) =
            sign_enterprise_event(requester_secret, &message)?;
        let event = ApprovalEvent {
            sequence: 0,
            kind: ApprovalEventKind::Request,
            domain_code,
            threshold: profile.approval_threshold,
            approver_role_mask: profile.approver_role_mask,
            requester_excluded: profile.requester_excluded,
            distinct_approvers: profile.distinct_approvers,
            one_time_finalization: profile.one_time_finalization,
            logical_timestamp: created_at,
            created_at,
            expires_at,
            request_id,
            profile_digest: profile.profile_digest,
            subject_digest,
            requester_key_id: requester_key_id.to_string(),
            requester_fingerprint,
            actor_key_id: requester_key_id.to_string(),
            actor_fingerprint,
            key_registry_head: registry.head_digest(),
            operation_reference: [0; 32],
            nonce: nonce.to_string(),
            signature,
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        };
        let appended = self.append(event)?;
        Ok(ApprovalRequestReceipt {
            changed: true,
            request_id,
            sequence: appended.sequence,
            expires_at,
            threshold: appended.threshold,
        })
    }

    pub fn approve(
        &mut self,
        profile: &EnterpriseProfile,
        registry: &KeyRegistry,
        request_id: [u8; 32],
        approver_key_id: &str,
        approver_secret: &[u8],
        logical_timestamp: u64,
        nonce: &str,
    ) -> Result<ApprovalSignatureReceipt> {
        profile.validate_static_contract()?;
        validate_identifier("approver_key_id", approver_key_id)?;
        validate_identifier("nonce", nonce)?;
        let state = self.states.get(&request_id)
            .cloned()
            .ok_or_else(|| EnterpriseError::Invalid(
                "approval request not found".to_string(),
            ))?;
        if state.request.profile_digest != profile.profile_digest {
            return Err(EnterpriseError::Invalid(
                "approval request profile mismatch".to_string(),
            ));
        }
        if state.finalization.is_some() {
            return Err(EnterpriseError::Invalid(
                "approval request is already finalized".to_string(),
            ));
        }
        if logical_timestamp <= self.last_timestamp
            || logical_timestamp <= state.request.created_at
            || logical_timestamp > state.request.expires_at
        {
            return Err(EnterpriseError::Invalid(
                "approval timestamp is outside request lifetime"
                    .to_string(),
            ));
        }
        if state.request.requester_excluded
            && approver_key_id == state.request.requester_key_id
        {
            return Err(EnterpriseError::Invalid(
                "requester cannot approve their own request"
                    .to_string(),
            ));
        }
        if state.approvals.contains_key(approver_key_id) {
            return Err(EnterpriseError::Invalid(format!(
                "approver already signed request: {approver_key_id}",
            )));
        }
        let approver = registry.get(approver_key_id).ok_or_else(|| {
            EnterpriseError::Invalid(format!(
                "approval signer is unknown: {approver_key_id}",
            ))
        })?;
        if !approver.has_role(profile.approver_role_mask) {
            return Err(EnterpriseError::Invalid(
                "approval signer is not an active AUDITOR"
                    .to_string(),
            ));
        }
        let approver_fingerprint = key_fingerprint(
            approver_secret,
        )
        .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
        if approver_fingerprint != approver.fingerprint {
            return Err(EnterpriseError::Invalid(
                "approval signer secret mismatch".to_string(),
            ));
        }
        let message = enterprise_signature_message(
            ApprovalEventKind::Approve as u8,
            request_id,
            profile.profile_digest,
            state.request.subject_digest,
            [0; 32],
            logical_timestamp,
            state.request.expires_at,
            approver_fingerprint,
            registry.head_digest(),
            &state.request.requester_key_id,
            approver_key_id,
            nonce,
        )?;
        let (actor_fingerprint, signature) =
            sign_enterprise_event(approver_secret, &message)?;
        let event = ApprovalEvent {
            sequence: 0,
            kind: ApprovalEventKind::Approve,
            domain_code: state.request.domain_code,
            threshold: state.request.threshold,
            approver_role_mask: state.request.approver_role_mask,
            requester_excluded: state.request.requester_excluded,
            distinct_approvers: state.request.distinct_approvers,
            one_time_finalization:
                state.request.one_time_finalization,
            logical_timestamp,
            created_at: state.request.created_at,
            expires_at: state.request.expires_at,
            request_id,
            profile_digest: state.request.profile_digest,
            subject_digest: state.request.subject_digest,
            requester_key_id:
                state.request.requester_key_id.clone(),
            requester_fingerprint:
                state.request.requester_fingerprint,
            actor_key_id: approver_key_id.to_string(),
            actor_fingerprint,
            key_registry_head: registry.head_digest(),
            operation_reference: [0; 32],
            nonce: nonce.to_string(),
            signature,
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        };
        self.append(event)?;
        let updated = self.states.get(&request_id)
            .expect("request exists after approval append");
        Ok(ApprovalSignatureReceipt {
            changed: true,
            request_id,
            sequence: self.events
                .last()
                .expect("approval event exists")
                .sequence,
            approval_count: updated.approval_count(),
            threshold: updated.request.threshold,
            ready: updated.approval_count()
                >= updated.request.threshold as usize,
        })
    }

    pub fn validate_ready(
        &self,
        profile: &EnterpriseProfile,
        request_id: [u8; 32],
        domain_code: u8,
        subject_digest: [u8; 32],
        requester_key_id: &str,
        logical_timestamp: u64,
    ) -> Result<ApprovalValidation> {
        let state = self.states.get(&request_id).ok_or_else(|| {
            EnterpriseError::Invalid(
                "approval request not found".to_string(),
            )
        })?;
        if state.request.profile_digest != profile.profile_digest
            || state.request.domain_code != domain_code
            || state.request.subject_digest != subject_digest
            || state.request.requester_key_id != requester_key_id
        {
            return Err(EnterpriseError::Invalid(
                "approval request does not match exact operation"
                    .to_string(),
            ));
        }
        if state.finalization.is_some() {
            return Err(EnterpriseError::Invalid(
                "approval request is already finalized".to_string(),
            ));
        }
        if logical_timestamp <= self.last_timestamp
            || logical_timestamp > state.request.expires_at
            || logical_timestamp <= state.request.created_at
        {
            return Err(EnterpriseError::Invalid(
                "approval request is expired or operation timestamp is invalid"
                    .to_string(),
            ));
        }
        if state.approval_count()
            < state.request.threshold as usize
        {
            return Err(EnterpriseError::Invalid(format!(
                "approval quorum not reached: approvals={} threshold={}",
                state.approval_count(),
                state.request.threshold,
            )));
        }
        if state.request.distinct_approvers
            && state.approvals.len()
                != state.approvals
                    .keys()
                    .collect::<BTreeSet<_>>()
                    .len()
        {
            return Err(EnterpriseError::Invalid(
                "approval set contains duplicate approvers"
                    .to_string(),
            ));
        }
        if state.request.requester_excluded
            && state.approvals.contains_key(requester_key_id)
        {
            return Err(EnterpriseError::Invalid(
                "approval set contains requester self-approval"
                    .to_string(),
            ));
        }
        Ok(ApprovalValidation {
            request_id,
            domain_code,
            subject_digest,
            requester_key_id: requester_key_id.to_string(),
            approval_count: state.approval_count(),
            threshold: state.request.threshold,
            expires_at: state.request.expires_at,
        })
    }

    pub fn finalize(
        &mut self,
        profile: &EnterpriseProfile,
        registry: &KeyRegistry,
        request_id: [u8; 32],
        requester_key_id: &str,
        requester_secret: &[u8],
        logical_timestamp: u64,
        nonce: &str,
        operation_reference: [u8; 32],
    ) -> Result<ApprovalFinalizationReceipt> {
        validate_identifier("requester_key_id", requester_key_id)?;
        validate_identifier("nonce", nonce)?;
        if operation_reference == [0; 32] {
            return Err(EnterpriseError::Invalid(
                "operation reference cannot be zero".to_string(),
            ));
        }
        if let Some(existing) = self.states.get(&request_id)
            .and_then(|state| state.finalization.as_ref())
        {
            if existing.operation_reference == operation_reference {
                return Ok(ApprovalFinalizationReceipt {
                    changed: false,
                    request_id,
                    sequence: existing.sequence,
                    operation_reference,
                });
            }
            return Err(EnterpriseError::Invalid(
                "approval request finalized for different operation"
                    .to_string(),
            ));
        }
        let validation = self.validate_ready(
            profile,
            request_id,
            self.states[&request_id].request.domain_code,
            self.states[&request_id].request.subject_digest,
            requester_key_id,
            logical_timestamp,
        )?;
        let requester = registry.get(requester_key_id).ok_or_else(|| {
            EnterpriseError::Invalid(format!(
                "finalization requester is unknown: {requester_key_id}",
            ))
        })?;
        let required_role = requester_role_for_domain(
            validation.domain_code,
        )?;
        if !requester.has_role(required_role) {
            return Err(EnterpriseError::Invalid(
                "finalization requester lacks operation role"
                    .to_string(),
            ));
        }
        let requester_fingerprint = key_fingerprint(
            requester_secret,
        )
        .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
        if requester_fingerprint != requester.fingerprint {
            return Err(EnterpriseError::Invalid(
                "finalization requester secret mismatch".to_string(),
            ));
        }
        let request = self.states[&request_id].request.clone();
        let message = enterprise_signature_message(
            ApprovalEventKind::Finalize as u8,
            request_id,
            profile.profile_digest,
            request.subject_digest,
            operation_reference,
            logical_timestamp,
            request.expires_at,
            requester_fingerprint,
            registry.head_digest(),
            requester_key_id,
            requester_key_id,
            nonce,
        )?;
        let (actor_fingerprint, signature) =
            sign_enterprise_event(requester_secret, &message)?;
        let event = ApprovalEvent {
            sequence: 0,
            kind: ApprovalEventKind::Finalize,
            domain_code: request.domain_code,
            threshold: request.threshold,
            approver_role_mask: request.approver_role_mask,
            requester_excluded: request.requester_excluded,
            distinct_approvers: request.distinct_approvers,
            one_time_finalization: request.one_time_finalization,
            logical_timestamp,
            created_at: request.created_at,
            expires_at: request.expires_at,
            request_id,
            profile_digest: request.profile_digest,
            subject_digest: request.subject_digest,
            requester_key_id: request.requester_key_id.clone(),
            requester_fingerprint: request.requester_fingerprint,
            actor_key_id: requester_key_id.to_string(),
            actor_fingerprint,
            key_registry_head: registry.head_digest(),
            operation_reference,
            nonce: nonce.to_string(),
            signature,
            previous_digest: [0; 32],
            frame_digest: [0; 32],
        };
        let appended = self.append(event)?;
        Ok(ApprovalFinalizationReceipt {
            changed: true,
            request_id,
            sequence: appended.sequence,
            operation_reference,
        })
    }

    fn append(
        &mut self,
        mut event: ApprovalEvent,
    ) -> Result<ApprovalEvent> {
        if event.logical_timestamp <= self.last_timestamp {
            return Err(EnterpriseError::Invalid(
                "approval ledger timestamps must be strictly increasing"
                    .to_string(),
            ));
        }
        let nonce_key = (
            event.actor_key_id.clone(),
            event.nonce.clone(),
        );
        if self.used_nonces.contains(&nonce_key) {
            return Err(EnterpriseError::Invalid(
                "approval event nonce already used".to_string(),
            ));
        }
        event.sequence = (self.events.len() as u64)
            .checked_add(1)
            .ok_or_else(|| EnterpriseError::Invalid(
                "approval event sequence overflow".to_string(),
            ))?;
        event.previous_digest = self.head_digest;
        validate_event_against_states(&self.states, &event)?;
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
        apply_event(&mut self.states, &event)?;
        self.used_nonces.insert(nonce_key);
        self.last_timestamp = event.logical_timestamp;
        self.head_digest = frame_digest;
        self.events.push(event.clone());
        Ok(event)
    }

    fn replay(&mut self, bytes: &[u8]) -> Result<()> {
        let frames = decode_frames(bytes)?;
        for frame in frames {
            let mut event = decode_payload(&frame.payload)?;
            event.sequence = frame.sequence;
            event.previous_digest = frame.previous_digest;
            event.frame_digest = frame.frame_digest;
            if event.logical_timestamp <= self.last_timestamp {
                return Err(EnterpriseError::Invalid(
                    "approval ledger timestamp order mismatch"
                        .to_string(),
                ));
            }
            let nonce_key = (
                event.actor_key_id.clone(),
                event.nonce.clone(),
            );
            if self.used_nonces.contains(&nonce_key) {
                return Err(EnterpriseError::Invalid(
                    "approval ledger duplicate nonce".to_string(),
                ));
            }
            validate_event_against_states(
                &self.states,
                &event,
            )?;
            apply_event(&mut self.states, &event)?;
            self.used_nonces.insert(nonce_key);
            self.last_timestamp = event.logical_timestamp;
            self.head_digest = event.frame_digest;
            self.events.push(event);
        }
        Ok(())
    }
}

pub fn requester_role_for_domain(
    domain_code: u8,
) -> Result<u16> {
    match domain_code {
        DOMAIN_KEY_ROTATE => Ok(ROLE_KEY_ADMIN),
        DOMAIN_POLICY_REGISTER | DOMAIN_POLICY_REVOKE => {
            Ok(ROLE_POLICY_ADMIN)
        }
        DOMAIN_TRUST_COMMIT => Ok(ROLE_TRUST_OPERATOR),
        _ => Err(EnterpriseError::Invalid(format!(
            "unsupported enterprise approval domain {domain_code}",
        ))),
    }
}

fn validate_event_against_states(
    states: &BTreeMap<[u8; 32], ApprovalRequestState>,
    event: &ApprovalEvent,
) -> Result<()> {
    validate_identifier(
        "requester_key_id",
        &event.requester_key_id,
    )?;
    validate_identifier("actor_key_id", &event.actor_key_id)?;
    validate_identifier("nonce", &event.nonce)?;
    if event.threshold < 2
        || event.approver_role_mask == 0
        || event.logical_timestamp == 0
        || event.created_at == 0
        || event.expires_at <= event.created_at
        || event.request_id == [0; 32]
        || event.profile_digest == [0; 32]
        || event.subject_digest == [0; 32]
        || event.requester_fingerprint == [0; 32]
        || event.actor_fingerprint == [0; 32]
        || event.key_registry_head == [0; 32]
        || event.signature == [0; 32]
        || !event.requester_excluded
        || !event.distinct_approvers
        || !event.one_time_finalization
    {
        return Err(EnterpriseError::Invalid(
            "approval event invariant mismatch".to_string(),
        ));
    }
    requester_role_for_domain(event.domain_code)?;

    match event.kind {
        ApprovalEventKind::Request => {
            if states.contains_key(&event.request_id)
                || event.logical_timestamp != event.created_at
                || event.actor_key_id != event.requester_key_id
                || event.actor_fingerprint
                    != event.requester_fingerprint
                || event.operation_reference != [0; 32]
            {
                return Err(EnterpriseError::Invalid(
                    "approval REQUEST event mismatch".to_string(),
                ));
            }
        }
        ApprovalEventKind::Approve => {
            let state = states.get(&event.request_id).ok_or_else(|| {
                EnterpriseError::Invalid(
                    "approval APPROVE references unknown request"
                        .to_string(),
                )
            })?;
            validate_common_request_fields(
                &state.request,
                event,
            )?;
            if state.finalization.is_some()
                || event.logical_timestamp <= state.request.created_at
                || event.logical_timestamp > state.request.expires_at
                || event.actor_key_id
                    == state.request.requester_key_id
                || state.approvals.contains_key(
                    &event.actor_key_id,
                )
                || event.operation_reference != [0; 32]
            {
                return Err(EnterpriseError::Invalid(
                    "approval APPROVE event mismatch".to_string(),
                ));
            }
        }
        ApprovalEventKind::Finalize => {
            let state = states.get(&event.request_id).ok_or_else(|| {
                EnterpriseError::Invalid(
                    "approval FINALIZE references unknown request"
                        .to_string(),
                )
            })?;
            validate_common_request_fields(
                &state.request,
                event,
            )?;
            if state.finalization.is_some()
                || event.logical_timestamp <= state.request.created_at
                || event.logical_timestamp > state.request.expires_at
                || event.actor_key_id
                    != state.request.requester_key_id
                || event.actor_fingerprint
                    == [0; 32]
                || event.operation_reference == [0; 32]
                || state.approval_count()
                    < state.request.threshold as usize
            {
                return Err(EnterpriseError::Invalid(
                    "approval FINALIZE event mismatch".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_common_request_fields(
    request: &ApprovalEvent,
    event: &ApprovalEvent,
) -> Result<()> {
    if event.domain_code != request.domain_code
        || event.threshold != request.threshold
        || event.approver_role_mask
            != request.approver_role_mask
        || event.requester_excluded
            != request.requester_excluded
        || event.distinct_approvers
            != request.distinct_approvers
        || event.one_time_finalization
            != request.one_time_finalization
        || event.created_at != request.created_at
        || event.expires_at != request.expires_at
        || event.profile_digest != request.profile_digest
        || event.subject_digest != request.subject_digest
        || event.requester_key_id
            != request.requester_key_id
        || event.requester_fingerprint
            != request.requester_fingerprint
    {
        return Err(EnterpriseError::Invalid(
            "approval event request binding mismatch".to_string(),
        ));
    }
    Ok(())
}

fn apply_event(
    states: &mut BTreeMap<[u8; 32], ApprovalRequestState>,
    event: &ApprovalEvent,
) -> Result<()> {
    match event.kind {
        ApprovalEventKind::Request => {
            states.insert(
                event.request_id,
                ApprovalRequestState {
                    request: event.clone(),
                    approvals: BTreeMap::new(),
                    finalization: None,
                },
            );
        }
        ApprovalEventKind::Approve => {
            let state = states.get_mut(&event.request_id)
                .ok_or_else(|| EnterpriseError::Invalid(
                    "approval request disappeared".to_string(),
                ))?;
            state.approvals.insert(
                event.actor_key_id.clone(),
                event.clone(),
            );
        }
        ApprovalEventKind::Finalize => {
            let state = states.get_mut(&event.request_id)
                .ok_or_else(|| EnterpriseError::Invalid(
                    "approval request disappeared".to_string(),
                ))?;
            state.finalization = Some(event.clone());
        }
    }
    Ok(())
}

fn encode_payload(event: &ApprovalEvent) -> Result<Vec<u8>> {
    let requester = event.requester_key_id.as_bytes();
    let actor = event.actor_key_id.as_bytes();
    let nonce = event.nonce.as_bytes();
    let flags = (event.requester_excluded as u16)
        | ((event.distinct_approvers as u16) << 1)
        | ((event.one_time_finalization as u16) << 2);
    let mut output = Vec::new();
    output.extend_from_slice(&APPROVAL_PAYLOAD_MAGIC);
    output.push(event.kind as u8);
    output.push(event.domain_code);
    output.extend_from_slice(&flags.to_le_bytes());
    output.extend_from_slice(&event.threshold.to_le_bytes());
    output.extend_from_slice(
        &event.approver_role_mask.to_le_bytes(),
    );
    output.extend_from_slice(
        &event.logical_timestamp.to_le_bytes(),
    );
    output.extend_from_slice(&event.created_at.to_le_bytes());
    output.extend_from_slice(&event.expires_at.to_le_bytes());
    output.extend_from_slice(
        &(requester.len() as u32).to_le_bytes(),
    );
    output.extend_from_slice(
        &(actor.len() as u32).to_le_bytes(),
    );
    output.extend_from_slice(
        &(nonce.len() as u32).to_le_bytes(),
    );
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&event.request_id);
    output.extend_from_slice(&event.profile_digest);
    output.extend_from_slice(&event.subject_digest);
    output.extend_from_slice(&event.requester_fingerprint);
    output.extend_from_slice(&event.actor_fingerprint);
    output.extend_from_slice(&event.key_registry_head);
    output.extend_from_slice(&event.operation_reference);
    output.extend_from_slice(&event.signature);
    output.extend_from_slice(&0u64.to_le_bytes());
    debug_assert_eq!(output.len(), APPROVAL_FIXED_BYTES);
    output.extend_from_slice(requester);
    output.extend_from_slice(actor);
    output.extend_from_slice(nonce);
    Ok(output)
}

fn decode_payload(payload: &[u8]) -> Result<ApprovalEvent> {
    if payload.len() < APPROVAL_FIXED_BYTES
        || payload[0..8] != APPROVAL_PAYLOAD_MAGIC
    {
        return Err(EnterpriseError::Invalid(
            "approval payload header mismatch".to_string(),
        ));
    }
    let kind = ApprovalEventKind::from_code(payload[8])?;
    let domain_code = payload[9];
    let flags = read_u16(payload, 10)?;
    if flags & !0b111 != 0 {
        return Err(EnterpriseError::Invalid(
            "approval payload flags invalid".to_string(),
        ));
    }
    let threshold = read_u16(payload, 12)?;
    let approver_role_mask = read_u16(payload, 14)?;
    let logical_timestamp = read_u64(payload, 16)?;
    let created_at = read_u64(payload, 24)?;
    let expires_at = read_u64(payload, 32)?;
    let requester_len = read_u32(payload, 40)? as usize;
    let actor_len = read_u32(payload, 44)? as usize;
    let nonce_len = read_u32(payload, 48)? as usize;
    if read_u32(payload, 52)? != 0
        || read_u64(payload, 312)? != 0
    {
        return Err(EnterpriseError::Invalid(
            "approval payload reserved field non-zero".to_string(),
        ));
    }
    let request_id = read_digest(payload, 56)?;
    let profile_digest = read_digest(payload, 88)?;
    let subject_digest = read_digest(payload, 120)?;
    let requester_fingerprint = read_digest(payload, 152)?;
    let actor_fingerprint = read_digest(payload, 184)?;
    let key_registry_head = read_digest(payload, 216)?;
    let operation_reference = read_digest(payload, 248)?;
    let signature = read_digest(payload, 280)?;
    let mut cursor = APPROVAL_FIXED_BYTES;
    let requester_key_id = read_string(
        payload,
        &mut cursor,
        requester_len,
        "requester_key_id",
    )?;
    let actor_key_id = read_string(
        payload,
        &mut cursor,
        actor_len,
        "actor_key_id",
    )?;
    let nonce = read_string(
        payload,
        &mut cursor,
        nonce_len,
        "nonce",
    )?;
    if cursor != payload.len() {
        return Err(EnterpriseError::Invalid(
            "approval payload trailing bytes".to_string(),
        ));
    }
    Ok(ApprovalEvent {
        sequence: 0,
        kind,
        domain_code,
        threshold,
        approver_role_mask,
        requester_excluded: flags & 1 != 0,
        distinct_approvers: flags & 2 != 0,
        one_time_finalization: flags & 4 != 0,
        logical_timestamp,
        created_at,
        expires_at,
        request_id,
        profile_digest,
        subject_digest,
        requester_key_id,
        requester_fingerprint,
        actor_key_id,
        actor_fingerprint,
        key_registry_head,
        operation_reference,
        nonce,
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
        return Err(EnterpriseError::Invalid(
            "approval payload exceeds maximum".to_string(),
        ));
    }
    let mut output = Vec::new();
    output.extend_from_slice(&APPROVAL_MAGIC);
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
            return Err(EnterpriseError::Truncated {
                context: "approval ledger",
                offset,
                remaining_bytes: remaining,
            });
        }
        let header = &bytes[offset..offset + FRAME_HEADER_BYTES];
        if header[0..8] != APPROVAL_MAGIC
            || read_u16(header, 8)? != 1
            || read_u16(header, 10)? != 0
            || read_u32(header, 12)? as usize
                != FRAME_HEADER_BYTES
            || header[128..144] != [0; 16]
        {
            return Err(EnterpriseError::Invalid(
                "approval frame header mismatch".to_string(),
            ));
        }
        let sequence = read_u64(header, 16)?;
        if sequence != frames.len() as u64 + 1 {
            return Err(EnterpriseError::Invalid(
                "approval frame sequence mismatch".to_string(),
            ));
        }
        let payload_len = usize::try_from(
            read_u64(header, 24)?,
        )
        .map_err(|_| EnterpriseError::Invalid(
            "approval payload length overflow".to_string(),
        ))?;
        if payload_len > MAX_PAYLOAD_BYTES {
            return Err(EnterpriseError::Invalid(
                "approval payload too large".to_string(),
            ));
        }
        let previous_digest = read_digest(header, 32)?;
        let expected_payload_digest = read_digest(header, 64)?;
        let expected_frame_digest = read_digest(header, 96)?;
        if previous_digest != head {
            return Err(EnterpriseError::Integrity(
                "approval previous digest mismatch".to_string(),
            ));
        }
        let payload_start = offset + FRAME_HEADER_BYTES;
        let frame_end = payload_start
            .checked_add(payload_len)
            .ok_or_else(|| EnterpriseError::Invalid(
                "approval frame length overflow".to_string(),
            ))?;
        if frame_end > bytes.len() {
            return Err(EnterpriseError::Truncated {
                context: "approval ledger",
                offset,
                remaining_bytes: remaining,
            });
        }
        let payload = bytes[payload_start..frame_end].to_vec();
        let actual_payload_digest = sha256(&payload);
        if actual_payload_digest != expected_payload_digest {
            return Err(EnterpriseError::Integrity(
                "approval payload digest mismatch".to_string(),
            ));
        }
        let actual_frame_digest = compute_frame_digest(
            sequence,
            previous_digest,
            expected_payload_digest,
        );
        if actual_frame_digest != expected_frame_digest {
            return Err(EnterpriseError::Integrity(
                "approval frame digest mismatch".to_string(),
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
    output.extend_from_slice(&APPROVAL_FRAME_DOMAIN);
    output.extend_from_slice(&sequence.to_le_bytes());
    output.extend_from_slice(&previous_digest);
    output.extend_from_slice(&payload_digest);
    sha256(&output)
}

fn create_empty_file(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(EnterpriseError::Invalid(format!(
            "approval ledger already exists: {}",
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
        return Err(EnterpriseError::Invalid(format!(
            "{name} exceeds maximum length",
        )));
    }
    let end = cursor.checked_add(length).ok_or_else(|| {
        EnterpriseError::Invalid(
            "approval string length overflow".to_string(),
        )
    })?;
    let value = bytes.get(*cursor..end).ok_or_else(|| {
        EnterpriseError::Invalid(format!(
            "truncated approval {name}",
        ))
    })?;
    *cursor = end;
    String::from_utf8(value.to_vec()).map_err(|_| {
        EnterpriseError::Invalid(format!(
            "approval {name} is not UTF-8",
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
            "truncated approval digest".to_string(),
        )
    })?;
    Ok(value.try_into().expect("checked digest"))
}
