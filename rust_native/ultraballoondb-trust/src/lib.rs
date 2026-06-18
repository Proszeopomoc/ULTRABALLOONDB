use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use ultraballoondb_storage::{hex_digest, sha256};

pub const LEDGER_MAGIC: [u8; 8] = *b"UBTRN01\0";
pub const LEDGER_MAJOR: u16 = 1;
pub const LEDGER_MINOR: u16 = 0;
pub const FRAME_HEADER_BYTES: usize = 144;
pub const PAYLOAD_MAGIC: [u8; 8] = *b"UBTRP01\0";
pub const INPUT_DIGEST_DOMAIN: [u8; 8] = *b"UBTRIN1\0";
pub const DECISION_DIGEST_DOMAIN: [u8; 8] = *b"UBTRDC1\0";
pub const TRANSITION_DIGEST_DOMAIN: [u8; 8] = *b"UBTRDG1\0";
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_EVIDENCE_REFS: usize = 4096;
pub const MAX_STRING_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub enum TrustError {
    Io(io::Error),
    Invalid(String),
    Integrity {
        context: String,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    TruncatedTail {
        offset: usize,
        remaining_bytes: usize,
    },
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Invalid(message) => write!(f, "invalid trust transition: {message}"),
            Self::Integrity {
                context,
                expected,
                actual,
            } => write!(
                f,
                "trust integrity mismatch for {context}: expected={} actual={}",
                hex_digest(expected),
                hex_digest(actual),
            ),
            Self::TruncatedTail {
                offset,
                remaining_bytes,
            } => write!(
                f,
                "truncated trust ledger tail at offset {offset}: remaining_bytes={remaining_bytes}",
            ),
        }
    }
}

impl std::error::Error for TrustError {}

impl From<io::Error> for TrustError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, TrustError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum MaturityState {
    Raw = 1,
    Hypothesis = 2,
    Candidate = 3,
    Verified = 4,
}

impl MaturityState {
    fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Raw),
            2 => Ok(Self::Hypothesis),
            3 => Ok(Self::Candidate),
            4 => Ok(Self::Verified),
            _ => Err(TrustError::Invalid(format!(
                "unknown maturity code {value}"
            ))),
        }
    }

    fn next(self) -> Option<Self> {
        match self {
            Self::Raw => Some(Self::Hypothesis),
            Self::Hypothesis => Some(Self::Candidate),
            Self::Candidate => Some(Self::Verified),
            Self::Verified => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "RAW",
            Self::Hypothesis => "HYPOTHESIS",
            Self::Candidate => "CANDIDATE",
            Self::Verified => "VERIFIED",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ValidityState {
    Active = 1,
    Disputed = 2,
    Expired = 3,
    Revoked = 4,
    Superseded = 5,
}

impl ValidityState {
    fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::Disputed),
            3 => Ok(Self::Expired),
            4 => Ok(Self::Revoked),
            5 => Ok(Self::Superseded),
            _ => Err(TrustError::Invalid(format!(
                "unknown validity code {value}"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Disputed => "DISPUTED",
            Self::Expired => "EXPIRED",
            Self::Revoked => "REVOKED",
            Self::Superseded => "SUPERSEDED",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustState {
    pub maturity: MaturityState,
    pub validity: ValidityState,
}

impl TrustState {
    pub const fn raw_active() -> Self {
        Self {
            maturity: MaturityState::Raw,
            validity: ValidityState::Active,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TrustOperation {
    Propose = 1,
    Promote = 2,
    Dispute = 3,
    Revoke = 4,
    Expire = 5,
    Supersede = 6,
}

impl TrustOperation {
    fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Propose),
            2 => Ok(Self::Promote),
            3 => Ok(Self::Dispute),
            4 => Ok(Self::Revoke),
            5 => Ok(Self::Expire),
            6 => Ok(Self::Supersede),
            _ => Err(TrustError::Invalid(format!(
                "unknown trust operation code {value}"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Propose => "PROPOSE",
            Self::Promote => "PROMOTE",
            Self::Dispute => "DISPUTE",
            Self::Revoke => "REVOKE",
            Self::Expire => "EXPIRE",
            Self::Supersede => "SUPERSEDE",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TransitionAuthority {
    EvidencePolicy = 1,
    Import = 2,
    Ranker = 3,
    Wave = 4,
    Similarity = 5,
    Frequency = 6,
    Llm = 7,
    RigorMultiplier = 8,
}

impl TransitionAuthority {
    fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::EvidencePolicy),
            2 => Ok(Self::Import),
            3 => Ok(Self::Ranker),
            4 => Ok(Self::Wave),
            5 => Ok(Self::Similarity),
            6 => Ok(Self::Frequency),
            7 => Ok(Self::Llm),
            8 => Ok(Self::RigorMultiplier),
            _ => Err(TrustError::Invalid(format!(
                "unknown transition authority code {value}"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EvidencePolicy => "EVIDENCE_POLICY",
            Self::Import => "IMPORT",
            Self::Ranker => "RANKER",
            Self::Wave => "WAVE",
            Self::Similarity => "SIMILARITY",
            Self::Frequency => "FREQUENCY",
            Self::Llm => "LLM",
            Self::RigorMultiplier => "RIGOR_MULTIPLIER",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRef {
    pub evidence_id: String,
    pub provenance_id: String,
    pub evidence_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionIntent {
    pub record_id: String,
    pub operation: TrustOperation,
    pub authority: TransitionAuthority,
    pub evidence_refs: Vec<EvidenceRef>,
    pub policy_id: String,
    pub policy_version: String,
    pub verifier_id: String,
    pub record_digest: [u8; 32],
    pub logical_timestamp: u64,
    pub reason_code: String,
    pub superseding_record_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustTransition {
    pub sequence: u64,
    pub logical_timestamp: u64,
    pub transition_id: [u8; 32],
    pub record_id: String,
    pub previous_state: Option<TrustState>,
    pub next_state: TrustState,
    pub operation: TrustOperation,
    pub authority: TransitionAuthority,
    pub evidence_refs: Vec<EvidenceRef>,
    pub policy_id: String,
    pub policy_version: String,
    pub verifier_id: String,
    pub record_digest: [u8; 32],
    pub input_digest: [u8; 32],
    pub decision_digest: [u8; 32],
    pub reason_code: String,
    pub superseding_record_id: Option<String>,
    pub previous_transition_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordTrustSnapshot {
    pub record_id: String,
    pub state: TrustState,
    pub record_digest: [u8; 32],
    pub last_transition_id: [u8; 32],
    pub last_sequence: u64,
    pub superseding_record_id: Option<String>,
}

#[derive(Debug)]
pub struct TrustLedger {
    path: PathBuf,
    transitions: Vec<TrustTransition>,
    states: BTreeMap<String, RecordTrustSnapshot>,
    head_digest: [u8; 32],
    last_timestamp: u64,
}

impl TrustLedger {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(TrustError::Invalid(format!(
                "trust ledger already exists: {}",
                path.display()
            )));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?
            .sync_all()?;
        Ok(Self {
            path,
            transitions: Vec::new(),
            states: BTreeMap::new(),
            head_digest: [0; 32],
            last_timestamp: 0,
        })
    }

    pub fn open_strict(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.is_file() {
            return Err(TrustError::Invalid(format!(
                "trust ledger file missing: {}",
                path.display()
            )));
        }
        let bytes = fs::read(&path)?;
        let mut ledger = Self {
            path,
            transitions: Vec::new(),
            states: BTreeMap::new(),
            head_digest: [0; 32],
            last_timestamp: 0,
        };
        ledger.replay_bytes(&bytes)?;
        Ok(ledger)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }

    pub fn transitions(&self) -> &[TrustTransition] {
        &self.transitions
    }

    pub fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }

    pub fn last_timestamp(&self) -> u64 {
        self.last_timestamp
    }

    pub fn snapshot(&self, record_id: &str) -> Option<&RecordTrustSnapshot> {
        self.states.get(record_id)
    }

    pub fn snapshots(&self) -> Vec<RecordTrustSnapshot> {
        self.states.values().cloned().collect()
    }

    pub fn apply(&mut self, intent: TransitionIntent) -> Result<TrustTransition> {
        if intent.logical_timestamp <= self.last_timestamp {
            return Err(TrustError::Invalid(format!(
                "logical timestamp must increase: previous={} requested={}",
                self.last_timestamp,
                intent.logical_timestamp,
            )));
        }
        let sequence = (self.transitions.len() as u64)
            .checked_add(1)
            .ok_or_else(|| TrustError::Invalid(
                "trust transition sequence overflow".to_string()
            ))?;
        let previous_state = self.states.get(&intent.record_id).map(|value| value.state);
        let next_state = validate_semantic_transition(&self.states, previous_state, &intent)?;
        let input_digest = compute_input_digest(&intent);
        let decision_digest = compute_decision_digest(
            input_digest,
            previous_state,
            next_state,
        );
        let payload = encode_payload(
            previous_state,
            next_state,
            input_digest,
            decision_digest,
            &intent,
        )?;
        let payload_digest = sha256(&payload);
        let transition_id = compute_transition_digest(
            sequence,
            intent.logical_timestamp,
            self.head_digest,
            payload_digest,
        );
        let frame = encode_frame(
            sequence,
            intent.logical_timestamp,
            self.head_digest,
            payload_digest,
            transition_id,
            &payload,
        )?;

        let mut file = OpenOptions::new()
            .append(true)
            .write(true)
            .open(&self.path)?;
        file.write_all(&frame)?;
        file.flush()?;
        file.sync_all()?;

        let transition = TrustTransition {
            sequence,
            logical_timestamp: intent.logical_timestamp,
            transition_id,
            record_id: intent.record_id,
            previous_state,
            next_state,
            operation: intent.operation,
            authority: intent.authority,
            evidence_refs: intent.evidence_refs,
            policy_id: intent.policy_id,
            policy_version: intent.policy_version,
            verifier_id: intent.verifier_id,
            record_digest: intent.record_digest,
            input_digest,
            decision_digest,
            reason_code: intent.reason_code,
            superseding_record_id: intent.superseding_record_id,
            previous_transition_digest: self.head_digest,
        };
        apply_replayed_transition(&mut self.states, &transition)?;
        self.last_timestamp = transition.logical_timestamp;
        self.head_digest = transition.transition_id;
        self.transitions.push(transition.clone());
        Ok(transition)
    }

    fn replay_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let remaining = bytes.len() - offset;
            if remaining < FRAME_HEADER_BYTES {
                return Err(TrustError::TruncatedTail {
                    offset,
                    remaining_bytes: remaining,
                });
            }
            let header = &bytes[offset..offset + FRAME_HEADER_BYTES];
            if header[0..8] != LEDGER_MAGIC {
                return Err(TrustError::Invalid(format!(
                    "ledger magic mismatch at offset {offset}"
                )));
            }
            let major = read_u16(header, 8)?;
            let minor = read_u16(header, 10)?;
            let header_bytes = read_u32(header, 12)? as usize;
            if major != LEDGER_MAJOR
                || minor != LEDGER_MINOR
                || header_bytes != FRAME_HEADER_BYTES
            {
                return Err(TrustError::Invalid(format!(
                    "ledger version/header mismatch at offset {offset}"
                )));
            }
            let sequence = read_u64(header, 16)?;
            let logical_timestamp = read_u64(header, 24)?;
            let payload_bytes = usize::try_from(read_u64(header, 32)?)
                .map_err(|_| TrustError::Invalid(
                    "ledger payload length too large".to_string()
                ))?;
            if payload_bytes > MAX_PAYLOAD_BYTES {
                return Err(TrustError::Invalid(format!(
                    "ledger payload exceeds maximum: {payload_bytes}"
                )));
            }
            let previous_digest = read_digest(header, 40)?;
            let expected_payload_digest = read_digest(header, 72)?;
            let expected_transition_digest = read_digest(header, 104)?;
            if header[136..144] != [0; 8] {
                return Err(TrustError::Invalid(format!(
                    "ledger reserved bytes are non-zero at sequence {sequence}"
                )));
            }
            let payload_start = offset + FRAME_HEADER_BYTES;
            let frame_end = payload_start
                .checked_add(payload_bytes)
                .ok_or_else(|| TrustError::Invalid(
                    "ledger frame length overflow".to_string()
                ))?;
            if frame_end > bytes.len() {
                return Err(TrustError::TruncatedTail {
                    offset,
                    remaining_bytes: bytes.len() - offset,
                });
            }
            let expected_sequence = (self.transitions.len() as u64) + 1;
            if sequence != expected_sequence {
                return Err(TrustError::Invalid(format!(
                    "ledger sequence mismatch: expected={expected_sequence} actual={sequence}"
                )));
            }
            if logical_timestamp <= self.last_timestamp {
                return Err(TrustError::Invalid(format!(
                    "ledger timestamp is not strictly increasing at sequence {sequence}"
                )));
            }
            if previous_digest != self.head_digest {
                return Err(TrustError::Integrity {
                    context: format!("previous transition chain at sequence {sequence}"),
                    expected: self.head_digest,
                    actual: previous_digest,
                });
            }
            let payload = &bytes[payload_start..frame_end];
            let actual_payload_digest = sha256(payload);
            if actual_payload_digest != expected_payload_digest {
                return Err(TrustError::Integrity {
                    context: format!("payload at sequence {sequence}"),
                    expected: expected_payload_digest,
                    actual: actual_payload_digest,
                });
            }
            let actual_transition_digest = compute_transition_digest(
                sequence,
                logical_timestamp,
                previous_digest,
                expected_payload_digest,
            );
            if actual_transition_digest != expected_transition_digest {
                return Err(TrustError::Integrity {
                    context: format!("transition at sequence {sequence}"),
                    expected: expected_transition_digest,
                    actual: actual_transition_digest,
                });
            }
            let transition = decode_payload(
                sequence,
                logical_timestamp,
                expected_transition_digest,
                previous_digest,
                payload,
            )?;
            let current_state = self.states.get(&transition.record_id).map(|value| value.state);
            if current_state != transition.previous_state {
                return Err(TrustError::Invalid(format!(
                    "replayed previous_state mismatch at sequence {sequence}"
                )));
            }
            let intent = TransitionIntent {
                record_id: transition.record_id.clone(),
                operation: transition.operation,
                authority: transition.authority,
                evidence_refs: transition.evidence_refs.clone(),
                policy_id: transition.policy_id.clone(),
                policy_version: transition.policy_version.clone(),
                verifier_id: transition.verifier_id.clone(),
                record_digest: transition.record_digest,
                logical_timestamp,
                reason_code: transition.reason_code.clone(),
                superseding_record_id: transition.superseding_record_id.clone(),
            };
            let expected_next = validate_semantic_transition(
                &self.states,
                current_state,
                &intent,
            )?;
            if expected_next != transition.next_state {
                return Err(TrustError::Invalid(format!(
                    "replayed next_state mismatch at sequence {sequence}"
                )));
            }
            let expected_input = compute_input_digest(&intent);
            if expected_input != transition.input_digest {
                return Err(TrustError::Integrity {
                    context: format!("input digest at sequence {sequence}"),
                    expected: expected_input,
                    actual: transition.input_digest,
                });
            }
            let expected_decision = compute_decision_digest(
                expected_input,
                current_state,
                expected_next,
            );
            if expected_decision != transition.decision_digest {
                return Err(TrustError::Integrity {
                    context: format!("decision digest at sequence {sequence}"),
                    expected: expected_decision,
                    actual: transition.decision_digest,
                });
            }
            apply_replayed_transition(&mut self.states, &transition)?;
            self.last_timestamp = logical_timestamp;
            self.head_digest = expected_transition_digest;
            self.transitions.push(transition);
            offset = frame_end;
        }
        Ok(())
    }
}

fn validate_semantic_transition(
    states: &BTreeMap<String, RecordTrustSnapshot>,
    previous_state: Option<TrustState>,
    intent: &TransitionIntent,
) -> Result<TrustState> {
    validate_common_intent(intent)?;
    match intent.authority {
        TransitionAuthority::EvidencePolicy => {}
        TransitionAuthority::Import if intent.operation == TrustOperation::Propose => {}
        authority => {
            return Err(TrustError::Invalid(format!(
                "authority {} cannot mutate trust through {}",
                authority.as_str(),
                intent.operation.as_str(),
            )))
        }
    }

    let current_snapshot = states.get(&intent.record_id);
    if let Some(snapshot) = current_snapshot {
        if snapshot.record_digest != intent.record_digest {
            return Err(TrustError::Invalid(format!(
                "record digest does not match bound digest for {}",
                intent.record_id,
            )));
        }
    }

    match intent.operation {
        TrustOperation::Propose => {
            if previous_state.is_some() {
                return Err(TrustError::Invalid(format!(
                    "record is already tracked: {}",
                    intent.record_id,
                )));
            }
            if intent.superseding_record_id.is_some() {
                return Err(TrustError::Invalid(
                    "PROPOSE cannot include superseding_record_id".to_string(),
                ));
            }
            Ok(TrustState::raw_active())
        }
        TrustOperation::Promote => {
            let current = require_current(previous_state, &intent.record_id)?;
            if current.validity != ValidityState::Active {
                return Err(TrustError::Invalid(
                    "PROMOTE requires ACTIVE validity".to_string(),
                ));
            }
            if intent.superseding_record_id.is_some() {
                return Err(TrustError::Invalid(
                    "PROMOTE cannot include superseding_record_id".to_string(),
                ));
            }
            let maturity = current.maturity.next().ok_or_else(|| {
                TrustError::Invalid(
                    "VERIFIED maturity cannot be promoted".to_string(),
                )
            })?;
            Ok(TrustState {
                maturity,
                validity: ValidityState::Active,
            })
        }
        TrustOperation::Dispute => {
            let current = require_current(previous_state, &intent.record_id)?;
            if current.validity != ValidityState::Active {
                return Err(TrustError::Invalid(
                    "DISPUTE requires ACTIVE validity".to_string(),
                ));
            }
            if intent.superseding_record_id.is_some() {
                return Err(TrustError::Invalid(
                    "DISPUTE cannot include superseding_record_id".to_string(),
                ));
            }
            Ok(TrustState {
                maturity: current.maturity,
                validity: ValidityState::Disputed,
            })
        }
        TrustOperation::Revoke => {
            let current = require_current(previous_state, &intent.record_id)?;
            if matches!(
                current.validity,
                ValidityState::Revoked | ValidityState::Superseded
            ) {
                return Err(TrustError::Invalid(
                    "REVOKE cannot mutate a terminal validity".to_string(),
                ));
            }
            if intent.superseding_record_id.is_some() {
                return Err(TrustError::Invalid(
                    "REVOKE cannot include superseding_record_id".to_string(),
                ));
            }
            Ok(TrustState {
                maturity: current.maturity,
                validity: ValidityState::Revoked,
            })
        }
        TrustOperation::Expire => {
            let current = require_current(previous_state, &intent.record_id)?;
            if !matches!(
                current.validity,
                ValidityState::Active | ValidityState::Disputed
            ) {
                return Err(TrustError::Invalid(
                    "EXPIRE requires ACTIVE or DISPUTED validity".to_string(),
                ));
            }
            if intent.superseding_record_id.is_some() {
                return Err(TrustError::Invalid(
                    "EXPIRE cannot include superseding_record_id".to_string(),
                ));
            }
            Ok(TrustState {
                maturity: current.maturity,
                validity: ValidityState::Expired,
            })
        }
        TrustOperation::Supersede => {
            let current = require_current(previous_state, &intent.record_id)?;
            if matches!(
                current.validity,
                ValidityState::Revoked | ValidityState::Superseded
            ) {
                return Err(TrustError::Invalid(
                    "SUPERSEDE cannot mutate a terminal validity".to_string(),
                ));
            }
            let superseding_id = intent
                .superseding_record_id
                .as_ref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| TrustError::Invalid(
                    "SUPERSEDE requires superseding_record_id".to_string(),
                ))?;
            if superseding_id == &intent.record_id {
                return Err(TrustError::Invalid(
                    "record cannot supersede itself".to_string(),
                ));
            }
            let superseding = states.get(superseding_id).ok_or_else(|| {
                TrustError::Invalid(format!(
                    "superseding record is not tracked: {superseding_id}"
                ))
            })?;
            if matches!(
                superseding.state.validity,
                ValidityState::Revoked | ValidityState::Superseded
            ) {
                return Err(TrustError::Invalid(
                    "superseding record has terminal validity".to_string(),
                ));
            }
            Ok(TrustState {
                maturity: current.maturity,
                validity: ValidityState::Superseded,
            })
        }
    }
}

fn validate_common_intent(intent: &TransitionIntent) -> Result<()> {
    validate_string("record_id", &intent.record_id)?;
    validate_string("policy_id", &intent.policy_id)?;
    validate_string("policy_version", &intent.policy_version)?;
    validate_string("verifier_id", &intent.verifier_id)?;
    validate_string("reason_code", &intent.reason_code)?;
    if is_zero_digest(&intent.record_digest) {
        return Err(TrustError::Invalid(
            "record_digest cannot be zero".to_string(),
        ));
    }
    if intent.logical_timestamp == 0 {
        return Err(TrustError::Invalid(
            "logical_timestamp must be greater than zero".to_string(),
        ));
    }
    if intent.evidence_refs.is_empty() {
        return Err(TrustError::Invalid(
            "at least one evidence reference is required".to_string(),
        ));
    }
    if intent.evidence_refs.len() > MAX_EVIDENCE_REFS {
        return Err(TrustError::Invalid(format!(
            "evidence reference count exceeds maximum {}",
            MAX_EVIDENCE_REFS,
        )));
    }
    let mut evidence_ids = BTreeSet::new();
    for evidence in &intent.evidence_refs {
        validate_string("evidence_id", &evidence.evidence_id)?;
        validate_string("provenance_id", &evidence.provenance_id)?;
        if is_zero_digest(&evidence.evidence_digest) {
            return Err(TrustError::Invalid(format!(
                "evidence digest cannot be zero: {}",
                evidence.evidence_id,
            )));
        }
        if !evidence_ids.insert(evidence.evidence_id.clone()) {
            return Err(TrustError::Invalid(format!(
                "duplicate evidence_id: {}",
                evidence.evidence_id,
            )));
        }
    }
    if let Some(value) = &intent.superseding_record_id {
        validate_string("superseding_record_id", value)?;
    }
    Ok(())
}

fn require_current(
    previous_state: Option<TrustState>,
    record_id: &str,
) -> Result<TrustState> {
    previous_state.ok_or_else(|| TrustError::Invalid(format!(
        "record is not tracked: {record_id}"
    )))
}

fn validate_string(name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(TrustError::Invalid(format!(
            "{name} cannot be empty"
        )));
    }
    if value.as_bytes().len() > MAX_STRING_BYTES {
        return Err(TrustError::Invalid(format!(
            "{name} exceeds maximum byte length {MAX_STRING_BYTES}"
        )));
    }
    Ok(())
}

fn is_zero_digest(value: &[u8; 32]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn compute_input_digest(intent: &TransitionIntent) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&INPUT_DIGEST_DOMAIN);
    preimage.push(intent.operation as u8);
    preimage.push(intent.authority as u8);
    preimage.extend_from_slice(&[0; 6]);
    push_string(&mut preimage, &intent.record_id);
    push_string(&mut preimage, &intent.policy_id);
    push_string(&mut preimage, &intent.policy_version);
    push_string(&mut preimage, &intent.verifier_id);
    push_string(&mut preimage, &intent.reason_code);
    push_optional_string(&mut preimage, intent.superseding_record_id.as_deref());
    preimage.extend_from_slice(&intent.record_digest);
    preimage.extend_from_slice(&intent.logical_timestamp.to_le_bytes());
    preimage.extend_from_slice(&(intent.evidence_refs.len() as u32).to_le_bytes());
    for evidence in &intent.evidence_refs {
        push_string(&mut preimage, &evidence.evidence_id);
        push_string(&mut preimage, &evidence.provenance_id);
        preimage.extend_from_slice(&evidence.evidence_digest);
    }
    sha256(&preimage)
}

fn compute_decision_digest(
    input_digest: [u8; 32],
    previous_state: Option<TrustState>,
    next_state: TrustState,
) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&DECISION_DIGEST_DOMAIN);
    preimage.extend_from_slice(&input_digest);
    let (previous_maturity, previous_validity) = encode_optional_state(previous_state);
    preimage.push(previous_maturity);
    preimage.push(previous_validity);
    preimage.push(next_state.maturity as u8);
    preimage.push(next_state.validity as u8);
    preimage.extend_from_slice(&[0; 4]);
    sha256(&preimage)
}

fn compute_transition_digest(
    sequence: u64,
    logical_timestamp: u64,
    previous_digest: [u8; 32],
    payload_digest: [u8; 32],
) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&TRANSITION_DIGEST_DOMAIN);
    preimage.extend_from_slice(&sequence.to_le_bytes());
    preimage.extend_from_slice(&logical_timestamp.to_le_bytes());
    preimage.extend_from_slice(&previous_digest);
    preimage.extend_from_slice(&payload_digest);
    sha256(&preimage)
}

fn encode_payload(
    previous_state: Option<TrustState>,
    next_state: TrustState,
    input_digest: [u8; 32],
    decision_digest: [u8; 32],
    intent: &TransitionIntent,
) -> Result<Vec<u8>> {
    let (previous_maturity, previous_validity) = encode_optional_state(previous_state);
    let superseding = intent.superseding_record_id.as_deref().unwrap_or("");
    let mut output = Vec::new();
    output.extend_from_slice(&PAYLOAD_MAGIC);
    output.push(intent.operation as u8);
    output.push(intent.authority as u8);
    output.push(previous_maturity);
    output.push(previous_validity);
    output.push(next_state.maturity as u8);
    output.push(next_state.validity as u8);
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&(intent.record_id.as_bytes().len() as u32).to_le_bytes());
    output.extend_from_slice(&(intent.policy_id.as_bytes().len() as u32).to_le_bytes());
    output.extend_from_slice(&(intent.policy_version.as_bytes().len() as u32).to_le_bytes());
    output.extend_from_slice(&(intent.verifier_id.as_bytes().len() as u32).to_le_bytes());
    output.extend_from_slice(&(intent.reason_code.as_bytes().len() as u32).to_le_bytes());
    output.extend_from_slice(&(superseding.as_bytes().len() as u32).to_le_bytes());
    output.extend_from_slice(&(intent.evidence_refs.len() as u32).to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&intent.record_digest);
    output.extend_from_slice(&input_digest);
    output.extend_from_slice(&decision_digest);
    output.extend_from_slice(intent.record_id.as_bytes());
    output.extend_from_slice(intent.policy_id.as_bytes());
    output.extend_from_slice(intent.policy_version.as_bytes());
    output.extend_from_slice(intent.verifier_id.as_bytes());
    output.extend_from_slice(intent.reason_code.as_bytes());
    output.extend_from_slice(superseding.as_bytes());
    for evidence in &intent.evidence_refs {
        output.extend_from_slice(&(evidence.evidence_id.as_bytes().len() as u32).to_le_bytes());
        output.extend_from_slice(&(evidence.provenance_id.as_bytes().len() as u32).to_le_bytes());
        output.extend_from_slice(&evidence.evidence_digest);
        output.extend_from_slice(evidence.evidence_id.as_bytes());
        output.extend_from_slice(evidence.provenance_id.as_bytes());
    }
    if output.len() > MAX_PAYLOAD_BYTES {
        return Err(TrustError::Invalid(format!(
            "encoded trust payload exceeds maximum {MAX_PAYLOAD_BYTES}"
        )));
    }
    Ok(output)
}

fn decode_payload(
    sequence: u64,
    logical_timestamp: u64,
    transition_id: [u8; 32],
    previous_transition_digest: [u8; 32],
    payload: &[u8],
) -> Result<TrustTransition> {
    const FIXED_BYTES: usize = 144;
    if payload.len() < FIXED_BYTES {
        return Err(TrustError::Invalid(
            "trust payload shorter than fixed header".to_string(),
        ));
    }
    if payload[0..8] != PAYLOAD_MAGIC {
        return Err(TrustError::Invalid(
            "trust payload magic mismatch".to_string(),
        ));
    }
    let operation = TrustOperation::from_code(payload[8])?;
    let authority = TransitionAuthority::from_code(payload[9])?;
    let previous_state = decode_optional_state(payload[10], payload[11])?;
    let next_state = TrustState {
        maturity: MaturityState::from_code(payload[12])?,
        validity: ValidityState::from_code(payload[13])?,
    };
    if read_u16(payload, 14)? != 0 {
        return Err(TrustError::Invalid(
            "trust payload reserved u16 is non-zero".to_string(),
        ));
    }
    let record_id_bytes = read_u32(payload, 16)? as usize;
    let policy_id_bytes = read_u32(payload, 20)? as usize;
    let policy_version_bytes = read_u32(payload, 24)? as usize;
    let verifier_id_bytes = read_u32(payload, 28)? as usize;
    let reason_code_bytes = read_u32(payload, 32)? as usize;
    let superseding_bytes = read_u32(payload, 36)? as usize;
    let evidence_count = read_u32(payload, 40)? as usize;
    if read_u32(payload, 44)? != 0 {
        return Err(TrustError::Invalid(
            "trust payload reserved u32 is non-zero".to_string(),
        ));
    }
    if evidence_count > MAX_EVIDENCE_REFS {
        return Err(TrustError::Invalid(
            "trust payload evidence count exceeds maximum".to_string(),
        ));
    }
    let record_digest = read_digest(payload, 48)?;
    let input_digest = read_digest(payload, 80)?;
    let decision_digest = read_digest(payload, 112)?;
    let mut cursor = FIXED_BYTES;
    let record_id = read_string(payload, &mut cursor, record_id_bytes, "record_id")?;
    let policy_id = read_string(payload, &mut cursor, policy_id_bytes, "policy_id")?;
    let policy_version = read_string(
        payload,
        &mut cursor,
        policy_version_bytes,
        "policy_version",
    )?;
    let verifier_id = read_string(payload, &mut cursor, verifier_id_bytes, "verifier_id")?;
    let reason_code = read_string(payload, &mut cursor, reason_code_bytes, "reason_code")?;
    let superseding_value = read_string(
        payload,
        &mut cursor,
        superseding_bytes,
        "superseding_record_id",
    )?;
    let superseding_record_id = if superseding_value.is_empty() {
        None
    } else {
        Some(superseding_value)
    };
    let mut evidence_refs = Vec::with_capacity(evidence_count);
    for _ in 0..evidence_count {
        if cursor + 40 > payload.len() {
            return Err(TrustError::Invalid(
                "truncated evidence reference fixed fields".to_string(),
            ));
        }
        let evidence_id_bytes = read_u32(payload, cursor)? as usize;
        let provenance_id_bytes = read_u32(payload, cursor + 4)? as usize;
        let evidence_digest = read_digest(payload, cursor + 8)?;
        cursor += 40;
        let evidence_id = read_string(
            payload,
            &mut cursor,
            evidence_id_bytes,
            "evidence_id",
        )?;
        let provenance_id = read_string(
            payload,
            &mut cursor,
            provenance_id_bytes,
            "provenance_id",
        )?;
        evidence_refs.push(EvidenceRef {
            evidence_id,
            provenance_id,
            evidence_digest,
        });
    }
    if cursor != payload.len() {
        return Err(TrustError::Invalid(
            "trust payload contains trailing bytes".to_string(),
        ));
    }
    Ok(TrustTransition {
        sequence,
        logical_timestamp,
        transition_id,
        record_id,
        previous_state,
        next_state,
        operation,
        authority,
        evidence_refs,
        policy_id,
        policy_version,
        verifier_id,
        record_digest,
        input_digest,
        decision_digest,
        reason_code,
        superseding_record_id,
        previous_transition_digest,
    })
}

fn encode_frame(
    sequence: u64,
    logical_timestamp: u64,
    previous_digest: [u8; 32],
    payload_digest: [u8; 32],
    transition_digest: [u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(TrustError::Invalid(
            "trust frame payload exceeds maximum".to_string(),
        ));
    }
    let mut output = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    output.extend_from_slice(&LEDGER_MAGIC);
    output.extend_from_slice(&LEDGER_MAJOR.to_le_bytes());
    output.extend_from_slice(&LEDGER_MINOR.to_le_bytes());
    output.extend_from_slice(&(FRAME_HEADER_BYTES as u32).to_le_bytes());
    output.extend_from_slice(&sequence.to_le_bytes());
    output.extend_from_slice(&logical_timestamp.to_le_bytes());
    output.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    output.extend_from_slice(&previous_digest);
    output.extend_from_slice(&payload_digest);
    output.extend_from_slice(&transition_digest);
    output.extend_from_slice(&[0; 8]);
    debug_assert_eq!(output.len(), FRAME_HEADER_BYTES);
    output.extend_from_slice(payload);
    Ok(output)
}

fn apply_replayed_transition(
    states: &mut BTreeMap<String, RecordTrustSnapshot>,
    transition: &TrustTransition,
) -> Result<()> {
    match transition.operation {
        TrustOperation::Propose => {
            if states.contains_key(&transition.record_id) {
                return Err(TrustError::Invalid(format!(
                    "replay attempted duplicate PROPOSE for {}",
                    transition.record_id,
                )));
            }
            states.insert(
                transition.record_id.clone(),
                RecordTrustSnapshot {
                    record_id: transition.record_id.clone(),
                    state: transition.next_state,
                    record_digest: transition.record_digest,
                    last_transition_id: transition.transition_id,
                    last_sequence: transition.sequence,
                    superseding_record_id: transition.superseding_record_id.clone(),
                },
            );
        }
        _ => {
            let snapshot = states.get_mut(&transition.record_id).ok_or_else(|| {
                TrustError::Invalid(format!(
                    "replay missing record state for {}",
                    transition.record_id,
                ))
            })?;
            if snapshot.record_digest != transition.record_digest {
                return Err(TrustError::Invalid(
                    "replay record digest binding mismatch".to_string(),
                ));
            }
            snapshot.state = transition.next_state;
            snapshot.last_transition_id = transition.transition_id;
            snapshot.last_sequence = transition.sequence;
            snapshot.superseding_record_id = transition.superseding_record_id.clone();
        }
    }
    Ok(())
}

fn encode_optional_state(state: Option<TrustState>) -> (u8, u8) {
    match state {
        Some(value) => (value.maturity as u8, value.validity as u8),
        None => (0, 0),
    }
}

fn decode_optional_state(maturity: u8, validity: u8) -> Result<Option<TrustState>> {
    if maturity == 0 && validity == 0 {
        return Ok(None);
    }
    if maturity == 0 || validity == 0 {
        return Err(TrustError::Invalid(
            "partial previous trust state encoding".to_string(),
        ));
    }
    Ok(Some(TrustState {
        maturity: MaturityState::from_code(maturity)?,
        validity: ValidityState::from_code(validity)?,
    }))
}

fn push_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.as_bytes().len() as u32).to_le_bytes());
    output.extend_from_slice(value.as_bytes());
}

fn push_optional_string(output: &mut Vec<u8>, value: Option<&str>) {
    push_string(output, value.unwrap_or(""));
}

fn read_string(
    bytes: &[u8],
    cursor: &mut usize,
    length: usize,
    context: &str,
) -> Result<String> {
    if length > MAX_STRING_BYTES {
        return Err(TrustError::Invalid(format!(
            "{context} exceeds maximum byte length"
        )));
    }
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| TrustError::Invalid(format!(
            "{context} length overflow"
        )))?;
    let value = bytes.get(*cursor..end).ok_or_else(|| {
        TrustError::Invalid(format!("truncated {context}"))
    })?;
    *cursor = end;
    String::from_utf8(value.to_vec()).map_err(|_| {
        TrustError::Invalid(format!("{context} is not UTF-8"))
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let end = offset.checked_add(2).ok_or_else(|| {
        TrustError::Invalid("u16 offset overflow".to_string())
    })?;
    let value = bytes.get(offset..end).ok_or_else(|| {
        TrustError::Invalid("truncated u16".to_string())
    })?;
    Ok(u16::from_le_bytes(value.try_into().expect("checked u16")))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or_else(|| {
        TrustError::Invalid("u32 offset overflow".to_string())
    })?;
    let value = bytes.get(offset..end).ok_or_else(|| {
        TrustError::Invalid("truncated u32".to_string())
    })?;
    Ok(u32::from_le_bytes(value.try_into().expect("checked u32")))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let end = offset.checked_add(8).ok_or_else(|| {
        TrustError::Invalid("u64 offset overflow".to_string())
    })?;
    let value = bytes.get(offset..end).ok_or_else(|| {
        TrustError::Invalid("truncated u64".to_string())
    })?;
    Ok(u64::from_le_bytes(value.try_into().expect("checked u64")))
}

fn read_digest(bytes: &[u8], offset: usize) -> Result<[u8; 32]> {
    let end = offset.checked_add(32).ok_or_else(|| {
        TrustError::Invalid("digest offset overflow".to_string())
    })?;
    let value = bytes.get(offset..end).ok_or_else(|| {
        TrustError::Invalid("truncated digest".to_string())
    })?;
    Ok(value.try_into().expect("checked digest"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn path(name: &str) -> PathBuf {
        let value = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "ultraballoondb-trust-{name}-{}-{value}.ubtrust",
            std::process::id()
        ))
    }

    fn digest(value: &str) -> [u8; 32] {
        sha256(value.as_bytes())
    }

    fn evidence(id: &str) -> EvidenceRef {
        EvidenceRef {
            evidence_id: id.to_string(),
            provenance_id: format!("provenance-{id}"),
            evidence_digest: digest(id),
        }
    }

    fn intent(
        record_id: &str,
        operation: TrustOperation,
        authority: TransitionAuthority,
        timestamp: u64,
    ) -> TransitionIntent {
        TransitionIntent {
            record_id: record_id.to_string(),
            operation,
            authority,
            evidence_refs: vec![evidence(&format!("evidence-{timestamp}"))],
            policy_id: "policy-main".to_string(),
            policy_version: "1".to_string(),
            verifier_id: "verifier-test".to_string(),
            record_digest: digest(record_id),
            logical_timestamp: timestamp,
            reason_code: format!("REASON_{timestamp}"),
            superseding_record_id: None,
        }
    }

    #[test]
    fn promotion_is_one_step_and_evidence_only() {
        let ledger_path = path("promotion");
        let mut ledger = TrustLedger::create(&ledger_path).unwrap();
        ledger
            .apply(intent(
                "record-a",
                TrustOperation::Propose,
                TransitionAuthority::Import,
                1,
            ))
            .unwrap();

        let before = fs::metadata(&ledger_path).unwrap().len();
        for authority in [
            TransitionAuthority::Import,
            TransitionAuthority::Ranker,
            TransitionAuthority::Wave,
            TransitionAuthority::Similarity,
            TransitionAuthority::Frequency,
            TransitionAuthority::Llm,
            TransitionAuthority::RigorMultiplier,
        ] {
            assert!(ledger
                .apply(intent(
                    "record-a",
                    TrustOperation::Promote,
                    authority,
                    ledger.last_timestamp() + 1,
                ))
                .is_err());
        }
        assert_eq!(fs::metadata(&ledger_path).unwrap().len(), before);
        assert_eq!(ledger.transition_count(), 1);

        ledger
            .apply(intent(
                "record-a",
                TrustOperation::Promote,
                TransitionAuthority::EvidencePolicy,
                100,
            ))
            .unwrap();
        assert_eq!(
            ledger.snapshot("record-a").unwrap().state,
            TrustState {
                maturity: MaturityState::Hypothesis,
                validity: ValidityState::Active,
            }
        );
        fs::remove_file(ledger_path).unwrap();
    }

    #[test]
    fn invalid_evidence_and_record_digest_are_rejected() {
        let ledger_path = path("evidence");
        let mut ledger = TrustLedger::create(&ledger_path).unwrap();
        let mut invalid = intent(
            "record-a",
            TrustOperation::Propose,
            TransitionAuthority::Import,
            1,
        );
        invalid.evidence_refs.clear();
        assert!(ledger.apply(invalid).is_err());

        ledger
            .apply(intent(
                "record-a",
                TrustOperation::Propose,
                TransitionAuthority::Import,
                2,
            ))
            .unwrap();
        let mut wrong_digest = intent(
            "record-a",
            TrustOperation::Promote,
            TransitionAuthority::EvidencePolicy,
            3,
        );
        wrong_digest.record_digest = digest("other-record");
        assert!(ledger.apply(wrong_digest).is_err());
        fs::remove_file(ledger_path).unwrap();
    }

    #[test]
    fn revocation_preserves_append_only_history_and_restart() {
        let ledger_path = path("history");
        let mut ledger = TrustLedger::create(&ledger_path).unwrap();
        ledger
            .apply(intent(
                "record-a",
                TrustOperation::Propose,
                TransitionAuthority::Import,
                1,
            ))
            .unwrap();
        let prefix = fs::read(&ledger_path).unwrap();
        ledger
            .apply(intent(
                "record-a",
                TrustOperation::Revoke,
                TransitionAuthority::EvidencePolicy,
                2,
            ))
            .unwrap();
        let full = fs::read(&ledger_path).unwrap();
        assert!(full.starts_with(&prefix));
        assert!(full.len() > prefix.len());
        drop(ledger);

        let reopened = TrustLedger::open_strict(&ledger_path).unwrap();
        assert_eq!(reopened.transition_count(), 2);
        assert_eq!(
            reopened.snapshot("record-a").unwrap().state.validity,
            ValidityState::Revoked,
        );
        fs::remove_file(ledger_path).unwrap();
    }

    #[test]
    fn truncated_and_corrupted_ledgers_fail_closed() {
        let ledger_path = path("corrupt-source");
        let mut ledger = TrustLedger::create(&ledger_path).unwrap();
        ledger
            .apply(intent(
                "record-a",
                TrustOperation::Propose,
                TransitionAuthority::Import,
                1,
            ))
            .unwrap();
        let bytes = fs::read(&ledger_path).unwrap();

        let truncated_path = path("truncated");
        fs::write(&truncated_path, &bytes[..bytes.len() - 3]).unwrap();
        assert!(matches!(
            TrustLedger::open_strict(&truncated_path),
            Err(TrustError::TruncatedTail { .. })
        ));

        let corrupt_path = path("corrupt");
        let mut corrupt = bytes.clone();
        corrupt[FRAME_HEADER_BYTES + 20] ^= 0x55;
        fs::write(&corrupt_path, corrupt).unwrap();
        assert!(TrustLedger::open_strict(&corrupt_path).is_err());

        fs::remove_file(ledger_path).unwrap();
        fs::remove_file(truncated_path).unwrap();
        fs::remove_file(corrupt_path).unwrap();
    }

    #[test]
    fn supersede_requires_existing_non_terminal_record() {
        let ledger_path = path("supersede");
        let mut ledger = TrustLedger::create(&ledger_path).unwrap();
        ledger
            .apply(intent(
                "old",
                TrustOperation::Propose,
                TransitionAuthority::Import,
                1,
            ))
            .unwrap();
        let mut missing = intent(
            "old",
            TrustOperation::Supersede,
            TransitionAuthority::EvidencePolicy,
            2,
        );
        missing.superseding_record_id = Some("new".to_string());
        assert!(ledger.apply(missing).is_err());

        ledger
            .apply(intent(
                "new",
                TrustOperation::Propose,
                TransitionAuthority::Import,
                3,
            ))
            .unwrap();
        let mut accepted = intent(
            "old",
            TrustOperation::Supersede,
            TransitionAuthority::EvidencePolicy,
            4,
        );
        accepted.superseding_record_id = Some("new".to_string());
        ledger.apply(accepted).unwrap();
        assert_eq!(
            ledger.snapshot("old").unwrap().state.validity,
            ValidityState::Superseded,
        );
        fs::remove_file(ledger_path).unwrap();
    }
}
