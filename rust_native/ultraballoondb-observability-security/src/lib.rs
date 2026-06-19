#![deny(unsafe_code)]

use std::cell::RefCell;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ultraballoondb_daemon::{BackendHealth, DaemonBackend};
use ultraballoondb_storage::sha256;

pub const VERSION: &str = "V00R3E1_OBSERVABILITY_AND_SECURITY_R01";
pub const AUDIT_VERSION: u16 = 1;
pub const AUDIT_HEADER_BYTES: usize = 64;
pub const AUDIT_RECORD_BYTES: usize = 180;

const AUDIT_MAGIC: [u8; 8] = *b"UBE1AU1\0";
const RECORD_MAGIC: [u8; 8] = *b"UBE1EV1\0";
const GENESIS_DOMAIN: &[u8] = b"UBDB_E1_AUDIT_GENESIS_V1";
const EVENT_DOMAIN: &[u8] = b"UBDB_E1_AUDIT_EVENT_V1";
const REQUEST_DOMAIN: &[u8] = b"UBDB_E1_REQUEST_V1";
const RESPONSE_DOMAIN: &[u8] = b"UBDB_E1_RESPONSE_V1";

pub const REASON_OK: u16 = 0;
pub const REASON_REQUEST_TOO_LARGE: u16 = 1001;
pub const REASON_RESPONSE_TOO_LARGE: u16 = 1002;
pub const REASON_WRITE_DISABLED: u16 = 1003;
pub const REASON_BACKEND_ERROR: u16 = 2001;
pub const REASON_BACKEND_UNHEALTHY: u16 = 2002;
pub const REASON_AUDIT_UNAVAILABLE: u16 = 3001;

#[derive(Debug)]
pub enum OperationsError {
    Io(std::io::Error),
    Invalid(String),
    Integrity(String),
}

impl fmt::Display for OperationsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Invalid(message) => write!(formatter, "invalid operations configuration: {message}"),
            Self::Integrity(message) => write!(formatter, "operations integrity error: {message}"),
        }
    }
}

impl std::error::Error for OperationsError {}

impl From<std::io::Error> for OperationsError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, OperationsError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum OperationKind {
    Health = 1,
    Read = 2,
    Write = 3,
}

impl OperationKind {
    fn from_u16(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::Health),
            2 => Ok(Self::Read),
            3 => Ok(Self::Write),
            _ => Err(OperationsError::Integrity(format!(
                "unknown operation kind {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum OperationOutcome {
    Accepted = 1,
    Rejected = 2,
    BackendError = 3,
}

impl OperationOutcome {
    fn from_u16(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::Accepted),
            2 => Ok(Self::Rejected),
            3 => Ok(Self::BackendError),
            _ => Err(OperationsError::Integrity(format!(
                "unknown operation outcome {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityPolicy {
    pub allow_writes: bool,
    pub remote_network_enabled: bool,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_audit_events: u64,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            allow_writes: true,
            remote_network_enabled: false,
            max_request_bytes: 8 * 1024 * 1024,
            max_response_bytes: 8 * 1024 * 1024,
            max_audit_events: 1_000_000,
        }
    }
}

impl SecurityPolicy {
    pub fn validate(&self) -> Result<()> {
        const MAX_BYTES: usize = 256 * 1024 * 1024;
        if self.remote_network_enabled {
            return Err(OperationsError::Invalid(
                "remote network enablement is outside E1 and requires a later authentication/TLS gate"
                    .to_string(),
            ));
        }
        if self.max_request_bytes == 0 || self.max_request_bytes > MAX_BYTES {
            return Err(OperationsError::Invalid(
                "max_request_bytes outside bounded range".to_string(),
            ));
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > MAX_BYTES {
            return Err(OperationsError::Invalid(
                "max_response_bytes outside bounded range".to_string(),
            ));
        }
        if self.max_audit_events == 0 || self.max_audit_events > 10_000_000 {
            return Err(OperationsError::Invalid(
                "max_audit_events outside bounded range".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub total_operations: u64,
    pub accepted_operations: u64,
    pub rejected_operations: u64,
    pub backend_errors: u64,
    pub health_operations: u64,
    pub read_operations: u64,
    pub write_operations: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub audit_events: u64,
    pub audit_available: bool,
}

impl MetricsSnapshot {
    pub fn to_prometheus_text(&self) -> String {
        format!(
            concat!(
                "# TYPE ultraballoondb_operations_total counter\n",
                "ultraballoondb_operations_total {}\n",
                "# TYPE ultraballoondb_operations_accepted_total counter\n",
                "ultraballoondb_operations_accepted_total {}\n",
                "# TYPE ultraballoondb_operations_rejected_total counter\n",
                "ultraballoondb_operations_rejected_total {}\n",
                "# TYPE ultraballoondb_backend_errors_total counter\n",
                "ultraballoondb_backend_errors_total {}\n",
                "# TYPE ultraballoondb_health_operations_total counter\n",
                "ultraballoondb_health_operations_total {}\n",
                "# TYPE ultraballoondb_read_operations_total counter\n",
                "ultraballoondb_read_operations_total {}\n",
                "# TYPE ultraballoondb_write_operations_total counter\n",
                "ultraballoondb_write_operations_total {}\n",
                "# TYPE ultraballoondb_request_bytes_total counter\n",
                "ultraballoondb_request_bytes_total {}\n",
                "# TYPE ultraballoondb_response_bytes_total counter\n",
                "ultraballoondb_response_bytes_total {}\n",
                "# TYPE ultraballoondb_audit_events_total counter\n",
                "ultraballoondb_audit_events_total {}\n",
                "# TYPE ultraballoondb_audit_available gauge\n",
                "ultraballoondb_audit_available {}\n"
            ),
            self.total_operations,
            self.accepted_operations,
            self.rejected_operations,
            self.backend_errors,
            self.health_operations,
            self.read_operations,
            self.write_operations,
            self.request_bytes,
            self.response_bytes,
            self.audit_events,
            u8::from(self.audit_available),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    pub sequence: u64,
    pub logical_time: u64,
    pub operation: OperationKind,
    pub outcome: OperationOutcome,
    pub reason_code: u16,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub request_digest: [u8; 32],
    pub response_digest: [u8; 32],
    pub previous_digest: [u8; 32],
    pub event_digest: [u8; 32],
}

struct AuditWriter {
    file: File,
    next_sequence: u64,
    previous_digest: [u8; 32],
}

impl AuditWriter {
    fn create(path: &Path) -> Result<Self> {
        if path.exists() {
            return Err(OperationsError::Invalid(format!(
                "audit path already exists: {}",
                path.display()
            )));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .create_new(true)
            .open(path)?;
        let genesis = sha256(GENESIS_DOMAIN);
        let mut header = Vec::with_capacity(AUDIT_HEADER_BYTES);
        header.extend_from_slice(&AUDIT_MAGIC);
        put_u16(&mut header, AUDIT_VERSION);
        put_u16(&mut header, AUDIT_HEADER_BYTES as u16);
        put_u32(&mut header, AUDIT_RECORD_BYTES as u32);
        header.extend_from_slice(&genesis);
        header.extend_from_slice(&[0u8; 16]);
        debug_assert_eq!(header.len(), AUDIT_HEADER_BYTES);
        file.write_all(&header)?;
        file.sync_all()?;
        Ok(Self {
            file,
            next_sequence: 1,
            previous_digest: genesis,
        })
    }

    fn append(
        &mut self,
        logical_time: u64,
        operation: OperationKind,
        outcome: OperationOutcome,
        reason_code: u16,
        request: &[u8],
        response: &[u8],
    ) -> Result<AuditRecord> {
        if logical_time == 0 {
            return Err(OperationsError::Invalid(
                "logical_time must be non-zero".to_string(),
            ));
        }
        let sequence = self.next_sequence;
        let request_digest = payload_digest(REQUEST_DOMAIN, request);
        let response_digest = payload_digest(RESPONSE_DOMAIN, response);
        let request_bytes = request.len() as u64;
        let response_bytes = response.len() as u64;
        let event_digest = compute_event_digest(
            sequence,
            logical_time,
            operation,
            outcome,
            reason_code,
            request_bytes,
            response_bytes,
            &request_digest,
            &response_digest,
            &self.previous_digest,
        );
        let record = AuditRecord {
            sequence,
            logical_time,
            operation,
            outcome,
            reason_code,
            request_bytes,
            response_bytes,
            request_digest,
            response_digest,
            previous_digest: self.previous_digest,
            event_digest,
        };
        let bytes = encode_record(&record);
        self.file.write_all(&bytes)?;
        self.file.flush()?;
        self.file.sync_data()?;
        self.previous_digest = event_digest;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| OperationsError::Invalid("audit sequence overflow".to_string()))?;
        Ok(record)
    }
}

struct OperationalState {
    metrics: MetricsSnapshot,
    audit: AuditWriter,
    next_logical_time: u64,
    audit_failed: bool,
}

pub struct ObservedBackend<B: DaemonBackend> {
    backend: B,
    policy: SecurityPolicy,
    state: RefCell<OperationalState>,
    audit_path: PathBuf,
}

impl<B: DaemonBackend> ObservedBackend<B> {
    pub fn new(backend: B, policy: SecurityPolicy, audit_path: impl AsRef<Path>) -> Result<Self> {
        policy.validate()?;
        let audit_path = audit_path.as_ref().to_path_buf();
        let audit = AuditWriter::create(&audit_path)?;
        Ok(Self {
            backend,
            policy,
            state: RefCell::new(OperationalState {
                metrics: MetricsSnapshot {
                    audit_available: true,
                    ..MetricsSnapshot::default()
                },
                audit,
                next_logical_time: 1,
                audit_failed: false,
            }),
            audit_path,
        })
    }

    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        self.state.borrow().metrics.clone()
    }

    pub fn export_prometheus(&self) -> String {
        self.metrics_snapshot().to_prometheus_text()
    }

    pub fn audit_path(&self) -> &Path {
        &self.audit_path
    }

    pub fn audit_available(&self) -> bool {
        !self.state.borrow().audit_failed
    }

    fn record(
        &self,
        operation: OperationKind,
        outcome: OperationOutcome,
        reason_code: u16,
        request: &[u8],
        response: &[u8],
    ) -> Result<()> {
        let mut state = self.state.borrow_mut();
        if state.audit_failed {
            return Err(OperationsError::Integrity(
                "audit is unavailable".to_string(),
            ));
        }
        if state.metrics.audit_events >= self.policy.max_audit_events {
            state.audit_failed = true;
            state.metrics.audit_available = false;
            return Err(OperationsError::Integrity(
                "audit event budget exhausted".to_string(),
            ));
        }
        let logical_time = state.next_logical_time;
        match state
            .audit
            .append(logical_time, operation, outcome, reason_code, request, response)
        {
            Ok(_) => {
                state.next_logical_time = state
                    .next_logical_time
                    .checked_add(1)
                    .ok_or_else(|| OperationsError::Integrity("logical time overflow".to_string()))?;
                state.metrics.total_operations = state.metrics.total_operations.saturating_add(1);
                state.metrics.audit_events = state.metrics.audit_events.saturating_add(1);
                state.metrics.request_bytes = state
                    .metrics
                    .request_bytes
                    .saturating_add(request.len() as u64);
                state.metrics.response_bytes = state
                    .metrics
                    .response_bytes
                    .saturating_add(response.len() as u64);
                match operation {
                    OperationKind::Health => {
                        state.metrics.health_operations =
                            state.metrics.health_operations.saturating_add(1)
                    }
                    OperationKind::Read => {
                        state.metrics.read_operations =
                            state.metrics.read_operations.saturating_add(1)
                    }
                    OperationKind::Write => {
                        state.metrics.write_operations =
                            state.metrics.write_operations.saturating_add(1)
                    }
                }
                match outcome {
                    OperationOutcome::Accepted => {
                        state.metrics.accepted_operations =
                            state.metrics.accepted_operations.saturating_add(1)
                    }
                    OperationOutcome::Rejected => {
                        state.metrics.rejected_operations =
                            state.metrics.rejected_operations.saturating_add(1)
                    }
                    OperationOutcome::BackendError => {
                        state.metrics.backend_errors =
                            state.metrics.backend_errors.saturating_add(1)
                    }
                }
                Ok(())
            }
            Err(error) => {
                state.audit_failed = true;
                state.metrics.audit_available = false;
                Err(error)
            }
        }
    }

    fn reject(
        &self,
        operation: OperationKind,
        reason_code: u16,
        request: &[u8],
        message: &'static str,
    ) -> std::result::Result<Vec<u8>, String> {
        if self
            .record(
                operation,
                OperationOutcome::Rejected,
                reason_code,
                request,
                &[],
            )
            .is_err()
        {
            return Err("E1_AUDIT_UNAVAILABLE".to_string());
        }
        Err(message.to_string())
    }

    fn execute_operation<F>(
        &mut self,
        operation: OperationKind,
        request: &[u8],
        callback: F,
    ) -> std::result::Result<Vec<u8>, String>
    where
        F: FnOnce(&mut B, &[u8]) -> std::result::Result<Vec<u8>, String>,
    {
        if !self.audit_available() {
            return Err("E1_AUDIT_UNAVAILABLE".to_string());
        }
        if request.len() > self.policy.max_request_bytes {
            return self.reject(
                operation,
                REASON_REQUEST_TOO_LARGE,
                request,
                "E1_REQUEST_TOO_LARGE",
            );
        }
        if operation == OperationKind::Write && !self.policy.allow_writes {
            return self.reject(
                operation,
                REASON_WRITE_DISABLED,
                request,
                "E1_WRITE_DISABLED",
            );
        }
        match callback(&mut self.backend, request) {
            Ok(response) => {
                if response.len() > self.policy.max_response_bytes {
                    return self.reject(
                        operation,
                        REASON_RESPONSE_TOO_LARGE,
                        request,
                        "E1_RESPONSE_TOO_LARGE",
                    );
                }
                if self
                    .record(
                        operation,
                        OperationOutcome::Accepted,
                        REASON_OK,
                        request,
                        &response,
                    )
                    .is_err()
                {
                    return Err("E1_AUDIT_UNAVAILABLE".to_string());
                }
                Ok(response)
            }
            Err(_backend_error) => {
                if self
                    .record(
                        operation,
                        OperationOutcome::BackendError,
                        REASON_BACKEND_ERROR,
                        request,
                        &[],
                    )
                    .is_err()
                {
                    return Err("E1_AUDIT_UNAVAILABLE".to_string());
                }
                Err("E1_BACKEND_ERROR".to_string())
            }
        }
    }
}

impl<B: DaemonBackend> DaemonBackend for ObservedBackend<B> {
    fn health(&self) -> BackendHealth {
        if !self.audit_available() {
            return BackendHealth {
                healthy: false,
                read_only: true,
                generation: 0,
            };
        }
        let health = self.backend.health();
        let outcome = if health.healthy {
            OperationOutcome::Accepted
        } else {
            OperationOutcome::BackendError
        };
        let reason_code = if health.healthy {
            REASON_OK
        } else {
            REASON_BACKEND_UNHEALTHY
        };
        if self
            .record(OperationKind::Health, outcome, reason_code, &[], &[])
            .is_err()
        {
            return BackendHealth {
                healthy: false,
                read_only: true,
                generation: health.generation,
            };
        }
        health
    }

    fn execute_read(&mut self, request: &[u8]) -> std::result::Result<Vec<u8>, String> {
        self.execute_operation(OperationKind::Read, request, |backend, bytes| {
            backend.execute_read(bytes)
        })
    }

    fn execute_write(&mut self, request: &[u8]) -> std::result::Result<Vec<u8>, String> {
        self.execute_operation(OperationKind::Write, request, |backend, bytes| {
            backend.execute_write(bytes)
        })
    }
}

pub fn strict_replay(path: impl AsRef<Path>) -> Result<Vec<AuditRecord>> {
    let mut bytes = Vec::new();
    File::open(path.as_ref())?.read_to_end(&mut bytes)?;
    if bytes.len() < AUDIT_HEADER_BYTES {
        return Err(OperationsError::Integrity(
            "truncated audit header".to_string(),
        ));
    }
    if &bytes[0..8] != AUDIT_MAGIC.as_slice() {
        return Err(OperationsError::Integrity(
            "audit magic mismatch".to_string(),
        ));
    }
    if get_u16(&bytes, 8)? != AUDIT_VERSION {
        return Err(OperationsError::Integrity(
            "unsupported audit version".to_string(),
        ));
    }
    if get_u16(&bytes, 10)? as usize != AUDIT_HEADER_BYTES {
        return Err(OperationsError::Integrity(
            "audit header size mismatch".to_string(),
        ));
    }
    if get_u32(&bytes, 12)? as usize != AUDIT_RECORD_BYTES {
        return Err(OperationsError::Integrity(
            "audit record size mismatch".to_string(),
        ));
    }
    let genesis = sha256(GENESIS_DOMAIN);
    if &bytes[16..48] != genesis.as_slice() {
        return Err(OperationsError::Integrity(
            "audit genesis digest mismatch".to_string(),
        ));
    }
    if bytes[48..64].iter().any(|value| *value != 0) {
        return Err(OperationsError::Integrity(
            "non-zero audit header reserved bytes".to_string(),
        ));
    }
    let remainder = bytes.len() - AUDIT_HEADER_BYTES;
    if remainder % AUDIT_RECORD_BYTES != 0 {
        return Err(OperationsError::Integrity(
            "truncated or trailing audit bytes".to_string(),
        ));
    }
    let mut records = Vec::new();
    let mut previous = genesis;
    let mut expected_sequence = 1u64;
    let mut previous_logical_time = 0u64;
    for chunk in bytes[AUDIT_HEADER_BYTES..].chunks_exact(AUDIT_RECORD_BYTES) {
        let record = decode_record(chunk)?;
        if record.sequence != expected_sequence {
            return Err(OperationsError::Integrity(
                "audit sequence is not contiguous".to_string(),
            ));
        }
        if record.logical_time <= previous_logical_time {
            return Err(OperationsError::Integrity(
                "audit logical time is not strictly increasing".to_string(),
            ));
        }
        if record.previous_digest != previous {
            return Err(OperationsError::Integrity(
                "audit previous digest mismatch".to_string(),
            ));
        }
        let expected_digest = compute_event_digest(
            record.sequence,
            record.logical_time,
            record.operation,
            record.outcome,
            record.reason_code,
            record.request_bytes,
            record.response_bytes,
            &record.request_digest,
            &record.response_digest,
            &record.previous_digest,
        );
        if record.event_digest != expected_digest {
            return Err(OperationsError::Integrity(
                "audit event digest mismatch".to_string(),
            ));
        }
        previous = record.event_digest;
        previous_logical_time = record.logical_time;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| OperationsError::Integrity("audit sequence overflow".to_string()))?;
        records.push(record);
    }
    Ok(records)
}

fn payload_digest(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(domain.len() + 8 + payload.len());
    bytes.extend_from_slice(domain);
    put_u64(&mut bytes, payload.len() as u64);
    bytes.extend_from_slice(payload);
    sha256(&bytes)
}

#[allow(clippy::too_many_arguments)]
fn compute_event_digest(
    sequence: u64,
    logical_time: u64,
    operation: OperationKind,
    outcome: OperationOutcome,
    reason_code: u16,
    request_bytes: u64,
    response_bytes: u64,
    request_digest: &[u8; 32],
    response_digest: &[u8; 32],
    previous_digest: &[u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(EVENT_DOMAIN);
    put_u16(&mut bytes, AUDIT_VERSION);
    put_u64(&mut bytes, sequence);
    put_u64(&mut bytes, logical_time);
    put_u16(&mut bytes, operation as u16);
    put_u16(&mut bytes, outcome as u16);
    put_u16(&mut bytes, reason_code);
    put_u64(&mut bytes, request_bytes);
    put_u64(&mut bytes, response_bytes);
    bytes.extend_from_slice(request_digest);
    bytes.extend_from_slice(response_digest);
    bytes.extend_from_slice(previous_digest);
    sha256(&bytes)
}

fn encode_record(record: &AuditRecord) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(AUDIT_RECORD_BYTES);
    bytes.extend_from_slice(&RECORD_MAGIC);
    put_u16(&mut bytes, AUDIT_VERSION);
    put_u16(&mut bytes, AUDIT_RECORD_BYTES as u16);
    put_u64(&mut bytes, record.sequence);
    put_u64(&mut bytes, record.logical_time);
    put_u16(&mut bytes, record.operation as u16);
    put_u16(&mut bytes, record.outcome as u16);
    put_u16(&mut bytes, record.reason_code);
    put_u16(&mut bytes, 0);
    put_u64(&mut bytes, record.request_bytes);
    put_u64(&mut bytes, record.response_bytes);
    bytes.extend_from_slice(&record.request_digest);
    bytes.extend_from_slice(&record.response_digest);
    bytes.extend_from_slice(&record.previous_digest);
    bytes.extend_from_slice(&record.event_digest);
    debug_assert_eq!(bytes.len(), AUDIT_RECORD_BYTES);
    bytes
}

fn decode_record(bytes: &[u8]) -> Result<AuditRecord> {
    if bytes.len() != AUDIT_RECORD_BYTES {
        return Err(OperationsError::Integrity(
            "audit record length mismatch".to_string(),
        ));
    }
    if &bytes[0..8] != RECORD_MAGIC.as_slice() {
        return Err(OperationsError::Integrity(
            "audit record magic mismatch".to_string(),
        ));
    }
    if get_u16(bytes, 8)? != AUDIT_VERSION {
        return Err(OperationsError::Integrity(
            "audit record version mismatch".to_string(),
        ));
    }
    if get_u16(bytes, 10)? as usize != AUDIT_RECORD_BYTES {
        return Err(OperationsError::Integrity(
            "audit record size field mismatch".to_string(),
        ));
    }
    if get_u16(bytes, 34)? != 0 {
        return Err(OperationsError::Integrity(
            "non-zero audit record reserved field".to_string(),
        ));
    }
    Ok(AuditRecord {
        sequence: get_u64(bytes, 12)?,
        logical_time: get_u64(bytes, 20)?,
        operation: OperationKind::from_u16(get_u16(bytes, 28)?)?,
        outcome: OperationOutcome::from_u16(get_u16(bytes, 30)?)?,
        reason_code: get_u16(bytes, 32)?,
        request_bytes: get_u64(bytes, 36)?,
        response_bytes: get_u64(bytes, 44)?,
        request_digest: array_32(bytes, 52)?,
        response_digest: array_32(bytes, 84)?,
        previous_digest: array_32(bytes, 116)?,
        event_digest: array_32(bytes, 148)?,
    })
}

fn array_32(bytes: &[u8], offset: usize) -> Result<[u8; 32]> {
    let end = offset
        .checked_add(32)
        .ok_or_else(|| OperationsError::Integrity("audit offset overflow".to_string()))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| OperationsError::Integrity("truncated audit digest".to_string()))?;
    let mut value = [0u8; 32];
    value.copy_from_slice(slice);
    Ok(value)
}

fn get_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| OperationsError::Integrity("truncated u16".to_string()))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn get_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| OperationsError::Integrity("truncated u32".to_string()))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn get_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let slice = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| OperationsError::Integrity("truncated u64".to_string()))?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestBackend;

    impl DaemonBackend for TestBackend {
        fn health(&self) -> BackendHealth {
            BackendHealth {
                healthy: true,
                read_only: false,
                generation: 7,
            }
        }

        fn execute_read(&mut self, request: &[u8]) -> std::result::Result<Vec<u8>, String> {
            if request == b"FAIL" {
                Err("backend-secret-error".to_string())
            } else {
                Ok(b"private-response-value".to_vec())
            }
        }

        fn execute_write(&mut self, _request: &[u8]) -> std::result::Result<Vec<u8>, String> {
            Ok(b"write-ok".to_vec())
        }
    }

    fn temporary_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ultraballoondb_e1_{}_{}_{}",
            name,
            std::process::id(),
            nanos
        ))
    }

    #[test]
    fn policy_rejects_remote_and_unbounded_configuration() {
        let mut policy = SecurityPolicy::default();
        policy.remote_network_enabled = true;
        assert!(policy.validate().is_err());
        policy.remote_network_enabled = false;
        policy.max_request_bytes = 0;
        assert!(policy.validate().is_err());
        policy.max_request_bytes = 1;
        policy.max_response_bytes = 0;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn wrapper_records_bounded_metrics_without_raw_payloads() {
        let path = temporary_path("wrapper");
        let policy = SecurityPolicy {
            allow_writes: true,
            remote_network_enabled: false,
            max_request_bytes: 32,
            max_response_bytes: 64,
            max_audit_events: 32,
        };
        let mut backend = ObservedBackend::new(TestBackend, policy, &path).expect("create wrapper");
        assert!(backend.health().healthy);
        assert_eq!(
            backend
                .execute_read(b"customer-secret-token")
                .expect("read")
                .as_slice(),
            b"private-response-value"
        );
        assert_eq!(
            backend.execute_write(b"write-secret").expect("write").as_slice(),
            b"write-ok"
        );
        assert_eq!(
            backend.execute_read(&[7u8; 33]).expect_err("oversized request"),
            "E1_REQUEST_TOO_LARGE"
        );
        assert_eq!(
            backend.execute_read(b"FAIL").expect_err("backend error"),
            "E1_BACKEND_ERROR"
        );
        let metrics = backend.metrics_snapshot();
        assert_eq!(metrics.total_operations, 5);
        assert_eq!(metrics.accepted_operations, 3);
        assert_eq!(metrics.rejected_operations, 1);
        assert_eq!(metrics.backend_errors, 1);
        assert_eq!(metrics.health_operations, 1);
        assert_eq!(metrics.read_operations, 3);
        assert_eq!(metrics.write_operations, 1);
        assert!(metrics.audit_available);
        let text = backend.export_prometheus();
        assert!(!text.contains("customer-secret-token"));
        assert!(!text.contains("private-response-value"));
        drop(backend);
        let raw = std::fs::read(&path).expect("read audit");
        assert!(!raw.windows(b"customer-secret-token".len()).any(|w| w == b"customer-secret-token"));
        assert!(!raw.windows(b"private-response-value".len()).any(|w| w == b"private-response-value"));
        let records = strict_replay(&path).expect("strict replay");
        assert_eq!(records.len(), 5);
        std::fs::remove_file(path).expect("remove audit");
    }


    #[test]
    fn audit_budget_exhaustion_fails_closed() {
        let path = temporary_path("budget");
        let policy = SecurityPolicy {
            max_request_bytes: 64,
            max_response_bytes: 64,
            max_audit_events: 1,
            ..SecurityPolicy::default()
        };
        let mut backend = ObservedBackend::new(TestBackend, policy, &path).expect("create wrapper");
        backend.execute_read(b"first").expect("first read");
        assert_eq!(
            backend.execute_read(b"second").expect_err("audit budget must fail closed"),
            "E1_AUDIT_UNAVAILABLE"
        );
        assert!(!backend.audit_available());
        assert!(!backend.metrics_snapshot().audit_available);
        drop(backend);
        assert_eq!(strict_replay(&path).expect("replay").len(), 1);
        std::fs::remove_file(path).expect("remove audit");
    }

    #[test]
    fn strict_replay_rejects_tamper_and_truncation() {
        let path = temporary_path("replay");
        let policy = SecurityPolicy {
            max_request_bytes: 64,
            max_response_bytes: 64,
            max_audit_events: 8,
            ..SecurityPolicy::default()
        };
        let mut backend = ObservedBackend::new(TestBackend, policy, &path).expect("create wrapper");
        backend.execute_read(b"hello").expect("read");
        drop(backend);
        assert_eq!(strict_replay(&path).expect("replay").len(), 1);
        let original = std::fs::read(&path).expect("read audit");
        let tampered = temporary_path("tampered");
        let mut tampered_bytes = original.clone();
        tampered_bytes[AUDIT_HEADER_BYTES + 60] ^= 0x01;
        std::fs::write(&tampered, tampered_bytes).expect("write tamper");
        assert!(strict_replay(&tampered).is_err());
        let truncated = temporary_path("truncated");
        std::fs::write(&truncated, &original[..original.len() - 1]).expect("write truncated");
        assert!(strict_replay(&truncated).is_err());
        std::fs::remove_file(path).expect("remove audit");
        std::fs::remove_file(tampered).expect("remove tamper");
        std::fs::remove_file(truncated).expect("remove truncated");
    }
}
