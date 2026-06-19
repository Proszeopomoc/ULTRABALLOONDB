use std::collections::BTreeSet;
use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use ultraballoondb_storage::sha256;

pub const VERSION: &str = "V00R3D2_DAEMON_AND_PROTOCOL_CORE_R02";
pub const PROTOCOL_VERSION: u16 = 1;
pub const HEADER_BYTES: usize = 64;
pub const LENGTH_PREFIX_BYTES: usize = 4;
pub const DEFAULT_MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;
pub const DEFAULT_MAX_REQUESTS_PER_CONNECTION: u32 = 4096;
pub const DEFAULT_MAX_READ_PAYLOAD_BYTES: u32 = 8 * 1024 * 1024;
pub const DEFAULT_MAX_WRITE_PAYLOAD_BYTES: u32 = 8 * 1024 * 1024;
pub const DEFAULT_IO_TIMEOUT_MILLIS: u64 = 30_000;

const FRAME_MAGIC: [u8; 8] = *b"UBDPR01\0";
const FRAME_DOMAIN: [u8; 8] = *b"UBDPDG01";
const CAP_READ: u64 = 1 << 0;
const CAP_WRITE: u64 = 1 << 1;
const CAP_HEALTH: u64 = 1 << 2;
const CAP_LOOPBACK_ONLY: u64 = 1 << 3;

#[derive(Debug)]
pub enum DaemonError {
    Io(std::io::Error),
    Invalid(String),
    Protocol(String),
    Backend(String),
    Closed,
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Invalid(message) => write!(f, "invalid daemon configuration: {message}"),
            Self::Protocol(message) => write!(f, "protocol error: {message}"),
            Self::Backend(message) => write!(f, "backend error: {message}"),
            Self::Closed => write!(f, "session already closed"),
        }
    }
}
impl std::error::Error for DaemonError {}
impl From<std::io::Error> for DaemonError {
    fn from(value: std::io::Error) -> Self { Self::Io(value) }
}
pub type Result<T> = std::result::Result<T, DaemonError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum FrameKind {
    Hello = 1,
    Ping = 2,
    Health = 3,
    Capabilities = 4,
    Read = 5,
    Write = 6,
    Close = 7,
    HelloAck = 0x8001,
    Pong = 0x8002,
    HealthResult = 0x8003,
    CapabilitiesResult = 0x8004,
    Result = 0x8005,
    Error = 0x8FFE,
    CloseAck = 0x8FFF,
}
impl FrameKind {
    pub fn from_u16(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::Hello), 2 => Ok(Self::Ping), 3 => Ok(Self::Health),
            4 => Ok(Self::Capabilities), 5 => Ok(Self::Read), 6 => Ok(Self::Write),
            7 => Ok(Self::Close), 0x8001 => Ok(Self::HelloAck), 0x8002 => Ok(Self::Pong),
            0x8003 => Ok(Self::HealthResult), 0x8004 => Ok(Self::CapabilitiesResult),
            0x8005 => Ok(Self::Result), 0x8FFE => Ok(Self::Error), 0x8FFF => Ok(Self::CloseAck),
            _ => Err(DaemonError::Protocol(format!("unknown frame kind {value}"))),
        }
    }
    pub fn is_request(self) -> bool { (self as u16) < 0x8000 }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    pub flags: u16,
    pub request_id: u64,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(kind: FrameKind, request_id: u64, payload: Vec<u8>) -> Self {
        Self { kind, flags: 0, request_id, payload }
    }
    pub fn encode(&self, max_frame_bytes: u32) -> Result<Vec<u8>> {
        if self.request_id == 0 { return Err(DaemonError::Protocol("request_id must be non-zero".to_string())); }
        if self.payload.len() > u32::MAX as usize { return Err(DaemonError::Protocol("payload too large".to_string())); }
        let total = HEADER_BYTES.checked_add(self.payload.len()).ok_or_else(|| DaemonError::Protocol("frame length overflow".to_string()))?;
        if total > max_frame_bytes as usize { return Err(DaemonError::Protocol("frame exceeds configured maximum".to_string())); }
        let mut header = Vec::with_capacity(HEADER_BYTES);
        header.extend_from_slice(&FRAME_MAGIC);
        put_u16(&mut header, PROTOCOL_VERSION);
        put_u16(&mut header, self.kind as u16);
        put_u16(&mut header, self.flags);
        put_u16(&mut header, 0);
        put_u64(&mut header, self.request_id);
        put_u32(&mut header, self.payload.len() as u32);
        put_u32(&mut header, 0);
        let digest = frame_digest(PROTOCOL_VERSION, self.kind as u16, self.flags, self.request_id, &self.payload);
        header.extend_from_slice(&digest);
        debug_assert_eq!(header.len(), HEADER_BYTES);
        header.extend_from_slice(&self.payload);
        Ok(header)
    }
    pub fn decode(bytes: &[u8], max_frame_bytes: u32) -> Result<Self> {
        if bytes.len() < HEADER_BYTES { return Err(DaemonError::Protocol("truncated frame header".to_string())); }
        if bytes.len() > max_frame_bytes as usize { return Err(DaemonError::Protocol("frame exceeds configured maximum".to_string())); }
        if bytes[..8] != FRAME_MAGIC { return Err(DaemonError::Protocol("frame magic mismatch".to_string())); }
        let version = get_u16(bytes, 8)?;
        if version != PROTOCOL_VERSION { return Err(DaemonError::Protocol(format!("unsupported protocol version {version}"))); }
        let kind_raw = get_u16(bytes, 10)?;
        let kind = FrameKind::from_u16(kind_raw)?;
        let flags = get_u16(bytes, 12)?;
        if get_u16(bytes, 14)? != 0 || get_u32(bytes, 28)? != 0 { return Err(DaemonError::Protocol("reserved frame bits are non-zero".to_string())); }
        let request_id = get_u64(bytes, 16)?;
        if request_id == 0 { return Err(DaemonError::Protocol("request_id must be non-zero".to_string())); }
        let payload_len = get_u32(bytes, 24)? as usize;
        let expected = HEADER_BYTES.checked_add(payload_len).ok_or_else(|| DaemonError::Protocol("frame length overflow".to_string()))?;
        if bytes.len() != expected { return Err(DaemonError::Protocol("frame length mismatch".to_string())); }
        let payload = bytes[HEADER_BYTES..].to_vec();
        let expected_digest = frame_digest(version, kind_raw, flags, request_id, &payload);
        if bytes[32..64] != expected_digest { return Err(DaemonError::Protocol("frame digest mismatch".to_string())); }
        Ok(Self { kind, flags, request_id, payload })
    }
}

#[derive(Clone, Debug)]
pub struct ProtocolConfig {
    pub max_frame_bytes: u32,
    pub max_requests_per_connection: u32,
    pub max_read_payload_bytes: u32,
    pub max_write_payload_bytes: u32,
    pub io_timeout_millis: u64,
    pub loopback_only: bool,
}
impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_requests_per_connection: DEFAULT_MAX_REQUESTS_PER_CONNECTION,
            max_read_payload_bytes: DEFAULT_MAX_READ_PAYLOAD_BYTES,
            max_write_payload_bytes: DEFAULT_MAX_WRITE_PAYLOAD_BYTES,
            io_timeout_millis: DEFAULT_IO_TIMEOUT_MILLIS,
            loopback_only: true,
        }
    }
}
impl ProtocolConfig {
    pub fn validate(&self) -> Result<()> {
        if self.max_frame_bytes < HEADER_BYTES as u32 || self.max_frame_bytes > 256 * 1024 * 1024 { return Err(DaemonError::Invalid("max_frame_bytes outside bounded range".to_string())); }
        if self.max_requests_per_connection == 0 || self.max_requests_per_connection > 1_000_000 { return Err(DaemonError::Invalid("max_requests_per_connection outside bounded range".to_string())); }
        let payload_limit = self.max_frame_bytes - HEADER_BYTES as u32;
        if self.max_read_payload_bytes > payload_limit || self.max_write_payload_bytes > payload_limit { return Err(DaemonError::Invalid("payload limit exceeds frame capacity".to_string())); }
        if self.io_timeout_millis == 0 || self.io_timeout_millis > 24 * 60 * 60 * 1000 { return Err(DaemonError::Invalid("I/O timeout outside bounded range".to_string())); }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendHealth {
    pub healthy: bool,
    pub read_only: bool,
    pub generation: u64,
}

pub trait DaemonBackend {
    fn health(&self) -> BackendHealth;
    fn execute_read(&mut self, request: &[u8]) -> std::result::Result<Vec<u8>, String>;
    fn execute_write(&mut self, request: &[u8]) -> std::result::Result<Vec<u8>, String>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionState { AwaitHello, Ready, Closed }

pub struct DaemonSession<B: DaemonBackend> {
    config: ProtocolConfig,
    backend: B,
    state: SessionState,
    last_request_id: u64,
    seen_request_ids: BTreeSet<u64>,
    request_count: u32,
    server_nonce: u64,
    read_count: u32,
    write_count: u32,
}

impl<B: DaemonBackend> DaemonSession<B> {
    pub fn new(config: ProtocolConfig, backend: B, server_nonce: u64) -> Result<Self> {
        config.validate()?;
        if server_nonce == 0 { return Err(DaemonError::Invalid("server_nonce must be non-zero".to_string())); }
        Ok(Self { config, backend, state: SessionState::AwaitHello, last_request_id: 0, seen_request_ids: BTreeSet::new(), request_count: 0, server_nonce, read_count: 0, write_count: 0 })
    }
    pub fn handle(&mut self, request: Frame) -> Result<Frame> {
        if self.state == SessionState::Closed { return Err(DaemonError::Closed); }
        if !request.kind.is_request() { return Err(DaemonError::Protocol("client sent response-kind frame".to_string())); }
        if request.request_id <= self.last_request_id || !self.seen_request_ids.insert(request.request_id) { return Ok(error_frame(request.request_id, 1002, "request_id must be unique and strictly increasing")); }
        self.last_request_id = request.request_id;
        self.request_count = self.request_count.checked_add(1).ok_or_else(|| DaemonError::Protocol("request counter overflow".to_string()))?;
        if self.request_count > self.config.max_requests_per_connection { self.state = SessionState::Closed; return Ok(error_frame(request.request_id, 1003, "connection request budget exhausted")); }
        match self.state {
            SessionState::AwaitHello => {
                if request.kind != FrameKind::Hello { self.state = SessionState::Closed; return Ok(error_frame(request.request_id, 1001, "HELLO required as first request")); }
                let hello = decode_hello(&request.payload)?;
                if hello.min_version > PROTOCOL_VERSION || hello.max_version < PROTOCOL_VERSION { self.state = SessionState::Closed; return Ok(error_frame(request.request_id, 1004, "no mutually supported protocol version")); }
                if hello.client_max_frame_bytes < HEADER_BYTES as u32 { self.state = SessionState::Closed; return Ok(error_frame(request.request_id, 1005, "client frame limit too small")); }
                self.state = SessionState::Ready;
                let negotiated = self.config.max_frame_bytes.min(hello.client_max_frame_bytes);
                Ok(Frame::new(FrameKind::HelloAck, request.request_id, encode_hello_ack(negotiated, self.server_nonce, capability_bits(&self.config))))
            }
            SessionState::Ready => self.handle_ready(request),
            SessionState::Closed => Err(DaemonError::Closed),
        }
    }
    fn handle_ready(&mut self, request: Frame) -> Result<Frame> {
        match request.kind {
            FrameKind::Hello => Ok(error_frame(request.request_id, 1006, "HELLO already completed")),
            FrameKind::Ping => Ok(Frame::new(FrameKind::Pong, request.request_id, request.payload)),
            FrameKind::Health => {
                if !request.payload.is_empty() { return Ok(error_frame(request.request_id, 1007, "HEALTH payload must be empty")); }
                Ok(Frame::new(FrameKind::HealthResult, request.request_id, encode_health(&self.backend.health())))
            }
            FrameKind::Capabilities => {
                if !request.payload.is_empty() { return Ok(error_frame(request.request_id, 1008, "CAPABILITIES payload must be empty")); }
                Ok(Frame::new(FrameKind::CapabilitiesResult, request.request_id, encode_capabilities(&self.config)))
            }
            FrameKind::Read => {
                if request.payload.len() > self.config.max_read_payload_bytes as usize { return Ok(error_frame(request.request_id, 1009, "READ payload exceeds configured limit")); }
                self.read_count += 1;
                match self.backend.execute_read(&request.payload) {
                    Ok(payload) => self.result_frame(request.request_id, payload),
                    Err(message) => Ok(error_frame(request.request_id, 2001, &message)),
                }
            }
            FrameKind::Write => {
                if request.payload.len() > self.config.max_write_payload_bytes as usize { return Ok(error_frame(request.request_id, 1010, "WRITE payload exceeds configured limit")); }
                if self.backend.health().read_only { return Ok(error_frame(request.request_id, 2002, "backend is read-only")); }
                self.write_count += 1;
                match self.backend.execute_write(&request.payload) {
                    Ok(payload) => self.result_frame(request.request_id, payload),
                    Err(message) => Ok(error_frame(request.request_id, 2003, &message)),
                }
            }
            FrameKind::Close => {
                if !request.payload.is_empty() { return Ok(error_frame(request.request_id, 1011, "CLOSE payload must be empty")); }
                self.state = SessionState::Closed;
                Ok(Frame::new(FrameKind::CloseAck, request.request_id, Vec::new()))
            }
            _ => Ok(error_frame(request.request_id, 1012, "unsupported request kind")),
        }
    }
    fn result_frame(&self, request_id: u64, payload: Vec<u8>) -> Result<Frame> {
        if HEADER_BYTES + payload.len() > self.config.max_frame_bytes as usize { return Ok(error_frame(request_id, 2004, "backend response exceeds configured frame limit")); }
        Ok(Frame::new(FrameKind::Result, request_id, payload))
    }
    pub fn is_closed(&self) -> bool { self.state == SessionState::Closed }
    pub fn request_count(&self) -> u32 { self.request_count }
    pub fn read_count(&self) -> u32 { self.read_count }
    pub fn write_count(&self) -> u32 { self.write_count }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServeReport {
    pub peer_loopback: bool,
    pub request_count: u32,
    pub read_count: u32,
    pub write_count: u32,
    pub closed_cleanly: bool,
}

pub fn validate_bind_address(address: SocketAddr, loopback_only: bool) -> Result<()> {
    if loopback_only && !address.ip().is_loopback() { return Err(DaemonError::Invalid("non-loopback bind rejected by default policy".to_string())); }
    Ok(())
}

pub fn bind_listener(address: SocketAddr, config: &ProtocolConfig) -> Result<TcpListener> {
    config.validate()?;
    validate_bind_address(address, config.loopback_only)?;
    let listener = TcpListener::bind(address)?;
    validate_bind_address(listener.local_addr()?, config.loopback_only)?;
    Ok(listener)
}

pub fn serve_one<B: DaemonBackend>(listener: &TcpListener, backend: B, config: ProtocolConfig, server_nonce: u64) -> Result<ServeReport> {
    config.validate()?;
    validate_bind_address(listener.local_addr()?, config.loopback_only)?;
    let (mut stream, peer) = listener.accept()?;
    if config.loopback_only && !peer.ip().is_loopback() { return Err(DaemonError::Protocol("non-loopback peer rejected".to_string())); }
    let timeout = Some(Duration::from_millis(config.io_timeout_millis));
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    stream.set_nodelay(true)?;
    let mut session = DaemonSession::new(config.clone(), backend, server_nonce)?;
    while !session.is_closed() {
        let request = read_frame(&mut stream, config.max_frame_bytes)?;
        let response = session.handle(request)?;
        write_frame(&mut stream, &response, config.max_frame_bytes)?;
    }
    stream.flush()?;
    Ok(ServeReport { peer_loopback: peer.ip().is_loopback(), request_count: session.request_count(), read_count: session.read_count(), write_count: session.write_count(), closed_cleanly: session.is_closed() })
}

pub fn write_frame(stream: &mut TcpStream, frame: &Frame, max_frame_bytes: u32) -> Result<Vec<u8>> {
    let encoded = frame.encode(max_frame_bytes)?;
    let len = encoded.len() as u32;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(&encoded)?;
    stream.flush()?;
    Ok(encoded)
}

pub fn read_frame(stream: &mut TcpStream, max_frame_bytes: u32) -> Result<Frame> {
    let mut prefix = [0u8; LENGTH_PREFIX_BYTES];
    stream.read_exact(&mut prefix)?;
    let length = u32::from_le_bytes(prefix);
    if length < HEADER_BYTES as u32 || length > max_frame_bytes { return Err(DaemonError::Protocol("network frame length outside configured bounds".to_string())); }
    let mut bytes = vec![0u8; length as usize];
    stream.read_exact(&mut bytes)?;
    Frame::decode(&bytes, max_frame_bytes)
}

pub fn encode_hello(min_version: u16, max_version: u16, client_max_frame_bytes: u32, client_nonce: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    put_u16(&mut out, min_version); put_u16(&mut out, max_version); put_u32(&mut out, client_max_frame_bytes); put_u64(&mut out, client_nonce); out
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Hello { min_version: u16, max_version: u16, client_max_frame_bytes: u32, _client_nonce: u64 }
fn decode_hello(payload: &[u8]) -> Result<Hello> {
    if payload.len() != 16 { return Err(DaemonError::Protocol("HELLO payload length mismatch".to_string())); }
    let min_version = get_u16(payload, 0)?; let max_version = get_u16(payload, 2)?;
    if min_version == 0 || min_version > max_version { return Err(DaemonError::Protocol("invalid HELLO version range".to_string())); }
    Ok(Hello { min_version, max_version, client_max_frame_bytes: get_u32(payload, 4)?, _client_nonce: get_u64(payload, 8)? })
}
fn encode_hello_ack(max_frame: u32, server_nonce: u64, capabilities: u64) -> Vec<u8> {
    let mut out=Vec::with_capacity(24); put_u16(&mut out, PROTOCOL_VERSION); put_u16(&mut out, 0); put_u32(&mut out, max_frame); put_u64(&mut out, server_nonce); put_u64(&mut out, capabilities); out
}
fn encode_health(health: &BackendHealth) -> Vec<u8> {
    let mut out=Vec::with_capacity(16); out.push(if health.healthy {1} else {0}); out.push(if health.read_only {1} else {0}); out.extend_from_slice(&[0u8;6]); put_u64(&mut out, health.generation); out
}
fn encode_capabilities(config: &ProtocolConfig) -> Vec<u8> {
    let mut out=Vec::with_capacity(24); put_u64(&mut out, capability_bits(config)); put_u32(&mut out, config.max_frame_bytes); put_u32(&mut out, config.max_requests_per_connection); put_u32(&mut out, config.max_read_payload_bytes); put_u32(&mut out, config.max_write_payload_bytes); out
}
fn capability_bits(config: &ProtocolConfig) -> u64 {
    CAP_READ | CAP_WRITE | CAP_HEALTH | if config.loopback_only { CAP_LOOPBACK_ONLY } else { 0 }
}
fn error_frame(request_id: u64, code: u16, message: &str) -> Frame {
    let bytes=message.as_bytes(); let len=bytes.len().min(u16::MAX as usize); let mut payload=Vec::with_capacity(4+len); put_u16(&mut payload, code); put_u16(&mut payload, len as u16); payload.extend_from_slice(&bytes[..len]); Frame::new(FrameKind::Error, request_id, payload)
}
fn frame_digest(version: u16, kind: u16, flags: u16, request_id: u64, payload: &[u8]) -> [u8;32] {
    let mut bytes=Vec::with_capacity(8+2+2+2+8+4+payload.len()); bytes.extend_from_slice(&FRAME_DOMAIN); put_u16(&mut bytes,version); put_u16(&mut bytes,kind); put_u16(&mut bytes,flags); put_u64(&mut bytes,request_id); put_u32(&mut bytes,payload.len() as u32); bytes.extend_from_slice(payload); sha256(&bytes)
}
fn put_u16(out:&mut Vec<u8>,value:u16){out.extend_from_slice(&value.to_le_bytes());}
fn put_u32(out:&mut Vec<u8>,value:u32){out.extend_from_slice(&value.to_le_bytes());}
fn put_u64(out:&mut Vec<u8>,value:u64){out.extend_from_slice(&value.to_le_bytes());}
fn get_u16(bytes:&[u8],offset:usize)->Result<u16>{let end=offset.checked_add(2).ok_or_else(||DaemonError::Protocol("offset overflow".to_string()))?;let s=bytes.get(offset..end).ok_or_else(||DaemonError::Protocol("truncated u16".to_string()))?;Ok(u16::from_le_bytes([s[0],s[1]]))}
fn get_u32(bytes:&[u8],offset:usize)->Result<u32>{let end=offset.checked_add(4).ok_or_else(||DaemonError::Protocol("offset overflow".to_string()))?;let s=bytes.get(offset..end).ok_or_else(||DaemonError::Protocol("truncated u32".to_string()))?;Ok(u32::from_le_bytes([s[0],s[1],s[2],s[3]]))}
fn get_u64(bytes:&[u8],offset:usize)->Result<u64>{let end=offset.checked_add(8).ok_or_else(||DaemonError::Protocol("offset overflow".to_string()))?;let s=bytes.get(offset..end).ok_or_else(||DaemonError::Protocol("truncated u64".to_string()))?;Ok(u64::from_le_bytes([s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7]]))}

#[cfg(test)]
mod tests {
    use super::*;
    struct TestBackend { generation:u64, read_only:bool }
    impl DaemonBackend for TestBackend {
        fn health(&self)->BackendHealth{BackendHealth{healthy:true,read_only:self.read_only,generation:self.generation}}
        fn execute_read(&mut self,request:&[u8])->std::result::Result<Vec<u8>,String>{let mut out=b"R:".to_vec();out.extend_from_slice(request);Ok(out)}
        fn execute_write(&mut self,request:&[u8])->std::result::Result<Vec<u8>,String>{self.generation+=1;let mut out=b"W:".to_vec();out.extend_from_slice(request);Ok(out)}
    }
    #[test] fn frame_roundtrip_and_tamper(){let f=Frame::new(FrameKind::Ping,7,b"abc".to_vec());let mut b=f.encode(1024).unwrap();assert_eq!(Frame::decode(&b,1024).unwrap(),f);let n=b.len();b[n-1]^=1;assert!(Frame::decode(&b,1024).is_err());}
    #[test]
    fn hello_required_closes_session() {
        let mut prehello = DaemonSession::new(
            ProtocolConfig::default(),
            TestBackend { generation: 0, read_only: false },
            9,
        )
        .unwrap();
        let response = prehello
            .handle(Frame::new(FrameKind::Ping, 1, vec![]))
            .unwrap();
        assert_eq!(response.kind, FrameKind::Error);
        assert!(prehello.is_closed());
        assert!(matches!(
            prehello.handle(Frame::new(
                FrameKind::Hello,
                2,
                encode_hello(1, 1, 4096, 3),
            )),
            Err(DaemonError::Closed)
        ));
    }

    #[test]
    fn hello_and_monotonic_ids() {
        let mut session = DaemonSession::new(
            ProtocolConfig::default(),
            TestBackend { generation: 0, read_only: false },
            10,
        )
        .unwrap();
        let hello = session
            .handle(Frame::new(
                FrameKind::Hello,
                1,
                encode_hello(1, 1, 4096, 3),
            ))
            .unwrap();
        assert_eq!(hello.kind, FrameKind::HelloAck);

        let pong = session
            .handle(Frame::new(FrameKind::Ping, 2, vec![]))
            .unwrap();
        assert_eq!(pong.kind, FrameKind::Pong);

        let duplicate = session
            .handle(Frame::new(FrameKind::Ping, 2, vec![]))
            .unwrap();
        assert_eq!(duplicate.kind, FrameKind::Error);
        assert!(!session.is_closed());

        let next = session
            .handle(Frame::new(FrameKind::Ping, 3, vec![]))
            .unwrap();
        assert_eq!(next.kind, FrameKind::Pong);
    }
    #[test] fn read_write_and_close(){let mut s=DaemonSession::new(ProtocolConfig::default(),TestBackend{generation:0,read_only:false},9).unwrap();s.handle(Frame::new(FrameKind::Hello,1,encode_hello(1,1,4096,3))).unwrap();assert_eq!(s.handle(Frame::new(FrameKind::Read,2,b"x".to_vec())).unwrap().payload,b"R:x");assert_eq!(s.handle(Frame::new(FrameKind::Write,3,b"y".to_vec())).unwrap().payload,b"W:y");assert_eq!(s.handle(Frame::new(FrameKind::Close,4,vec![])).unwrap().kind,FrameKind::CloseAck);assert!(s.is_closed());}
    #[test] fn non_loopback_rejected(){assert!(validate_bind_address("0.0.0.0:0".parse().unwrap(),true).is_err());assert!(validate_bind_address("127.0.0.1:0".parse().unwrap(),true).is_ok());}
}
