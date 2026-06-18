#![deny(unsafe_op_in_unsafe_fn)]

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const STORAGE_MAJOR: u16 = 1;
pub const STORAGE_MINOR: u16 = 0;
pub const FILE_HEADER_BYTES: usize = 80;
pub const RECORD_HEADER_BYTES: usize = 56;
pub const HEAD_FIXED_PAYLOAD_BYTES: usize = 48;

pub const MAGIC_HEAD: [u8; 8] = *b"UBHEAD1\0";
pub const MAGIC_MANIFEST: [u8; 8] = *b"UBMETA1\0";
pub const MAGIC_SEGMENT: [u8; 8] = *b"UBSEG01\0";

#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    InvalidMagic {
        expected: [u8; 8],
        actual: [u8; 8],
    },
    UnsupportedVersion {
        major: u16,
        minor: u16,
    },
    InvalidHeader(&'static str),
    InvalidRecord(String),
    IntegrityMismatch {
        context: String,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    NonZeroPadding {
        offset: u64,
    },
    TrailingBytes {
        expected_end: u64,
        actual_end: u64,
    },
    AlreadyExistsDifferent(PathBuf),
    InvalidPath(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::InvalidMagic { expected, actual } => write!(
                f,
                "invalid magic: expected={} actual={}",
                String::from_utf8_lossy(expected),
                String::from_utf8_lossy(actual)
            ),
            Self::UnsupportedVersion { major, minor } => {
                write!(f, "unsupported storage version {major}.{minor}")
            }
            Self::InvalidHeader(message) => write!(f, "invalid header: {message}"),
            Self::InvalidRecord(message) => write!(f, "invalid record: {message}"),
            Self::IntegrityMismatch {
                context,
                expected,
                actual,
            } => write!(
                f,
                "integrity mismatch for {context}: expected={} actual={}",
                hex_digest(expected),
                hex_digest(actual)
            ),
            Self::NonZeroPadding { offset } => {
                write!(f, "non-zero alignment padding at file offset {offset}")
            }
            Self::TrailingBytes {
                expected_end,
                actual_end,
            } => write!(
                f,
                "trailing bytes: expected end {expected_end}, actual end {actual_end}"
            ),
            Self::AlreadyExistsDifferent(path) => {
                write!(f, "immutable file already exists with different bytes: {}", path.display())
            }
            Self::InvalidPath(message) => write!(f, "invalid path: {message}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<io::Error> for StorageError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Clone)]
struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self
            .total_len
            .checked_add(data.len() as u64)
            .expect("SHA-256 input length overflow");

        if self.buffer_len != 0 {
            let needed = 64 - self.buffer_len;
            let take = needed.min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take]
                .copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }

        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self
            .total_len
            .checked_mul(8)
            .expect("SHA-256 bit length overflow");

        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            for byte in &mut self.buffer[self.buffer_len..] {
                *byte = 0;
            }
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0; 64];
            self.buffer_len = 0;
        }

        for byte in &mut self.buffer[self.buffer_len..56] {
            *byte = 0;
        }
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);

        let mut output = [0u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        output
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ];

        let mut schedule = [0u32; 64];
        for index in 0..16 {
            schedule[index] = u32::from_be_bytes(
                block[index * 4..index * 4 + 4]
                    .try_into()
                    .expect("fixed SHA-256 word"),
            );
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sum1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(schedule[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sum0.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(data);
    digest.finalize()
}

pub fn hex_digest(digest: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02X}").expect("writing to String cannot fail");
    }
    output
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or(StorageError::InvalidHeader("u16 offset overflow"))?;
    let value = bytes
        .get(offset..end)
        .ok_or(StorageError::InvalidHeader("truncated u16"))?;
    Ok(u16::from_le_bytes(value.try_into().expect("checked u16")))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or(StorageError::InvalidHeader("u32 offset overflow"))?;
    let value = bytes
        .get(offset..end)
        .ok_or(StorageError::InvalidHeader("truncated u32"))?;
    Ok(u32::from_le_bytes(value.try_into().expect("checked u32")))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or(StorageError::InvalidHeader("u64 offset overflow"))?;
    let value = bytes
        .get(offset..end)
        .ok_or(StorageError::InvalidHeader("truncated u64"))?;
    Ok(u64::from_le_bytes(value.try_into().expect("checked u64")))
}

fn read_digest(bytes: &[u8], offset: usize) -> Result<[u8; 32]> {
    let end = offset
        .checked_add(32)
        .ok_or(StorageError::InvalidHeader("digest offset overflow"))?;
    let value = bytes
        .get(offset..end)
        .ok_or(StorageError::InvalidHeader("truncated digest"))?;
    Ok(value.try_into().expect("checked digest"))
}

fn padding_len(length: usize) -> usize {
    (8 - (length % 8)) % 8
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileHeader {
    pub magic: [u8; 8],
    pub major: u16,
    pub minor: u16,
    pub generation: u64,
    pub payload_bytes: u64,
    pub item_count: u64,
    pub flags: u64,
    pub payload_sha256: [u8; 32],
}

impl FileHeader {
    pub fn new(
        magic: [u8; 8],
        generation: u64,
        payload_bytes: u64,
        item_count: u64,
        payload_sha256: [u8; 32],
    ) -> Self {
        Self {
            magic,
            major: STORAGE_MAJOR,
            minor: STORAGE_MINOR,
            generation,
            payload_bytes,
            item_count,
            flags: 0,
            payload_sha256,
        }
    }

    pub fn encode(&self) -> [u8; FILE_HEADER_BYTES] {
        let mut bytes = [0u8; FILE_HEADER_BYTES];
        bytes[0..8].copy_from_slice(&self.magic);
        bytes[8..10].copy_from_slice(&self.major.to_le_bytes());
        bytes[10..12].copy_from_slice(&self.minor.to_le_bytes());
        bytes[12..16].copy_from_slice(&(FILE_HEADER_BYTES as u32).to_le_bytes());
        bytes[16..24].copy_from_slice(&self.generation.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.payload_bytes.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.item_count.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.flags.to_le_bytes());
        bytes[48..80].copy_from_slice(&self.payload_sha256);
        bytes
    }

    pub fn decode(bytes: &[u8], expected_magic: [u8; 8]) -> Result<Self> {
        if bytes.len() != FILE_HEADER_BYTES {
            return Err(StorageError::InvalidHeader("file header must be exactly 80 bytes"));
        }
        let magic: [u8; 8] = bytes[0..8].try_into().expect("fixed magic");
        if magic != expected_magic {
            return Err(StorageError::InvalidMagic {
                expected: expected_magic,
                actual: magic,
            });
        }
        let major = read_u16(bytes, 8)?;
        let minor = read_u16(bytes, 10)?;
        if major != STORAGE_MAJOR {
            return Err(StorageError::UnsupportedVersion { major, minor });
        }
        if read_u32(bytes, 12)? != FILE_HEADER_BYTES as u32 {
            return Err(StorageError::InvalidHeader("file header_bytes is not 80"));
        }
        let flags = read_u64(bytes, 40)?;
        if flags != 0 {
            return Err(StorageError::InvalidHeader("unknown file flags"));
        }
        Ok(Self {
            magic,
            major,
            minor,
            generation: read_u64(bytes, 16)?,
            payload_bytes: read_u64(bytes, 24)?,
            item_count: read_u64(bytes, 32)?,
            flags,
            payload_sha256: read_digest(bytes, 48)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordKind {
    Record = 1,
    TypedEdge = 2,
    RecordTombstone = 3,
    EdgeTombstone = 4,
    Metadata = 5,
}

impl RecordKind {
    fn from_u16(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::Record),
            2 => Ok(Self::TypedEdge),
            3 => Ok(Self::RecordTombstone),
            4 => Ok(Self::EdgeTombstone),
            5 => Ok(Self::Metadata),
            _ => Err(StorageError::InvalidRecord(format!(
                "unknown record kind {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SegmentEntry {
    pub kind: RecordKind,
    pub logical_id: u64,
    pub payload: Vec<u8>,
}

impl SegmentEntry {
    pub fn new(kind: RecordKind, logical_id: u64, payload: Vec<u8>) -> Result<Self> {
        let entry = Self {
            kind,
            logical_id,
            payload,
        };
        validate_entry_payload(&entry)?;
        Ok(entry)
    }

    pub fn record(
        logical_id: u64,
        record_id: &str,
        node_id: u64,
        user_payload: &[u8],
    ) -> Result<Self> {
        if record_id.is_empty() {
            return Err(StorageError::InvalidRecord(
                "record_id cannot be empty".to_string(),
            ));
        }
        let record_id_bytes = record_id.as_bytes();
        let record_id_len = u32::try_from(record_id_bytes.len())
            .map_err(|_| StorageError::InvalidRecord("record_id too long".to_string()))?;
        let user_payload_len = u64::try_from(user_payload.len())
            .map_err(|_| StorageError::InvalidRecord("payload too long".to_string()))?;

        let mut payload = Vec::with_capacity(
            56usize
                .checked_add(record_id_bytes.len())
                .and_then(|value| value.checked_add(user_payload.len()))
                .ok_or_else(|| StorageError::InvalidRecord("record payload overflow".to_string()))?,
        );
        payload.extend_from_slice(&record_id_len.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&node_id.to_le_bytes());
        payload.extend_from_slice(&user_payload_len.to_le_bytes());
        payload.extend_from_slice(&sha256(user_payload));
        payload.extend_from_slice(record_id_bytes);
        payload.extend_from_slice(user_payload);
        Self::new(RecordKind::Record, logical_id, payload)
    }

    pub fn typed_edge(
        logical_id: u64,
        src: u64,
        dst: u64,
        edge_type: u32,
        weight: f64,
    ) -> Result<Self> {
        if !weight.is_finite() {
            return Err(StorageError::InvalidRecord(
                "typed edge weight must be finite".to_string(),
            ));
        }
        let canonical_weight = if weight == 0.0 { 0.0 } else { weight };
        let mut payload = Vec::with_capacity(32);
        payload.extend_from_slice(&src.to_le_bytes());
        payload.extend_from_slice(&dst.to_le_bytes());
        payload.extend_from_slice(&edge_type.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&canonical_weight.to_bits().to_le_bytes());
        Self::new(RecordKind::TypedEdge, logical_id, payload)
    }

    pub fn metadata(logical_id: u64, payload: Vec<u8>) -> Result<Self> {
        Self::new(RecordKind::Metadata, logical_id, payload)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordHeader {
    kind: RecordKind,
    flags: u16,
    logical_id: u64,
    payload_bytes: u64,
    payload_sha256: [u8; 32],
}

impl RecordHeader {
    fn for_entry(entry: &SegmentEntry) -> Result<Self> {
        Ok(Self {
            kind: entry.kind,
            flags: 0,
            logical_id: entry.logical_id,
            payload_bytes: u64::try_from(entry.payload.len())
                .map_err(|_| StorageError::InvalidRecord("payload too long".to_string()))?,
            payload_sha256: sha256(&entry.payload),
        })
    }

    fn encode(&self) -> [u8; RECORD_HEADER_BYTES] {
        let mut bytes = [0u8; RECORD_HEADER_BYTES];
        bytes[0..2].copy_from_slice(&(self.kind as u16).to_le_bytes());
        bytes[2..4].copy_from_slice(&self.flags.to_le_bytes());
        bytes[4..8].copy_from_slice(&(RECORD_HEADER_BYTES as u32).to_le_bytes());
        bytes[8..16].copy_from_slice(&self.logical_id.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.payload_bytes.to_le_bytes());
        bytes[24..56].copy_from_slice(&self.payload_sha256);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RECORD_HEADER_BYTES {
            return Err(StorageError::InvalidHeader(
                "record header must be exactly 56 bytes",
            ));
        }
        let flags = read_u16(bytes, 2)?;
        if flags != 0 {
            return Err(StorageError::InvalidRecord(
                "unknown record flags".to_string(),
            ));
        }
        if read_u32(bytes, 4)? != RECORD_HEADER_BYTES as u32 {
            return Err(StorageError::InvalidRecord(
                "record header_bytes is not 56".to_string(),
            ));
        }
        Ok(Self {
            kind: RecordKind::from_u16(read_u16(bytes, 0)?)?,
            flags,
            logical_id: read_u64(bytes, 8)?,
            payload_bytes: read_u64(bytes, 16)?,
            payload_sha256: read_digest(bytes, 24)?,
        })
    }
}

fn validate_entry_payload(entry: &SegmentEntry) -> Result<()> {
    match entry.kind {
        RecordKind::Record => validate_record_payload(&entry.payload),
        RecordKind::TypedEdge => validate_typed_edge_payload(&entry.payload),
        RecordKind::RecordTombstone
        | RecordKind::EdgeTombstone
        | RecordKind::Metadata => Ok(()),
    }
}

fn validate_record_payload(payload: &[u8]) -> Result<()> {
    if payload.len() < 56 {
        return Err(StorageError::InvalidRecord(
            "record payload shorter than fixed prefix".to_string(),
        ));
    }
    let record_id_len = read_u32(payload, 0)? as usize;
    if read_u32(payload, 4)? != 0 {
        return Err(StorageError::InvalidRecord(
            "record reserved field is non-zero".to_string(),
        ));
    }
    let user_payload_len = usize::try_from(read_u64(payload, 16)?)
        .map_err(|_| StorageError::InvalidRecord("user payload too large".to_string()))?;
    let expected_len = 56usize
        .checked_add(record_id_len)
        .and_then(|value| value.checked_add(user_payload_len))
        .ok_or_else(|| StorageError::InvalidRecord("record length overflow".to_string()))?;
    if payload.len() != expected_len {
        return Err(StorageError::InvalidRecord(format!(
            "record payload length mismatch expected={expected_len} actual={}",
            payload.len()
        )));
    }
    if record_id_len == 0 {
        return Err(StorageError::InvalidRecord(
            "record_id cannot be empty".to_string(),
        ));
    }
    let record_id_end = 56 + record_id_len;
    std::str::from_utf8(&payload[56..record_id_end])
        .map_err(|_| StorageError::InvalidRecord("record_id is not UTF-8".to_string()))?;
    let expected_hash = read_digest(payload, 24)?;
    let actual_hash = sha256(&payload[record_id_end..]);
    if expected_hash != actual_hash {
        return Err(StorageError::IntegrityMismatch {
            context: "record user payload".to_string(),
            expected: expected_hash,
            actual: actual_hash,
        });
    }
    Ok(())
}

fn validate_typed_edge_payload(payload: &[u8]) -> Result<()> {
    if payload.len() != 32 {
        return Err(StorageError::InvalidRecord(format!(
            "typed edge payload must be 32 bytes, actual={}",
            payload.len()
        )));
    }
    if read_u32(payload, 20)? != 0 {
        return Err(StorageError::InvalidRecord(
            "typed edge reserved field is non-zero".to_string(),
        ));
    }
    let bits = read_u64(payload, 24)?;
    let weight = f64::from_bits(bits);
    if !weight.is_finite() {
        return Err(StorageError::InvalidRecord(
            "typed edge weight must be finite".to_string(),
        ));
    }
    if weight == 0.0 && bits != 0 {
        return Err(StorageError::InvalidRecord(
            "typed edge negative zero is not canonical".to_string(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegrityReport {
    pub path: PathBuf,
    pub magic: [u8; 8],
    pub generation: u64,
    pub item_count: u64,
    pub payload_bytes: u64,
    pub file_bytes: u64,
    pub payload_sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub generation: u64,
    pub manifest_filename: String,
    pub manifest_sha256: [u8; 32],
}

impl Head {
    fn validate_filename(&self) -> Result<()> {
        if self.manifest_filename.is_empty() {
            return Err(StorageError::InvalidPath(
                "manifest filename cannot be empty".to_string(),
            ));
        }
        let path = Path::new(&self.manifest_filename);
        if path.is_absolute()
            || path.components().any(|component| {
                !matches!(component, Component::Normal(_))
            })
            || path.components().count() != 1
        {
            return Err(StorageError::InvalidPath(
                "manifest filename must be one normal relative path component".to_string(),
            ));
        }
        if !self.manifest_filename.starts_with("MANIFEST-")
            || !self.manifest_filename.ends_with(".ubmeta")
        {
            return Err(StorageError::InvalidPath(
                "manifest filename does not match MANIFEST-*.ubmeta".to_string(),
            ));
        }
        Ok(())
    }

    fn encode_payload(&self) -> Result<Vec<u8>> {
        self.validate_filename()?;
        let filename = self.manifest_filename.as_bytes();
        let filename_len = u32::try_from(filename.len())
            .map_err(|_| StorageError::InvalidPath("manifest filename too long".to_string()))?;
        let mut payload = Vec::with_capacity(HEAD_FIXED_PAYLOAD_BYTES + filename.len() + 7);
        payload.extend_from_slice(&self.generation.to_le_bytes());
        payload.extend_from_slice(&filename_len.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&self.manifest_sha256);
        payload.extend_from_slice(filename);
        payload.resize(payload.len() + padding_len(payload.len()), 0);
        Ok(payload)
    }

    fn decode_payload(payload: &[u8]) -> Result<Self> {
        if payload.len() < HEAD_FIXED_PAYLOAD_BYTES {
            return Err(StorageError::InvalidHeader("head payload too short"));
        }
        let generation = read_u64(payload, 0)?;
        let filename_len = read_u32(payload, 8)? as usize;
        if read_u32(payload, 12)? != 0 {
            return Err(StorageError::InvalidHeader("head reserved field is non-zero"));
        }
        let manifest_sha256 = read_digest(payload, 16)?;
        let filename_end = HEAD_FIXED_PAYLOAD_BYTES
            .checked_add(filename_len)
            .ok_or(StorageError::InvalidHeader("head filename length overflow"))?;
        if filename_end > payload.len() {
            return Err(StorageError::InvalidHeader("head filename is truncated"));
        }
        if payload[filename_end..].iter().any(|byte| *byte != 0) {
            return Err(StorageError::NonZeroPadding {
                offset: filename_end as u64,
            });
        }
        let manifest_filename = std::str::from_utf8(
            &payload[HEAD_FIXED_PAYLOAD_BYTES..filename_end],
        )
        .map_err(|_| StorageError::InvalidHeader("head filename is not UTF-8"))?
        .to_string();
        let head = Self {
            generation,
            manifest_filename,
            manifest_sha256,
        };
        head.validate_filename()?;
        Ok(head)
    }
}

#[derive(Clone, Debug)]
pub struct PageStore {
    root: PathBuf,
}

impl PageStore {
    pub fn create(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        for directory in [
            "manifests",
            "segments",
            "wal",
            "checkpoints",
            "indexes",
        ] {
            fs::create_dir_all(root.join(directory))?;
        }
        sync_parent_dir(&root)?;
        Ok(Self { root })
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !root.is_dir() {
            return Err(StorageError::InvalidPath(format!(
                "database root is not a directory: {}",
                root.display()
            )));
        }
        for directory in ["manifests", "segments", "wal", "checkpoints", "indexes"] {
            if !root.join(directory).is_dir() {
                return Err(StorageError::InvalidPath(format!(
                    "required directory missing: {directory}"
                )));
            }
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn write_segment<I>(
        &self,
        generation: u64,
        sequence: u64,
        entries: I,
    ) -> Result<IntegrityReport>
    where
        I: IntoIterator<Item = SegmentEntry>,
    {
        let path = self.root.join("segments").join(format!(
            "SEGMENT-{generation:020}-{sequence:020}.ubseg"
        ));
        write_segment_file(&path, generation, entries)
    }

    pub fn write_manifest(
        &self,
        generation: u64,
        item_count: u64,
        payload: &[u8],
    ) -> Result<IntegrityReport> {
        let path = self
            .root
            .join("manifests")
            .join(format!("MANIFEST-{generation:020}.ubmeta"));
        write_versioned_file(
            &path,
            MAGIC_MANIFEST,
            generation,
            item_count,
            payload,
            false,
        )
    }

    pub fn publish_head(&self, head: &Head) -> Result<IntegrityReport> {
        head.validate_filename()?;
        let manifest_path = self.root.join("manifests").join(&head.manifest_filename);
        let manifest_report = verify_versioned_file(&manifest_path, MAGIC_MANIFEST)?;
        if manifest_report.generation != head.generation {
            return Err(StorageError::InvalidHeader(
                "head and manifest generations differ",
            ));
        }
        let actual_manifest_hash = sha256_file(&manifest_path)?;
        if actual_manifest_hash != head.manifest_sha256 {
            return Err(StorageError::IntegrityMismatch {
                context: "head referenced manifest file".to_string(),
                expected: head.manifest_sha256,
                actual: actual_manifest_hash,
            });
        }

        let payload = head.encode_payload()?;
        write_versioned_file(
            &self.root.join("CURRENT.ubhead"),
            MAGIC_HEAD,
            head.generation,
            1,
            &payload,
            true,
        )
    }

    pub fn read_head(&self) -> Result<Option<Head>> {
        let path = self.root.join("CURRENT.ubhead");
        if !path.exists() {
            return Ok(None);
        }
        let (header, payload, _) = read_versioned_file(&path, MAGIC_HEAD)?;
        if header.item_count != 1 {
            return Err(StorageError::InvalidHeader(
                "head item_count must be exactly 1",
            ));
        }
        let head = Head::decode_payload(&payload)?;
        if head.generation != header.generation {
            return Err(StorageError::InvalidHeader(
                "head payload generation differs from file header",
            ));
        }
        Ok(Some(head))
    }

    pub fn verify(&self) -> Result<StoreIntegrityReport> {
        let mut segment_paths = Vec::new();
        for entry in fs::read_dir(self.root.join("segments"))? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) == Some("ubseg") {
                segment_paths.push(path);
            }
        }
        segment_paths.sort();

        let mut segments = Vec::with_capacity(segment_paths.len());
        for path in segment_paths {
            segments.push(verify_segment(&path)?);
        }

        let head = self.read_head()?;
        let manifest = if let Some(ref head_value) = head {
            let path = self
                .root
                .join("manifests")
                .join(&head_value.manifest_filename);
            let report = verify_versioned_file(&path, MAGIC_MANIFEST)?;
            let actual_file_hash = sha256_file(&path)?;
            if actual_file_hash != head_value.manifest_sha256 {
                return Err(StorageError::IntegrityMismatch {
                    context: "store manifest file".to_string(),
                    expected: head_value.manifest_sha256,
                    actual: actual_file_hash,
                });
            }
            Some(report)
        } else {
            None
        };

        Ok(StoreIntegrityReport {
            root: self.root.clone(),
            segment_count: segments.len() as u64,
            segments,
            head,
            manifest,
        })
    }
}

#[derive(Clone, Debug)]
pub struct StoreIntegrityReport {
    pub root: PathBuf,
    pub segment_count: u64,
    pub segments: Vec<IntegrityReport>,
    pub head: Option<Head>,
    pub manifest: Option<IntegrityReport>,
}

pub fn write_segment_file<I>(
    path: &Path,
    generation: u64,
    entries: I,
) -> Result<IntegrityReport>
where
    I: IntoIterator<Item = SegmentEntry>,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = temporary_path(path)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&temporary)?;

    let result = (|| -> Result<IntegrityReport> {
        file.write_all(&[0u8; FILE_HEADER_BYTES])?;
        let mut payload_digest = Sha256::new();
        let mut payload_bytes = 0u64;
        let mut item_count = 0u64;

        for entry in entries {
            validate_entry_payload(&entry)?;
            let record_header = RecordHeader::for_entry(&entry)?;
            let encoded_header = record_header.encode();
            file.write_all(&encoded_header)?;
            payload_digest.update(&encoded_header);
            payload_bytes = payload_bytes
                .checked_add(RECORD_HEADER_BYTES as u64)
                .ok_or(StorageError::InvalidHeader("segment size overflow"))?;

            file.write_all(&entry.payload)?;
            payload_digest.update(&entry.payload);
            payload_bytes = payload_bytes
                .checked_add(entry.payload.len() as u64)
                .ok_or(StorageError::InvalidHeader("segment size overflow"))?;

            let padding = padding_len(entry.payload.len());
            if padding != 0 {
                let zeros = [0u8; 8];
                file.write_all(&zeros[..padding])?;
                payload_digest.update(&zeros[..padding]);
                payload_bytes = payload_bytes
                    .checked_add(padding as u64)
                    .ok_or(StorageError::InvalidHeader("segment size overflow"))?;
            }
            item_count = item_count
                .checked_add(1)
                .ok_or(StorageError::InvalidHeader("segment item count overflow"))?;
        }

        let payload_sha256 = payload_digest.finalize();
        let header = FileHeader::new(
            MAGIC_SEGMENT,
            generation,
            payload_bytes,
            item_count,
            payload_sha256,
        );
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&header.encode())?;
        file.flush()?;
        file.sync_all()?;
        drop(file);

        publish_immutable(&temporary, path)?;
        verify_segment(path)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn verify_segment(path: &Path) -> Result<IntegrityReport> {
    let mut file = File::open(path)?;
    let file_bytes = file.metadata()?.len();
    if file_bytes < FILE_HEADER_BYTES as u64 {
        return Err(StorageError::InvalidHeader("segment file shorter than header"));
    }

    let mut header_bytes = [0u8; FILE_HEADER_BYTES];
    file.read_exact(&mut header_bytes)?;
    let header = FileHeader::decode(&header_bytes, MAGIC_SEGMENT)?;
    let expected_end = (FILE_HEADER_BYTES as u64)
        .checked_add(header.payload_bytes)
        .ok_or(StorageError::InvalidHeader("segment payload end overflow"))?;
    if file_bytes != expected_end {
        return Err(StorageError::TrailingBytes {
            expected_end,
            actual_end: file_bytes,
        });
    }

    let mut payload_digest = Sha256::new();
    let mut consumed = 0u64;
    let mut item_count = 0u64;

    while consumed < header.payload_bytes {
        let remaining = header.payload_bytes - consumed;
        if remaining < RECORD_HEADER_BYTES as u64 {
            return Err(StorageError::InvalidRecord(
                "truncated record header at segment tail".to_string(),
            ));
        }

        let record_offset = FILE_HEADER_BYTES as u64 + consumed;
        let mut encoded_header = [0u8; RECORD_HEADER_BYTES];
        file.read_exact(&mut encoded_header)?;
        payload_digest.update(&encoded_header);
        consumed += RECORD_HEADER_BYTES as u64;

        let record_header = RecordHeader::decode(&encoded_header)?;
        let payload_len = usize::try_from(record_header.payload_bytes)
            .map_err(|_| StorageError::InvalidRecord("record payload too large".to_string()))?;
        let padding = padding_len(payload_len);
        let required = record_header
            .payload_bytes
            .checked_add(padding as u64)
            .ok_or_else(|| StorageError::InvalidRecord("record size overflow".to_string()))?;
        if required > header.payload_bytes - consumed {
            return Err(StorageError::InvalidRecord(
                "record payload exceeds segment boundary".to_string(),
            ));
        }

        let mut payload = vec![0u8; payload_len];
        file.read_exact(&mut payload)?;
        payload_digest.update(&payload);
        consumed += payload_len as u64;

        let actual_record_hash = sha256(&payload);
        if actual_record_hash != record_header.payload_sha256 {
            return Err(StorageError::IntegrityMismatch {
                context: format!("segment record at offset {record_offset}"),
                expected: record_header.payload_sha256,
                actual: actual_record_hash,
            });
        }

        let entry = SegmentEntry {
            kind: record_header.kind,
            logical_id: record_header.logical_id,
            payload,
        };
        validate_entry_payload(&entry)?;

        if padding != 0 {
            let mut padding_bytes = [0u8; 8];
            file.read_exact(&mut padding_bytes[..padding])?;
            payload_digest.update(&padding_bytes[..padding]);
            if padding_bytes[..padding].iter().any(|byte| *byte != 0) {
                return Err(StorageError::NonZeroPadding {
                    offset: FILE_HEADER_BYTES as u64 + consumed,
                });
            }
            consumed += padding as u64;
        }

        item_count += 1;
    }

    if consumed != header.payload_bytes {
        return Err(StorageError::InvalidHeader(
            "segment payload consumption mismatch",
        ));
    }
    if item_count != header.item_count {
        return Err(StorageError::InvalidHeader(
            "segment item_count differs from parsed records",
        ));
    }

    let actual_payload_hash = payload_digest.finalize();
    if actual_payload_hash != header.payload_sha256 {
        return Err(StorageError::IntegrityMismatch {
            context: format!("segment payload {}", path.display()),
            expected: header.payload_sha256,
            actual: actual_payload_hash,
        });
    }

    Ok(IntegrityReport {
        path: path.to_path_buf(),
        magic: header.magic,
        generation: header.generation,
        item_count: header.item_count,
        payload_bytes: header.payload_bytes,
        file_bytes,
        payload_sha256: header.payload_sha256,
    })
}

pub fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize())
}

fn write_versioned_file(
    path: &Path,
    magic: [u8; 8],
    generation: u64,
    item_count: u64,
    payload: &[u8],
    replace: bool,
) -> Result<IntegrityReport> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let payload_bytes = u64::try_from(payload.len())
        .map_err(|_| StorageError::InvalidHeader("payload too long"))?;
    let header = FileHeader::new(
        magic,
        generation,
        payload_bytes,
        item_count,
        sha256(payload),
    );

    let temporary = temporary_path(path)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    let result = (|| -> Result<IntegrityReport> {
        file.write_all(&header.encode())?;
        file.write_all(payload)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);

        if replace {
            atomic_move(&temporary, path, true)?;
        } else {
            publish_immutable(&temporary, path)?;
        }
        sync_parent_dir(
            path.parent()
                .ok_or_else(|| StorageError::InvalidPath("file has no parent".to_string()))?,
        )?;
        verify_versioned_file(path, magic)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_versioned_file(
    path: &Path,
    expected_magic: [u8; 8],
) -> Result<(FileHeader, Vec<u8>, u64)> {
    let mut file = File::open(path)?;
    let file_bytes = file.metadata()?.len();
    if file_bytes < FILE_HEADER_BYTES as u64 {
        return Err(StorageError::InvalidHeader("file shorter than header"));
    }
    let mut header_bytes = [0u8; FILE_HEADER_BYTES];
    file.read_exact(&mut header_bytes)?;
    let header = FileHeader::decode(&header_bytes, expected_magic)?;
    let expected_end = (FILE_HEADER_BYTES as u64)
        .checked_add(header.payload_bytes)
        .ok_or(StorageError::InvalidHeader("payload end overflow"))?;
    if file_bytes != expected_end {
        return Err(StorageError::TrailingBytes {
            expected_end,
            actual_end: file_bytes,
        });
    }
    let payload_len = usize::try_from(header.payload_bytes)
        .map_err(|_| StorageError::InvalidHeader("payload too large"))?;
    let mut payload = vec![0u8; payload_len];
    file.read_exact(&mut payload)?;
    let actual_hash = sha256(&payload);
    if actual_hash != header.payload_sha256 {
        return Err(StorageError::IntegrityMismatch {
            context: path.display().to_string(),
            expected: header.payload_sha256,
            actual: actual_hash,
        });
    }
    Ok((header, payload, file_bytes))
}

fn verify_versioned_file(path: &Path, expected_magic: [u8; 8]) -> Result<IntegrityReport> {
    let (header, _, file_bytes) = read_versioned_file(path, expected_magic)?;
    Ok(IntegrityReport {
        path: path.to_path_buf(),
        magic: header.magic,
        generation: header.generation,
        item_count: header.item_count,
        payload_bytes: header.payload_bytes,
        file_bytes,
        payload_sha256: header.payload_sha256,
    })
}

fn publish_immutable(temporary: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        let existing_hash = sha256_file(destination)?;
        let temporary_hash = sha256_file(temporary)?;
        if existing_hash == temporary_hash
            && fs::metadata(destination)?.len() == fs::metadata(temporary)?.len()
        {
            fs::remove_file(temporary)?;
            return Ok(());
        }
        return Err(StorageError::AlreadyExistsDifferent(
            destination.to_path_buf(),
        ));
    }
    atomic_move(temporary, destination, false)?;
    let parent = destination
        .parent()
        .ok_or_else(|| StorageError::InvalidPath("destination has no parent".to_string()))?;
    sync_parent_dir(parent)
}

fn temporary_path(destination: &Path) -> Result<PathBuf> {
    let parent = destination
        .parent()
        .ok_or_else(|| StorageError::InvalidPath("destination has no parent".to_string()))?;
    let name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| StorageError::InvalidPath("destination filename is not UTF-8".to_string()))?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StorageError::InvalidHeader("system clock before UNIX epoch"))?
        .as_nanos();
    Ok(parent.join(format!(".{name}.tmp-{}-{timestamp}", std::process::id())))
}

#[cfg(unix)]
fn atomic_move(temporary: &Path, destination: &Path, _replace: bool) -> Result<()> {
    fs::rename(temporary, destination)?;
    Ok(())
}

#[cfg(windows)]
fn atomic_move(temporary: &Path, destination: &Path, replace: bool) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    let source_wide: Vec<u16> = temporary
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut flags = MOVEFILE_WRITE_THROUGH;
    if replace {
        flags |= MOVEFILE_REPLACE_EXISTING;
    }
    let result = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            flags,
        )
    };
    if result == 0 {
        return Err(StorageError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(windows)]
#[link(name = "Kernel32")]
extern "system" {
    fn MoveFileExW(
        existing_file_name: *const u16,
        new_file_name: *const u16,
        flags: u32,
    ) -> i32;
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_parent_dir(_path: &Path) -> Result<()> {
    // MoveFileExW is always invoked with MOVEFILE_WRITE_THROUGH. This is the
    // Windows durability barrier corresponding to rename + directory fsync.
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn atomic_move(temporary: &Path, destination: &Path, replace: bool) -> Result<()> {
    if destination.exists() && !replace {
        return Err(StorageError::AlreadyExistsDifferent(
            destination.to_path_buf(),
        ));
    }
    if destination.exists() {
        fs::remove_file(destination)?;
    }
    fs::rename(temporary, destination)?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_parent_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_root(name: &str) -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "ultraballoondb-storage-{name}-{}-{counter}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        root
    }

    fn sample_entries() -> Vec<SegmentEntry> {
        vec![
            SegmentEntry::record(1, "alpha", 11, b"payload-alpha").unwrap(),
            SegmentEntry::typed_edge(2, 11, 22, 7, 0.75).unwrap(),
            SegmentEntry::metadata(3, b"metadata-v1".to_vec()).unwrap(),
        ]
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            hex_digest(&sha256(b"")),
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
        assert_eq!(
            hex_digest(&sha256(b"abc")),
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        );
    }

    #[test]
    fn file_header_roundtrip() {
        let header = FileHeader::new(MAGIC_SEGMENT, 9, 123, 4, sha256(b"x"));
        let decoded = FileHeader::decode(&header.encode(), MAGIC_SEGMENT).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn segment_roundtrip_and_restart() {
        let root = test_root("roundtrip");
        let store = PageStore::create(&root).unwrap();
        let report = store.write_segment(1, 0, sample_entries()).unwrap();
        assert_eq!(report.item_count, 3);

        let reopened = PageStore::open(&root).unwrap();
        let integrity = reopened.verify().unwrap();
        assert_eq!(integrity.segment_count, 1);
        assert_eq!(integrity.segments[0].item_count, 3);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn deterministic_segment_bytes() {
        let left_root = test_root("deterministic-left");
        let right_root = test_root("deterministic-right");
        let left = PageStore::create(&left_root).unwrap();
        let right = PageStore::create(&right_root).unwrap();

        let left_report = left.write_segment(5, 7, sample_entries()).unwrap();
        let right_report = right.write_segment(5, 7, sample_entries()).unwrap();
        assert_eq!(
            fs::read(left_report.path).unwrap(),
            fs::read(right_report.path).unwrap()
        );
        fs::remove_dir_all(left_root).unwrap();
        fs::remove_dir_all(right_root).unwrap();
    }

    #[test]
    fn record_payload_corruption_is_rejected() {
        let root = test_root("corruption");
        let store = PageStore::create(&root).unwrap();
        let report = store.write_segment(1, 0, sample_entries()).unwrap();
        let mut bytes = fs::read(&report.path).unwrap();
        bytes[FILE_HEADER_BYTES + RECORD_HEADER_BYTES + 10] ^= 0x40;
        fs::write(&report.path, bytes).unwrap();
        assert!(verify_segment(&report.path).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let root = test_root("trailing");
        let store = PageStore::create(&root).unwrap();
        let report = store.write_segment(1, 0, sample_entries()).unwrap();
        let mut file = OpenOptions::new().append(true).open(&report.path).unwrap();
        file.write_all(b"x").unwrap();
        file.sync_all().unwrap();
        assert!(matches!(
            verify_segment(&report.path),
            Err(StorageError::TrailingBytes { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn immutable_segment_rejects_different_content() {
        let root = test_root("immutable");
        let store = PageStore::create(&root).unwrap();
        store.write_segment(1, 0, sample_entries()).unwrap();
        let changed = vec![SegmentEntry::metadata(99, b"different".to_vec()).unwrap()];
        assert!(matches!(
            store.write_segment(1, 0, changed),
            Err(StorageError::AlreadyExistsDifferent(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn head_atomic_replace_and_manifest_binding() {
        let root = test_root("head");
        let store = PageStore::create(&root).unwrap();

        let manifest1 = store.write_manifest(1, 0, b"manifest-one").unwrap();
        let manifest1_hash = sha256_file(&manifest1.path).unwrap();
        store
            .publish_head(&Head {
                generation: 1,
                manifest_filename: manifest1
                    .path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                manifest_sha256: manifest1_hash,
            })
            .unwrap();

        let manifest2 = store.write_manifest(2, 0, b"manifest-two").unwrap();
        let manifest2_hash = sha256_file(&manifest2.path).unwrap();
        store
            .publish_head(&Head {
                generation: 2,
                manifest_filename: manifest2
                    .path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                manifest_sha256: manifest2_hash,
            })
            .unwrap();

        let head = PageStore::open(&root)
            .unwrap()
            .read_head()
            .unwrap()
            .unwrap();
        assert_eq!(head.generation, 2);
        assert_eq!(head.manifest_sha256, manifest2_hash);
        assert_eq!(PageStore::open(&root).unwrap().verify().unwrap().segment_count, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn path_traversal_head_is_rejected() {
        let head = Head {
            generation: 1,
            manifest_filename: "../MANIFEST-1.ubmeta".to_string(),
            manifest_sha256: [0; 32],
        };
        assert!(head.encode_payload().is_err());
    }

    #[test]
    fn typed_edge_negative_zero_is_canonicalized() {
        let edge = SegmentEntry::typed_edge(1, 1, 2, 3, -0.0).unwrap();
        assert_eq!(read_u64(&edge.payload, 24).unwrap(), 0);
    }
}
