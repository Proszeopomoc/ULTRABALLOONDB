use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use ultraballoondb_storage::{hex_digest, sha256};

pub const WAL_MAGIC: [u8; 8] = *b"UBWFR01\0";
pub const WAL_MAJOR: u16 = 1;
pub const WAL_HEADER_BYTES: usize = 96;
pub const MAX_WAL_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum FrameType {
    Begin = 1,
    PutRecord = 2,
    PutEdge = 3,
    DeleteRecord = 4,
    DeleteEdge = 5,
    Commit = 6,
    Abort = 7,
    Checkpoint = 8,
}

impl FrameType {
    fn from_u16(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::Begin),
            2 => Ok(Self::PutRecord),
            3 => Ok(Self::PutEdge),
            4 => Ok(Self::DeleteRecord),
            5 => Ok(Self::DeleteEdge),
            6 => Ok(Self::Commit),
            7 => Ok(Self::Abort),
            8 => Ok(Self::Checkpoint),
            _ => Err(WalError::InvalidHeader(format!(
                "unknown frame type {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalFrame {
    pub frame_type: FrameType,
    pub lsn: u64,
    pub transaction_id: [u8; 16],
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalScan {
    pub frames: Vec<WalFrame>,
    pub maximum_lsn: u64,
    pub repaired_trailing_bytes: u64,
    pub valid_bytes: u64,
}

#[derive(Debug)]
pub enum WalError {
    Io(io::Error),
    InvalidHeader(String),
    Integrity {
        context: String,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    NonMonotonicLsn {
        previous: u64,
        actual: u64,
    },
    PayloadTooLarge(u64),
}

impl fmt::Display for WalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::InvalidHeader(message) => {
                write!(f, "invalid WAL header: {message}")
            }
            Self::Integrity {
                context,
                expected,
                actual,
            } => write!(
                f,
                "WAL integrity mismatch for {context}: expected={} actual={}",
                hex_digest(expected),
                hex_digest(actual)
            ),
            Self::NonMonotonicLsn { previous, actual } => write!(
                f,
                "non-monotonic LSN: previous={previous} actual={actual}"
            ),
            Self::PayloadTooLarge(bytes) => {
                write!(f, "WAL payload too large: {bytes}")
            }
        }
    }
}

impl std::error::Error for WalError {}

impl From<io::Error> for WalError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, WalError>;

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| WalError::InvalidHeader("u16 overflow".to_string()))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| WalError::InvalidHeader("truncated u16".to_string()))?;
    Ok(u16::from_le_bytes(value.try_into().expect("checked u16")))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| WalError::InvalidHeader("u32 overflow".to_string()))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| WalError::InvalidHeader("truncated u32".to_string()))?;
    Ok(u32::from_le_bytes(value.try_into().expect("checked u32")))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| WalError::InvalidHeader("u64 overflow".to_string()))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| WalError::InvalidHeader("truncated u64".to_string()))?;
    Ok(u64::from_le_bytes(value.try_into().expect("checked u64")))
}

fn read_digest(bytes: &[u8], offset: usize) -> Result<[u8; 32]> {
    let end = offset
        .checked_add(32)
        .ok_or_else(|| WalError::InvalidHeader("digest overflow".to_string()))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| WalError::InvalidHeader("truncated digest".to_string()))?;
    Ok(value.try_into().expect("checked digest"))
}

fn encode_header(
    frame_type: FrameType,
    lsn: u64,
    transaction_id: [u8; 16],
    payload: &[u8],
) -> Result<[u8; WAL_HEADER_BYTES]> {
    let payload_bytes = u64::try_from(payload.len())
        .map_err(|_| WalError::PayloadTooLarge(u64::MAX))?;
    if payload_bytes > MAX_WAL_PAYLOAD_BYTES {
        return Err(WalError::PayloadTooLarge(payload_bytes));
    }
    let mut bytes = [0u8; WAL_HEADER_BYTES];
    bytes[0..8].copy_from_slice(&WAL_MAGIC);
    bytes[8..10].copy_from_slice(&WAL_MAJOR.to_le_bytes());
    bytes[10..12].copy_from_slice(&(frame_type as u16).to_le_bytes());
    bytes[12..16].copy_from_slice(&(WAL_HEADER_BYTES as u32).to_le_bytes());
    bytes[16..24].copy_from_slice(&lsn.to_le_bytes());
    bytes[24..40].copy_from_slice(&transaction_id);
    bytes[40..48].copy_from_slice(&payload_bytes.to_le_bytes());
    bytes[48..56].copy_from_slice(&0u64.to_le_bytes());
    bytes[56..88].copy_from_slice(&sha256(payload));
    bytes[88..96].copy_from_slice(&0u64.to_le_bytes());
    Ok(bytes)
}

fn decode_header(
    bytes: &[u8; WAL_HEADER_BYTES],
) -> Result<(FrameType, u64, [u8; 16], u64, [u8; 32])> {
    if &bytes[0..8] != &WAL_MAGIC[..] {
        return Err(WalError::InvalidHeader(
            "magic mismatch".to_string(),
        ));
    }
    let major = read_u16(bytes, 8)?;
    if major != WAL_MAJOR {
        return Err(WalError::InvalidHeader(format!(
            "unsupported major version {major}"
        )));
    }
    let frame_type = FrameType::from_u16(read_u16(bytes, 10)?)?;
    if read_u32(bytes, 12)? != WAL_HEADER_BYTES as u32 {
        return Err(WalError::InvalidHeader(
            "header_bytes is not 96".to_string(),
        ));
    }
    let lsn = read_u64(bytes, 16)?;
    if lsn == 0 {
        return Err(WalError::InvalidHeader(
            "LSN cannot be zero".to_string(),
        ));
    }
    let transaction_id: [u8; 16] =
        bytes[24..40].try_into().expect("fixed transaction ID");
    let payload_bytes = read_u64(bytes, 40)?;
    if payload_bytes > MAX_WAL_PAYLOAD_BYTES {
        return Err(WalError::PayloadTooLarge(payload_bytes));
    }
    if read_u64(bytes, 48)? != 0 || read_u64(bytes, 88)? != 0 {
        return Err(WalError::InvalidHeader(
            "flags or reserved are non-zero".to_string(),
        ));
    }
    let payload_hash = read_digest(bytes, 56)?;
    Ok((
        frame_type,
        lsn,
        transaction_id,
        payload_bytes,
        payload_hash,
    ))
}

pub fn scan_wal(path: &Path, repair_trailing: bool) -> Result<WalScan> {
    if !path.exists() {
        return Ok(WalScan {
            frames: Vec::new(),
            maximum_lsn: 0,
            repaired_trailing_bytes: 0,
            valid_bytes: 0,
        });
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(repair_trailing)
        .open(path)?;
    let file_bytes = file.metadata()?.len();
    let mut offset = 0u64;
    let mut previous_lsn = 0u64;
    let mut frames = Vec::new();

    while offset < file_bytes {
        let remaining = file_bytes - offset;
        if remaining < WAL_HEADER_BYTES as u64 {
            if repair_trailing {
                file.set_len(offset)?;
                file.sync_all()?;
                return Ok(WalScan {
                    maximum_lsn: previous_lsn,
                    frames,
                    repaired_trailing_bytes: remaining,
                    valid_bytes: offset,
                });
            }
            return Err(WalError::InvalidHeader(
                "incomplete final frame header".to_string(),
            ));
        }

        file.seek(SeekFrom::Start(offset))?;
        let mut header = [0u8; WAL_HEADER_BYTES];
        file.read_exact(&mut header)?;
        let (
            frame_type,
            lsn,
            transaction_id,
            payload_bytes,
            expected_hash,
        ) = decode_header(&header)?;

        if previous_lsn != 0 && lsn <= previous_lsn {
            return Err(WalError::NonMonotonicLsn {
                previous: previous_lsn,
                actual: lsn,
            });
        }

        let frame_bytes = (WAL_HEADER_BYTES as u64)
            .checked_add(payload_bytes)
            .ok_or_else(|| WalError::InvalidHeader(
                "frame length overflow".to_string()
            ))?;
        if remaining < frame_bytes {
            if repair_trailing {
                file.set_len(offset)?;
                file.sync_all()?;
                return Ok(WalScan {
                    maximum_lsn: previous_lsn,
                    frames,
                    repaired_trailing_bytes: remaining,
                    valid_bytes: offset,
                });
            }
            return Err(WalError::InvalidHeader(
                "incomplete final frame payload".to_string(),
            ));
        }

        let payload_len = usize::try_from(payload_bytes)
            .map_err(|_| WalError::PayloadTooLarge(payload_bytes))?;
        let mut payload = vec![0u8; payload_len];
        file.read_exact(&mut payload)?;
        let actual_hash = sha256(&payload);
        if actual_hash != expected_hash {
            return Err(WalError::Integrity {
                context: format!("frame LSN {lsn}"),
                expected: expected_hash,
                actual: actual_hash,
            });
        }

        frames.push(WalFrame {
            frame_type,
            lsn,
            transaction_id,
            payload,
        });
        previous_lsn = lsn;
        offset = offset
            .checked_add(frame_bytes)
            .ok_or_else(|| WalError::InvalidHeader(
                "WAL offset overflow".to_string()
            ))?;
    }

    Ok(WalScan {
        frames,
        maximum_lsn: previous_lsn,
        repaired_trailing_bytes: 0,
        valid_bytes: offset,
    })
}

pub struct WalWriter {
    path: PathBuf,
    file: File,
    next_lsn: u64,
}

impl WalWriter {
    pub fn open(path: impl AsRef<Path>, repair_trailing: bool) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let scan = scan_wal(&path, repair_trailing)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;
        Ok(Self {
            path,
            file,
            next_lsn: scan.maximum_lsn.saturating_add(1).max(1),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn next_lsn(&self) -> u64 {
        self.next_lsn
    }

    pub fn append(
        &mut self,
        frame_type: FrameType,
        transaction_id: [u8; 16],
        payload: &[u8],
    ) -> Result<u64> {
        let lsn = self.next_lsn;
        let header = encode_header(
            frame_type,
            lsn,
            transaction_id,
            payload,
        )?;
        self.file.write_all(&header)?;
        self.file.write_all(payload)?;
        self.next_lsn = self
            .next_lsn
            .checked_add(1)
            .ok_or_else(|| WalError::InvalidHeader(
                "LSN overflow".to_string()
            ))?;
        Ok(lsn)
    }

    pub fn flush_and_sync(&mut self) -> Result<()> {
        self.file.flush()?;
        self.file.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn path(name: &str) -> PathBuf {
        let value = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "ultraballoondb-wal-{name}-{}-{value}.ubwal",
            std::process::id()
        ))
    }

    #[test]
    fn roundtrip_and_monotonic_lsn() {
        let path = path("roundtrip");
        let mut writer = WalWriter::open(&path, true).unwrap();
        assert_eq!(
            writer.append(FrameType::Begin, [1; 16], b"begin").unwrap(),
            1
        );
        assert_eq!(
            writer.append(FrameType::Commit, [1; 16], b"commit").unwrap(),
            2
        );
        writer.flush_and_sync().unwrap();
        let scan = scan_wal(&path, false).unwrap();
        assert_eq!(scan.frames.len(), 2);
        assert_eq!(scan.maximum_lsn, 2);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn incomplete_tail_is_repaired() {
        let path = path("tail");
        let mut writer = WalWriter::open(&path, true).unwrap();
        writer.append(FrameType::Begin, [2; 16], b"x").unwrap();
        writer.flush_and_sync().unwrap();
        drop(writer);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"partial").unwrap();
        file.sync_all().unwrap();
        let scan = scan_wal(&path, true).unwrap();
        assert_eq!(scan.frames.len(), 1);
        assert_eq!(scan.repaired_trailing_bytes, 7);
        assert_eq!(scan_wal(&path, false).unwrap().frames.len(), 1);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn complete_corrupt_frame_is_rejected() {
        let path = path("corrupt");
        let mut writer = WalWriter::open(&path, true).unwrap();
        writer.append(FrameType::Begin, [3; 16], b"payload").unwrap();
        writer.flush_and_sync().unwrap();
        drop(writer);
        let mut bytes = fs::read(&path).unwrap();
        bytes[WAL_HEADER_BYTES] ^= 0x40;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            scan_wal(&path, true),
            Err(WalError::Integrity { .. })
        ));
        fs::remove_file(path).unwrap();
    }
}
