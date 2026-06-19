use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ultraballoondb_storage::sha256;

pub const VERSION: &str = "V00R3C1_BACKUP_RESTORE_UPGRADE_DRY_RUN_R01";
pub const BACKUP_MANIFEST_FILE_NAME: &str = "backup-manifest.ubbackup";
pub const RESTORE_RECEIPT_FILE_NAME: &str = "restore-receipt.ubrestore";
pub const PAYLOAD_DIRECTORY_NAME: &str = "payload";

const MANIFEST_MAGIC: [u8; 8] = *b"UBBKP01\0";
const RECEIPT_MAGIC: [u8; 8] = *b"UBRST01\0";
const MANIFEST_DOMAIN: [u8; 8] = *b"UBBKMN01";
const PLAN_DOMAIN: [u8; 8] = *b"UBBKPL01";
const RECEIPT_DOMAIN: [u8; 8] = *b"UBBKRC01";
const FORMAT_VERSION: u16 = 1;
const MAX_FILES: usize = 1_000_000;
const MAX_PATH_BYTES: usize = 4096;
const MAX_ID_BYTES: usize = 1024;
const MAX_UPGRADE_STEPS: u64 = 64;
const COPY_BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub enum BackupError {
    Io(std::io::Error),
    Invalid(String),
    Integrity(String),
    Conflict(String),
    Truncated { context: &'static str, offset: usize },
}

impl fmt::Display for BackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Invalid(message) => write!(f, "invalid backup operation: {message}"),
            Self::Integrity(message) => write!(f, "backup integrity error: {message}"),
            Self::Conflict(message) => write!(f, "backup conflict: {message}"),
            Self::Truncated { context, offset } => {
                write!(f, "truncated {context} at offset {offset}")
            }
        }
    }
}

impl std::error::Error for BackupError {}
impl From<std::io::Error> for BackupError {
    fn from(value: std::io::Error) -> Self { Self::Io(value) }
}

pub type Result<T> = std::result::Result<T, BackupError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupRequest {
    pub backup_id: String,
    pub source_database_id: String,
    pub logical_timestamp: u64,
    pub source_schema_version: u64,
    pub provenance_head_digest: [u8; 32],
    pub relative_files: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupFileEntry {
    pub relative_path: String,
    pub size_bytes: u64,
    pub content_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupManifest {
    pub backup_id: String,
    pub source_database_id: String,
    pub logical_timestamp: u64,
    pub source_schema_version: u64,
    pub provenance_head_digest: [u8; 32],
    pub files: Vec<BackupFileEntry>,
    pub manifest_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeDryRun {
    pub source_schema_version: u64,
    pub target_schema_version: u64,
    pub step_count: u64,
    pub file_count: usize,
    pub total_bytes: u64,
    pub plan_digest: [u8; 32],
    pub would_write: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreDryRun {
    pub source_schema_version: u64,
    pub target_schema_version: u64,
    pub file_count: usize,
    pub total_bytes: u64,
    pub conflict_count: usize,
    pub plan_digest: [u8; 32],
    pub would_write: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreReceipt {
    pub logical_timestamp: u64,
    pub manifest_digest: [u8; 32],
    pub plan_digest: [u8; 32],
    pub file_count: usize,
    pub total_bytes: u64,
    pub receipt_digest: [u8; 32],
}

pub fn digest_file(path: impl AsRef<Path>) -> Result<([u8; 32], u64)> {
    let path = path.as_ref();
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BackupError::Invalid(format!("not a regular non-symlink file: {}", path.display())));
    }
    let mut file = File::open(path)?;
    let mut state = Sha256State::new();
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 { break; }
        state.update(&buffer[..read]);
        total = total.checked_add(read as u64)
            .ok_or_else(|| BackupError::Invalid("file size overflow".to_string()))?;
    }
    Ok((state.finalize(), total))
}

pub fn create_backup(
    source_root: impl AsRef<Path>,
    backup_root: impl AsRef<Path>,
    request: &BackupRequest,
) -> Result<BackupManifest> {
    validate_request(request)?;
    let source_root = fs::canonicalize(source_root.as_ref())?;
    if !source_root.is_dir() {
        return Err(BackupError::Invalid("source root is not a directory".to_string()));
    }
    let backup_root = absolute_new_path(backup_root.as_ref())?;
    if backup_root.exists() {
        return Err(BackupError::Conflict(format!("backup destination already exists: {}", backup_root.display())));
    }
    if backup_root.starts_with(&source_root) || source_root.starts_with(&backup_root) {
        return Err(BackupError::Invalid("source and backup roots overlap".to_string()));
    }
    let mut relative_files = request.relative_files.clone();
    for path in &relative_files { validate_relative_path(path)?; }
    relative_files.sort();
    if relative_files.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(BackupError::Invalid("duplicate relative backup path".to_string()));
    }

    let parent = backup_root.parent().ok_or_else(|| BackupError::Invalid("backup destination has no parent".to_string()))?;
    fs::create_dir_all(parent)?;
    let temporary = temporary_sibling(&backup_root, "backup")?;
    if temporary.exists() { fs::remove_dir_all(&temporary)?; }
    fs::create_dir(&temporary)?;
    let payload_root = temporary.join(PAYLOAD_DIRECTORY_NAME);
    fs::create_dir(&payload_root)?;

    let result = (|| {
        let mut files = Vec::with_capacity(relative_files.len());
        for relative in relative_files {
            let source = resolve_source_file(&source_root, &relative)?;
            let destination = join_relative(&payload_root, &relative);
            if let Some(parent) = destination.parent() { fs::create_dir_all(parent)?; }
            let (digest, size) = copy_stable_file(&source, &destination)?;
            files.push(BackupFileEntry {
                relative_path: relative,
                size_bytes: size,
                content_digest: digest,
            });
        }
        let mut manifest = BackupManifest {
            backup_id: request.backup_id.clone(),
            source_database_id: request.source_database_id.clone(),
            logical_timestamp: request.logical_timestamp,
            source_schema_version: request.source_schema_version,
            provenance_head_digest: request.provenance_head_digest,
            files,
            manifest_digest: [0u8; 32],
        };
        let encoded = encode_manifest(&manifest)?;
        manifest.manifest_digest = encoded[encoded.len() - 32..].try_into().expect("digest length");
        let manifest_path = temporary.join(BACKUP_MANIFEST_FILE_NAME);
        write_new_synced(&manifest_path, &encoded)?;
        verify_backup_directory(&temporary)?;
        fs::rename(&temporary, &backup_root)?;
        open_backup_strict(&backup_root)
    })();
    if result.is_err() { let _ = fs::remove_dir_all(&temporary); }
    result
}

pub fn open_backup_strict(backup_root: impl AsRef<Path>) -> Result<BackupManifest> {
    let backup_root = backup_root.as_ref();
    let metadata = fs::symlink_metadata(backup_root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BackupError::Invalid("backup root is not a regular directory".to_string()));
    }
    verify_backup_root_entries(backup_root)?;
    let manifest = decode_manifest(&fs::read(backup_root.join(BACKUP_MANIFEST_FILE_NAME))?)?;
    verify_payload(backup_root, &manifest)?;
    Ok(manifest)
}

pub fn upgrade_dry_run(
    backup_root: impl AsRef<Path>,
    target_schema_version: u64,
) -> Result<UpgradeDryRun> {
    let manifest = open_backup_strict(backup_root)?;
    upgrade_plan(&manifest, target_schema_version)
}

pub fn restore_dry_run(
    backup_root: impl AsRef<Path>,
    destination_root: impl AsRef<Path>,
    target_schema_version: u64,
) -> Result<RestoreDryRun> {
    let manifest = open_backup_strict(backup_root)?;
    let upgrade = upgrade_plan(&manifest, target_schema_version)?;
    let destination_root = destination_root.as_ref();
    let mut conflicts = 0usize;
    if destination_root.exists() {
        let metadata = fs::symlink_metadata(destination_root)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            conflicts = manifest.files.len().max(1);
        } else {
            for entry in &manifest.files {
                let target = join_relative(destination_root, &entry.relative_path);
                if target.exists() || parent_component_is_file(destination_root, &entry.relative_path)? {
                    conflicts += 1;
                }
            }
        }
    } else {
        for entry in &manifest.files {
            let target = join_relative(destination_root, &entry.relative_path);
            if target.exists() || parent_component_is_file(destination_root, &entry.relative_path)? {
                conflicts += 1;
            }
        }
    }
    Ok(RestoreDryRun {
        source_schema_version: manifest.source_schema_version,
        target_schema_version,
        file_count: manifest.files.len(),
        total_bytes: upgrade.total_bytes,
        conflict_count: conflicts,
        plan_digest: upgrade.plan_digest,
        would_write: false,
    })
}

pub fn restore_to_new_directory(
    backup_root: impl AsRef<Path>,
    destination_root: impl AsRef<Path>,
    expected_plan_digest: [u8; 32],
) -> Result<RestoreReceipt> {
    let backup_root = fs::canonicalize(backup_root.as_ref())?;
    let manifest = open_backup_strict(&backup_root)?;
    let plan = upgrade_plan(&manifest, manifest.source_schema_version)?;
    if plan.plan_digest != expected_plan_digest {
        return Err(BackupError::Integrity("restore plan digest mismatch".to_string()));
    }
    let destination_root = absolute_new_path(destination_root.as_ref())?;
    if destination_root.exists() {
        return Err(BackupError::Conflict(format!("restore destination already exists: {}", destination_root.display())));
    }
    if destination_root.starts_with(&backup_root) || backup_root.starts_with(&destination_root) {
        return Err(BackupError::Invalid("backup and restore roots overlap".to_string()));
    }
    let parent = destination_root.parent().ok_or_else(|| BackupError::Invalid("restore destination has no parent".to_string()))?;
    fs::create_dir_all(parent)?;
    let temporary = temporary_sibling(&destination_root, "restore")?;
    if temporary.exists() { fs::remove_dir_all(&temporary)?; }
    fs::create_dir(&temporary)?;

    let result = (|| {
        for entry in &manifest.files {
            let source = join_relative(&backup_root.join(PAYLOAD_DIRECTORY_NAME), &entry.relative_path);
            let destination = join_relative(&temporary, &entry.relative_path);
            if let Some(parent) = destination.parent() { fs::create_dir_all(parent)?; }
            copy_verified_file(&source, &destination, entry.size_bytes, entry.content_digest)?;
        }
        let mut receipt = RestoreReceipt {
            logical_timestamp: manifest.logical_timestamp,
            manifest_digest: manifest.manifest_digest,
            plan_digest: plan.plan_digest,
            file_count: manifest.files.len(),
            total_bytes: plan.total_bytes,
            receipt_digest: [0u8; 32],
        };
        let encoded = encode_receipt(&receipt)?;
        receipt.receipt_digest = encoded[encoded.len() - 32..].try_into().expect("digest length");
        write_new_synced(&temporary.join(RESTORE_RECEIPT_FILE_NAME), &encoded)?;
        verify_restored_directory(&temporary, &manifest, &receipt)?;
        fs::rename(&temporary, &destination_root)?;
        read_restore_receipt(destination_root.join(RESTORE_RECEIPT_FILE_NAME))
    })();
    if result.is_err() { let _ = fs::remove_dir_all(&temporary); }
    result
}

pub fn read_restore_receipt(path: impl AsRef<Path>) -> Result<RestoreReceipt> {
    decode_receipt(&fs::read(path)?)
}

fn validate_request(request: &BackupRequest) -> Result<()> {
    validate_id("backup_id", &request.backup_id)?;
    validate_id("source_database_id", &request.source_database_id)?;
    if request.logical_timestamp == 0 { return Err(BackupError::Invalid("logical timestamp must be nonzero".to_string())); }
    if request.source_schema_version == 0 { return Err(BackupError::Invalid("source schema version must be nonzero".to_string())); }
    if request.provenance_head_digest == [0u8; 32] { return Err(BackupError::Invalid("provenance head digest must be nonzero".to_string())); }
    if request.relative_files.is_empty() || request.relative_files.len() > MAX_FILES {
        return Err(BackupError::Invalid("backup file count outside bounds".to_string()));
    }
    Ok(())
}

fn validate_id(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.as_bytes().len() > MAX_ID_BYTES || value.as_bytes().contains(&0) || value.chars().any(char::is_control) {
        return Err(BackupError::Invalid(format!("{name} is empty or outside bounds")));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<()> {
    if value.is_empty() || value.as_bytes().len() > MAX_PATH_BYTES || value.contains('\\') || value.contains('\0') || value.contains(':') {
        return Err(BackupError::Invalid(format!("invalid relative path: {value}")));
    }
    let path = Path::new(value);
    if path.is_absolute() { return Err(BackupError::Invalid(format!("absolute path rejected: {value}"))); }
    let mut count = 0usize;
    for component in path.components() {
        match component {
            Component::Normal(part) if !part.is_empty() => count += 1,
            _ => return Err(BackupError::Invalid(format!("unsafe path component: {value}"))),
        }
    }
    if count == 0 { return Err(BackupError::Invalid("empty relative path".to_string())); }
    Ok(())
}

fn join_relative(root: &Path, relative: &str) -> PathBuf {
    let mut output = root.to_path_buf();
    for part in relative.split('/') { output.push(part); }
    output
}

fn resolve_source_file(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_relative_path(relative)?;
    let mut current = root.to_path_buf();
    for part in relative.split('/') {
        current.push(part);
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            return Err(BackupError::Invalid(format!("symlink rejected: {}", current.display())));
        }
    }
    let canonical = fs::canonicalize(&current)?;
    if !canonical.starts_with(root) {
        return Err(BackupError::Invalid("source path escapes source root".to_string()));
    }
    let metadata = fs::metadata(&canonical)?;
    if !metadata.is_file() {
        return Err(BackupError::Invalid(format!("source is not a file: {}", canonical.display())));
    }
    Ok(canonical)
}

fn copy_stable_file(source: &Path, destination: &Path) -> Result<([u8; 32], u64)> {
    let first = copy_stream_and_digest(source, destination)?;
    let second = digest_file(source)?;
    if first != second {
        let _ = fs::remove_file(destination);
        return Err(BackupError::Conflict(format!("source changed while backing up: {}", source.display())));
    }
    let destination_digest = digest_file(destination)?;
    if destination_digest != first {
        let _ = fs::remove_file(destination);
        return Err(BackupError::Integrity(format!("copied payload verification failed: {}", destination.display())));
    }
    Ok(first)
}

fn copy_stream_and_digest(source: &Path, destination: &Path) -> Result<([u8; 32], u64)> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BackupError::Invalid("copy source is not a regular file".to_string()));
    }
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new().create_new(true).write(true).open(destination)?;
    let mut state = Sha256State::new();
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    let mut total = 0u64;
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 { break; }
        output.write_all(&buffer[..read])?;
        state.update(&buffer[..read]);
        total = total.checked_add(read as u64)
            .ok_or_else(|| BackupError::Invalid("file size overflow".to_string()))?;
    }
    output.flush()?;
    output.sync_all()?;
    Ok((state.finalize(), total))
}

fn copy_verified_file(source: &Path, destination: &Path, expected_size: u64, expected_digest: [u8; 32]) -> Result<()> {
    let (digest, size) = copy_stream_and_digest(source, destination)?;
    if size != expected_size || digest != expected_digest {
        let _ = fs::remove_file(destination);
        return Err(BackupError::Integrity(format!("restore copy mismatch: {}", source.display())));
    }
    Ok(())
}

fn verify_backup_directory(root: &Path) -> Result<()> {
    verify_backup_root_entries(root)?;
    let manifest = decode_manifest(&fs::read(root.join(BACKUP_MANIFEST_FILE_NAME))?)?;
    verify_payload(root, &manifest)
}

fn verify_backup_root_entries(root: &Path) -> Result<()> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(BackupError::Integrity(format!("symlink found in backup root: {}", path.display())));
        }
        let name = entry.file_name().into_string().map_err(|_| BackupError::Integrity("non-UTF8 backup root entry rejected".to_string()))?;
        names.insert(name);
    }
    let expected = BTreeSet::from([BACKUP_MANIFEST_FILE_NAME.to_string(), PAYLOAD_DIRECTORY_NAME.to_string()]);
    if names != expected {
        return Err(BackupError::Integrity("backup root entry set mismatch".to_string()));
    }
    let manifest_metadata = fs::symlink_metadata(root.join(BACKUP_MANIFEST_FILE_NAME))?;
    let payload_metadata = fs::symlink_metadata(root.join(PAYLOAD_DIRECTORY_NAME))?;
    if !manifest_metadata.is_file() || !payload_metadata.is_dir() {
        return Err(BackupError::Integrity("backup root entry types mismatch".to_string()));
    }
    Ok(())
}

fn verify_payload(root: &Path, manifest: &BackupManifest) -> Result<()> {
    let payload = root.join(PAYLOAD_DIRECTORY_NAME);
    let metadata = fs::symlink_metadata(&payload)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BackupError::Integrity("payload directory missing or unsafe".to_string()));
    }
    let expected: BTreeSet<String> = manifest.files.iter().map(|entry| entry.relative_path.clone()).collect();
    let actual = collect_regular_files(&payload, &payload)?;
    if actual != expected {
        return Err(BackupError::Integrity(format!("payload file set mismatch expected={} actual={}", expected.len(), actual.len())));
    }
    for entry in &manifest.files {
        let path = join_relative(&payload, &entry.relative_path);
        let (digest, size) = digest_file(&path)?;
        if size != entry.size_bytes || digest != entry.content_digest {
            return Err(BackupError::Integrity(format!("payload content mismatch: {}", entry.relative_path)));
        }
    }
    Ok(())
}

fn verify_restored_directory(root: &Path, manifest: &BackupManifest, receipt: &RestoreReceipt) -> Result<()> {
    let expected: BTreeSet<String> = manifest.files.iter().map(|entry| entry.relative_path.clone()).collect();
    let mut actual = collect_regular_files(root, root)?;
    actual.remove(RESTORE_RECEIPT_FILE_NAME);
    if actual != expected {
        return Err(BackupError::Integrity("restored file set mismatch".to_string()));
    }
    for entry in &manifest.files {
        let (digest, size) = digest_file(join_relative(root, &entry.relative_path))?;
        if digest != entry.content_digest || size != entry.size_bytes {
            return Err(BackupError::Integrity(format!("restored content mismatch: {}", entry.relative_path)));
        }
    }
    let decoded = read_restore_receipt(root.join(RESTORE_RECEIPT_FILE_NAME))?;
    if decoded != *receipt { return Err(BackupError::Integrity("restore receipt mismatch".to_string())); }
    Ok(())
}

fn collect_regular_files(root: &Path, current: &Path) -> Result<BTreeSet<String>> {
    let mut output = BTreeSet::new();
    collect_regular_files_inner(root, current, &mut output)?;
    Ok(output)
}

fn collect_regular_files_inner(root: &Path, current: &Path, output: &mut BTreeSet<String>) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(current)?.collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(BackupError::Integrity(format!("symlink found in payload: {}", path.display())));
        }
        if metadata.is_dir() {
            collect_regular_files_inner(root, &path, output)?;
        } else if metadata.is_file() {
            let relative = path.strip_prefix(root).map_err(|_| BackupError::Integrity("payload path escaped root".to_string()))?;
            let mut parts = Vec::new();
            for component in relative.components() {
                let part = component.as_os_str().to_str().ok_or_else(|| BackupError::Integrity("non-UTF8 payload path rejected".to_string()))?;
                parts.push(part.to_string());
            }
            let normalized = parts.join("/");
            validate_relative_path(&normalized)?;
            output.insert(normalized);
        } else {
            return Err(BackupError::Integrity(format!("non-regular payload entry: {}", path.display())));
        }
    }
    Ok(())
}

fn parent_component_is_file(root: &Path, relative: &str) -> Result<bool> {
    validate_relative_path(relative)?;
    let mut current = root.to_path_buf();
    let parts: Vec<_> = relative.split('/').collect();
    for part in parts.iter().take(parts.len().saturating_sub(1)) {
        current.push(part);
        if current.exists() {
            let metadata = fs::symlink_metadata(&current)?;
            if metadata.file_type().is_symlink() || metadata.is_file() { return Ok(true); }
        }
    }
    Ok(false)
}

fn upgrade_plan(manifest: &BackupManifest, target_schema_version: u64) -> Result<UpgradeDryRun> {
    if target_schema_version == 0 {
        return Err(BackupError::Invalid("target schema version must be nonzero".to_string()));
    }
    if target_schema_version < manifest.source_schema_version {
        return Err(BackupError::Invalid("schema downgrade rejected".to_string()));
    }
    let steps = target_schema_version - manifest.source_schema_version;
    if steps > MAX_UPGRADE_STEPS {
        return Err(BackupError::Invalid("upgrade step count exceeds bounded maximum".to_string()));
    }
    let total_bytes = manifest.files.iter().try_fold(0u64, |sum, entry| sum.checked_add(entry.size_bytes).ok_or_else(|| BackupError::Invalid("total byte count overflow".to_string())))?;
    let plan_digest = compute_plan_digest(manifest, target_schema_version, total_bytes)?;
    Ok(UpgradeDryRun {
        source_schema_version: manifest.source_schema_version,
        target_schema_version,
        step_count: steps,
        file_count: manifest.files.len(),
        total_bytes,
        plan_digest,
        would_write: false,
    })
}

fn compute_plan_digest(manifest: &BackupManifest, target_schema_version: u64, total_bytes: u64) -> Result<[u8; 32]> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&PLAN_DOMAIN);
    bytes.extend_from_slice(&manifest.manifest_digest);
    bytes.extend_from_slice(&manifest.source_schema_version.to_le_bytes());
    bytes.extend_from_slice(&target_schema_version.to_le_bytes());
    bytes.extend_from_slice(&(manifest.files.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&total_bytes.to_le_bytes());
    for entry in &manifest.files {
        put_string(&mut bytes, &entry.relative_path)?;
        bytes.extend_from_slice(&entry.size_bytes.to_le_bytes());
        bytes.extend_from_slice(&entry.content_digest);
    }
    Ok(sha256(&bytes))
}

fn encode_manifest(manifest: &BackupManifest) -> Result<Vec<u8>> {
    validate_id("backup_id", &manifest.backup_id)?;
    validate_id("source_database_id", &manifest.source_database_id)?;
    if manifest.logical_timestamp == 0 || manifest.source_schema_version == 0 || manifest.provenance_head_digest == [0u8; 32] {
        return Err(BackupError::Invalid("manifest required field missing".to_string()));
    }
    if manifest.files.is_empty() || manifest.files.len() > MAX_FILES {
        return Err(BackupError::Invalid("manifest file count outside bounds".to_string()));
    }
    let mut last: Option<&str> = None;
    let mut content = Vec::new();
    content.extend_from_slice(&MANIFEST_MAGIC);
    content.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    content.extend_from_slice(&0u16.to_le_bytes());
    content.extend_from_slice(&manifest.logical_timestamp.to_le_bytes());
    content.extend_from_slice(&manifest.source_schema_version.to_le_bytes());
    put_string(&mut content, &manifest.backup_id)?;
    put_string(&mut content, &manifest.source_database_id)?;
    content.extend_from_slice(&manifest.provenance_head_digest);
    content.extend_from_slice(&(manifest.files.len() as u32).to_le_bytes());
    for entry in &manifest.files {
        validate_relative_path(&entry.relative_path)?;
        if let Some(previous) = last {
            if previous >= entry.relative_path.as_str() {
                return Err(BackupError::Invalid("manifest paths are not strictly sorted".to_string()));
            }
        }
        last = Some(&entry.relative_path);
        put_string(&mut content, &entry.relative_path)?;
        content.extend_from_slice(&entry.size_bytes.to_le_bytes());
        content.extend_from_slice(&entry.content_digest);
    }
    let mut digest_input = Vec::with_capacity(MANIFEST_DOMAIN.len() + content.len());
    digest_input.extend_from_slice(&MANIFEST_DOMAIN);
    digest_input.extend_from_slice(&content);
    content.extend_from_slice(&sha256(&digest_input));
    Ok(content)
}

fn decode_manifest(data: &[u8]) -> Result<BackupManifest> {
    if data.len() < 8 + 2 + 2 + 8 + 8 + 4 + 4 + 32 + 4 + 32 {
        return Err(BackupError::Truncated { context: "backup manifest", offset: data.len() });
    }
    let content_end = data.len() - 32;
    let stored_digest: [u8; 32] = data[content_end..].try_into().expect("digest length");
    let mut digest_input = Vec::with_capacity(MANIFEST_DOMAIN.len() + content_end);
    digest_input.extend_from_slice(&MANIFEST_DOMAIN);
    digest_input.extend_from_slice(&data[..content_end]);
    if sha256(&digest_input) != stored_digest {
        return Err(BackupError::Integrity("manifest digest mismatch".to_string()));
    }
    let mut cursor = 0usize;
    if take(data, &mut cursor, 8, "manifest magic")? != MANIFEST_MAGIC.as_slice() {
        return Err(BackupError::Invalid("manifest magic mismatch".to_string()));
    }
    let version = read_u16(data, &mut cursor, "manifest version")?;
    let flags = read_u16(data, &mut cursor, "manifest flags")?;
    if version != FORMAT_VERSION || flags != 0 {
        return Err(BackupError::Invalid("manifest version or flags mismatch".to_string()));
    }
    let logical_timestamp = read_u64(data, &mut cursor, "logical timestamp")?;
    let source_schema_version = read_u64(data, &mut cursor, "source schema version")?;
    let backup_id = read_string(data, &mut cursor, "backup id")?;
    let source_database_id = read_string(data, &mut cursor, "database id")?;
    let provenance_head_digest = read_digest(data, &mut cursor, "provenance digest")?;
    let file_count = read_u32(data, &mut cursor, "file count")? as usize;
    if file_count == 0 || file_count > MAX_FILES {
        return Err(BackupError::Invalid("manifest file count outside bounds".to_string()));
    }
    let mut files = Vec::with_capacity(file_count);
    let mut last: Option<String> = None;
    for _ in 0..file_count {
        let relative_path = read_string(data, &mut cursor, "relative path")?;
        validate_relative_path(&relative_path)?;
        if last.as_deref().is_some_and(|previous| previous >= relative_path.as_str()) {
            return Err(BackupError::Invalid("manifest paths are not strictly sorted".to_string()));
        }
        last = Some(relative_path.clone());
        let size_bytes = read_u64(data, &mut cursor, "file size")?;
        let content_digest = read_digest(data, &mut cursor, "file digest")?;
        files.push(BackupFileEntry { relative_path, size_bytes, content_digest });
    }
    if cursor != content_end {
        return Err(BackupError::Invalid("manifest trailing bytes".to_string()));
    }
    let manifest = BackupManifest {
        backup_id,
        source_database_id,
        logical_timestamp,
        source_schema_version,
        provenance_head_digest,
        files,
        manifest_digest: stored_digest,
    };
    validate_id("backup_id", &manifest.backup_id)?;
    validate_id("source_database_id", &manifest.source_database_id)?;
    if manifest.logical_timestamp == 0 || manifest.source_schema_version == 0 || manifest.provenance_head_digest == [0u8; 32] {
        return Err(BackupError::Invalid("manifest required field missing".to_string()));
    }
    Ok(manifest)
}

fn encode_receipt(receipt: &RestoreReceipt) -> Result<Vec<u8>> {
    let file_count = u32::try_from(receipt.file_count).map_err(|_| BackupError::Invalid("receipt file count overflow".to_string()))?;
    let mut content = Vec::new();
    content.extend_from_slice(&RECEIPT_MAGIC);
    content.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    content.extend_from_slice(&0u16.to_le_bytes());
    content.extend_from_slice(&receipt.logical_timestamp.to_le_bytes());
    content.extend_from_slice(&receipt.manifest_digest);
    content.extend_from_slice(&receipt.plan_digest);
    content.extend_from_slice(&file_count.to_le_bytes());
    content.extend_from_slice(&receipt.total_bytes.to_le_bytes());
    let mut digest_input = Vec::with_capacity(RECEIPT_DOMAIN.len() + content.len());
    digest_input.extend_from_slice(&RECEIPT_DOMAIN);
    digest_input.extend_from_slice(&content);
    content.extend_from_slice(&sha256(&digest_input));
    Ok(content)
}

fn decode_receipt(data: &[u8]) -> Result<RestoreReceipt> {
    const RECEIPT_BYTES: usize = 128;
    if data.len() != RECEIPT_BYTES {
        return Err(BackupError::Truncated { context: "restore receipt", offset: data.len() });
    }
    let content_end = data.len() - 32;
    let stored_digest: [u8; 32] = data[content_end..].try_into().expect("digest length");
    let mut digest_input = Vec::with_capacity(RECEIPT_DOMAIN.len() + content_end);
    digest_input.extend_from_slice(&RECEIPT_DOMAIN);
    digest_input.extend_from_slice(&data[..content_end]);
    if sha256(&digest_input) != stored_digest {
        return Err(BackupError::Integrity("restore receipt digest mismatch".to_string()));
    }
    let mut cursor = 0usize;
    if take(data, &mut cursor, 8, "receipt magic")? != RECEIPT_MAGIC.as_slice() {
        return Err(BackupError::Invalid("restore receipt magic mismatch".to_string()));
    }
    if read_u16(data, &mut cursor, "receipt version")? != FORMAT_VERSION || read_u16(data, &mut cursor, "receipt flags")? != 0 {
        return Err(BackupError::Invalid("restore receipt version or flags mismatch".to_string()));
    }
    let logical_timestamp = read_u64(data, &mut cursor, "receipt timestamp")?;
    let manifest_digest = read_digest(data, &mut cursor, "receipt manifest digest")?;
    let plan_digest = read_digest(data, &mut cursor, "receipt plan digest")?;
    let file_count = read_u32(data, &mut cursor, "receipt file count")? as usize;
    let total_bytes = read_u64(data, &mut cursor, "receipt total bytes")?;
    if cursor != content_end { return Err(BackupError::Invalid("restore receipt trailing bytes".to_string())); }
    Ok(RestoreReceipt {
        logical_timestamp,
        manifest_digest,
        plan_digest,
        file_count,
        total_bytes,
        receipt_digest: stored_digest,
    })
}

fn put_string(output: &mut Vec<u8>, value: &str) -> Result<()> {
    if value.as_bytes().len() > MAX_PATH_BYTES.max(MAX_ID_BYTES) {
        return Err(BackupError::Invalid("string exceeds format bounds".to_string()));
    }
    let length = u32::try_from(value.as_bytes().len()).map_err(|_| BackupError::Invalid("string length overflow".to_string()))?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn take<'a>(data: &'a [u8], cursor: &mut usize, count: usize, context: &'static str) -> Result<&'a [u8]> {
    let end = cursor.checked_add(count).ok_or_else(|| BackupError::Truncated { context, offset: *cursor })?;
    if end > data.len() { return Err(BackupError::Truncated { context, offset: *cursor }); }
    let value = &data[*cursor..end];
    *cursor = end;
    Ok(value)
}

fn read_u16(data: &[u8], cursor: &mut usize, context: &'static str) -> Result<u16> {
    Ok(u16::from_le_bytes(take(data, cursor, 2, context)?.try_into().expect("u16 length")))
}
fn read_u32(data: &[u8], cursor: &mut usize, context: &'static str) -> Result<u32> {
    Ok(u32::from_le_bytes(take(data, cursor, 4, context)?.try_into().expect("u32 length")))
}
fn read_u64(data: &[u8], cursor: &mut usize, context: &'static str) -> Result<u64> {
    Ok(u64::from_le_bytes(take(data, cursor, 8, context)?.try_into().expect("u64 length")))
}
fn read_digest(data: &[u8], cursor: &mut usize, context: &'static str) -> Result<[u8; 32]> {
    Ok(take(data, cursor, 32, context)?.try_into().expect("digest length"))
}
fn read_string(data: &[u8], cursor: &mut usize, context: &'static str) -> Result<String> {
    let length = read_u32(data, cursor, context)? as usize;
    if length == 0 || length > MAX_PATH_BYTES.max(MAX_ID_BYTES) {
        return Err(BackupError::Invalid(format!("{context} length outside bounds")));
    }
    String::from_utf8(take(data, cursor, length, context)?.to_vec())
        .map_err(|_| BackupError::Invalid(format!("{context} is not UTF-8")))
}

fn absolute_new_path(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() { return Err(BackupError::Invalid("empty destination path".to_string())); }
    let parent = path.parent().ok_or_else(|| BackupError::Invalid("destination has no parent".to_string()))?;
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BackupError::Invalid("destination parent must be an existing non-symlink directory".to_string()));
    }
    let parent = fs::canonicalize(parent)?;
    let name = path.file_name().ok_or_else(|| BackupError::Invalid("destination has no final component".to_string()))?;
    Ok(parent.join(name))
}

fn temporary_sibling(destination: &Path, label: &str) -> Result<PathBuf> {
    let parent = destination.parent().ok_or_else(|| BackupError::Invalid("destination has no parent".to_string()))?;
    let name = destination.file_name().ok_or_else(|| BackupError::Invalid("destination has no name".to_string()))?.to_string_lossy();
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    Ok(parent.join(format!(".{name}.{label}.tmp-{}-{nanos}", std::process::id())))
}

fn write_new_synced(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(data)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

#[derive(Clone)]
struct Sha256State {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    message_len: u64,
}

impl Sha256State {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            message_len: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.message_len = self.message_len.wrapping_add(input.len() as u64);
        if self.buffer_len != 0 {
            let take = (64 - self.buffer_len).min(input.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&input[..take]);
            self.buffer_len += take;
            input = &input[take..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }
        while input.len() >= 64 {
            let block: [u8; 64] = input[..64].try_into().expect("block length");
            self.compress(&block);
            input = &input[64..];
        }
        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.message_len.wrapping_mul(8);
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            for byte in &mut self.buffer[self.buffer_len..] { *byte = 0; }
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0u8; 64];
            self.buffer_len = 0;
        }
        for byte in &mut self.buffer[self.buffer_len..56] { *byte = 0; }
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
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
        ];
        let mut w = [0u32; 64];
        for index in 0..16 {
            w[index] = u32::from_be_bytes(block[index * 4..index * 4 + 4].try_into().expect("word length"));
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7) ^ w[index - 15].rotate_right(18) ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17) ^ w[index - 2].rotate_right(19) ^ (w[index - 2] >> 10);
            w[index] = w[index - 16].wrapping_add(s0).wrapping_add(w[index - 7]).wrapping_add(s1);
        }
        let mut a = self.state[0]; let mut b = self.state[1]; let mut c = self.state[2]; let mut d = self.state[3];
        let mut e = self.state[4]; let mut f = self.state[5]; let mut g = self.state[6]; let mut h = self.state[7];
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[index]).wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g; g = f; f = e; e = d.wrapping_add(temp1); d = c; c = b; b = a; a = temp1.wrapping_add(temp2);
        }
        self.state[0] = self.state[0].wrapping_add(a); self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c); self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e); self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g); self.state[7] = self.state[7].wrapping_add(h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_root(label: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        std::env::temp_dir().join(format!("ubdb-c1-test-{label}-{}-{nanos}", std::process::id()))
    }

    fn fixture() -> (PathBuf, PathBuf, BackupRequest) {
        let root = temporary_root("fixture");
        let source = root.join("source");
        let backup = root.join("backup");
        fs::create_dir_all(source.join("storage")).unwrap();
        fs::create_dir_all(source.join("wal")).unwrap();
        fs::write(source.join("storage/database.ubdb"), b"database-fixture-v1").unwrap();
        fs::write(source.join("wal/database.ubwal"), b"wal-fixture-v1").unwrap();
        let request = BackupRequest {
            backup_id: "backup-test-1".to_string(),
            source_database_id: "database-test-1".to_string(),
            logical_timestamp: 100,
            source_schema_version: 3,
            provenance_head_digest: sha256(b"provenance-head"),
            relative_files: vec!["storage/database.ubdb".to_string(), "wal/database.ubwal".to_string()],
        };
        (source, backup, request)
    }

    #[test]
    fn streaming_sha256_matches_storage_sha256() {
        let mut state = Sha256State::new();
        state.update(b"a"); state.update(b"bc");
        assert_eq!(state.finalize(), sha256(b"abc"));
    }

    #[test]
    fn streaming_sha256_matches_large_storage_sha256() {
        let data: Vec<u8> = (0..200_003).map(|index| (index % 251) as u8).collect();
        let mut state = Sha256State::new();
        for chunk in data.chunks(777) { state.update(chunk); }
        assert_eq!(state.finalize(), sha256(&data));
    }

    #[test]
    fn rejects_unsafe_paths() {
        for value in ["", "../x", "a/../b", "a\\b", "/root", "C:/x", "./x"] {
            assert!(validate_relative_path(value).is_err(), "{value}");
        }
        assert!(validate_relative_path("storage/database.ubdb").is_ok());
    }

    #[test]
    fn backup_restore_and_dry_run_round_trip() {
        let (source, backup, request) = fixture();
        let root = source.parent().unwrap().to_path_buf();
        let manifest = create_backup(&source, &backup, &request).unwrap();
        assert_eq!(manifest.files.len(), 2);
        let upgrade = upgrade_dry_run(&backup, 5).unwrap();
        assert_eq!(upgrade.step_count, 2);
        assert!(!upgrade.would_write);
        let destination = root.join("restore");
        let dry = restore_dry_run(&backup, &destination, 3).unwrap();
        assert_eq!(dry.conflict_count, 0);
        assert!(!destination.exists());
        let receipt = restore_to_new_directory(&backup, &destination, dry.plan_digest).unwrap();
        assert_eq!(receipt.file_count, 2);
        assert_eq!(fs::read(destination.join("storage/database.ubdb")).unwrap(), b"database-fixture-v1");
        assert!(restore_to_new_directory(&backup, &destination, dry.plan_digest).is_err());
        assert!(upgrade_dry_run(&backup, 2).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn strict_replay_rejects_tamper_truncation_and_extra_files() {
        let (source, backup, request) = fixture();
        let root = source.parent().unwrap().to_path_buf();
        create_backup(&source, &backup, &request).unwrap();
        let payload = backup.join("payload/storage/database.ubdb");
        let original_payload = fs::read(&payload).unwrap();
        fs::write(&payload, b"tampered").unwrap();
        assert!(open_backup_strict(&backup).is_err());
        fs::write(&payload, original_payload).unwrap();
        let manifest_path = backup.join(BACKUP_MANIFEST_FILE_NAME);
        let original_manifest = fs::read(&manifest_path).unwrap();
        fs::write(&manifest_path, &original_manifest[..original_manifest.len() - 1]).unwrap();
        assert!(open_backup_strict(&backup).is_err());
        fs::write(&manifest_path, original_manifest).unwrap();
        fs::write(backup.join("payload/extra.bin"), b"extra").unwrap();
        assert!(open_backup_strict(&backup).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
