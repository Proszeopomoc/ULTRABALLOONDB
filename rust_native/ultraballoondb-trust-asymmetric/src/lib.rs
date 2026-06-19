mod cng;
mod cli;
mod ledger;
mod registry;

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

pub use cng::{
    create_persisted_key, delete_persisted_key,
    export_public_blob, private_export_rejected,
    provider_key_exists, sign_digest, validate_public_blob,
    verify_digest, write_public_blob, ProviderKeyMaterial,
    ALGORITHM_ECDSA_P256, ECDSA_P256_PUBLIC_BLOB_BYTES,
    ECDSA_P256_SIGNATURE_BYTES, PRIVATE_BLOB_TYPE,
    PUBLIC_BLOB_TYPE, SOFTWARE_KSP,
};
pub use cli::{main_entry, run_cli, CliError};
pub use ledger::{
    authorization_message_digest, AsymmetricAuthorization,
    AsymmetricAuthorizationLedger, AuthorizationReceipt,
};
pub use registry::{
    registry_event_subject_digest, AsymmetricKeyEvent,
    AsymmetricKeyEventKind, AsymmetricKeyRegistry,
    AsymmetricKeyState, KeyEventReceipt,
};

pub const VERSION: &str =
    "V00R3T6B_ASYMMETRIC_PUBLIC_KEY_REGISTRY_AND_SOFTWARE_CNG_SIGNATURE_CORE_R01";
pub const COMMAND_SCHEMA: &str =
    "ultraballoondb.trust.asymmetric.command.v1";

pub const DOMAIN_POLICY_REGISTER: u8 = 4;
pub const DOMAIN_TRUST_COMMIT: u8 = 5;
pub const DOMAIN_KEY_ROTATE: u8 = 6;
pub const DOMAIN_POLICY_REVOKE: u8 = 7;
pub const DOMAIN_FEDERATION_BUNDLE: u8 = 8;

#[derive(Debug)]
pub enum AsymmetricError {
    Io(io::Error),
    Invalid(String),
    Integrity(String),
    Provider(String),
    Truncated {
        context: &'static str,
        offset: usize,
        remaining_bytes: usize,
    },
}

impl fmt::Display for AsymmetricError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Invalid(message) => {
                write!(f, "invalid asymmetric operation: {message}")
            }
            Self::Integrity(message) => {
                write!(f, "asymmetric integrity error: {message}")
            }
            Self::Provider(message) => {
                write!(f, "CNG provider error: {message}")
            }
            Self::Truncated {
                context,
                offset,
                remaining_bytes,
            } => write!(
                f,
                "truncated {context} at offset {offset}: remaining_bytes={remaining_bytes}",
            ),
        }
    }
}

impl std::error::Error for AsymmetricError {}

impl From<io::Error> for AsymmetricError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, AsymmetricError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsymmetricPaths {
    pub root: PathBuf,
    pub key_registry: PathBuf,
    pub authorization_ledger: PathBuf,
}

impl AsymmetricPaths {
    pub fn from_root(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        Self {
            key_registry: root.join("asymmetric-keys.ubakey"),
            authorization_ledger: root.join(
                "asymmetric-authorizations.ubasig",
            ),
            root,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitReceipt {
    pub changed: bool,
    pub key_registry_changed: bool,
    pub authorization_ledger_changed: bool,
    pub key_registry_path: PathBuf,
    pub authorization_ledger_path: PathBuf,
}

pub fn init_asymmetric_root(
    root: impl AsRef<Path>,
) -> Result<InitReceipt> {
    let paths = AsymmetricPaths::from_root(root);
    std::fs::create_dir_all(&paths.root)?;

    let key_registry_changed =
        if paths.key_registry.exists() {
            AsymmetricKeyRegistry::open_strict(
                &paths.key_registry,
            )?;
            false
        } else {
            AsymmetricKeyRegistry::create(
                &paths.key_registry,
            )?;
            true
        };

    let authorization_ledger_changed =
        if paths.authorization_ledger.exists() {
            AsymmetricAuthorizationLedger::open_strict(
                &paths.authorization_ledger,
                &AsymmetricKeyRegistry::open_strict(
                    &paths.key_registry,
                )?,
            )?;
            false
        } else {
            AsymmetricAuthorizationLedger::create(
                &paths.authorization_ledger,
            )?;
            true
        };

    Ok(InitReceipt {
        changed: key_registry_changed
            || authorization_ledger_changed,
        key_registry_changed,
        authorization_ledger_changed,
        key_registry_path: paths.key_registry,
        authorization_ledger_path:
            paths.authorization_ledger,
    })
}

pub fn validate_identifier(
    name: &str,
    value: &str,
) -> Result<()> {
    if value.is_empty() || value.len() > 1024 {
        return Err(AsymmetricError::Invalid(format!(
            "{name} must contain 1..1024 UTF-8 bytes",
        )));
    }
    if value.chars().any(|character| character.is_control()) {
        return Err(AsymmetricError::Invalid(format!(
            "{name} contains a control character",
        )));
    }
    Ok(())
}

pub fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02X}")
            .expect("write to String");
    }
    output
}

pub fn parse_hex_digest(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err(AsymmetricError::Invalid(
            "digest must contain 64 hexadecimal characters"
                .to_string(),
        ));
    }
    let mut output = [0u8; 32];
    for index in 0..32 {
        output[index] = u8::from_str_radix(
            &value[index * 2..index * 2 + 2],
            16,
        )
        .map_err(|_| {
            AsymmetricError::Invalid(
                "digest contains non-hexadecimal character"
                    .to_string(),
            )
        })?;
    }
    if output == [0; 32] {
        return Err(AsymmetricError::Invalid(
            "zero digest is forbidden".to_string(),
        ));
    }
    Ok(output)
}
