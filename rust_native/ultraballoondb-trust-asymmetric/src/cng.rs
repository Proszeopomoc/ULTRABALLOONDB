use crate::{AsymmetricError, Result};

pub const SOFTWARE_KSP: &str =
    "Microsoft Software Key Storage Provider";
pub const ALGORITHM_ECDSA_P256: &str = "ECDSA_P256";
pub const PUBLIC_BLOB_TYPE: &str = "ECCPUBLICBLOB";
pub const PRIVATE_BLOB_TYPE: &str = "PKCS8_PRIVATEKEY";
pub const ECDSA_P256_PUBLIC_BLOB_BYTES: usize = 72;
pub const ECDSA_P256_SIGNATURE_BYTES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderKeyMaterial {
    pub provider_name: String,
    pub provider_key_name: String,
    pub public_blob: Vec<u8>,
    pub private_export_rejected: bool,
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::{ffi::OsStr, ptr};

    type Handle = usize;
    type Status = i32;
    type Dword = u32;

    const SUCCESS: Status = 0;
    const NCRYPT_SILENT_FLAG: Dword = 0x00000040;
    const NCRYPT_EXPORT_POLICY_PROPERTY: &str = "Export Policy";

    #[link(name = "ncrypt")]
    extern "system" {
        fn NCryptOpenStorageProvider(
            ph_provider: *mut Handle,
            provider_name: *const u16,
            flags: Dword,
        ) -> Status;
        fn NCryptCreatePersistedKey(
            provider: Handle,
            ph_key: *mut Handle,
            algorithm_id: *const u16,
            key_name: *const u16,
            legacy_key_spec: Dword,
            flags: Dword,
        ) -> Status;
        fn NCryptOpenKey(
            provider: Handle,
            ph_key: *mut Handle,
            key_name: *const u16,
            legacy_key_spec: Dword,
            flags: Dword,
        ) -> Status;
        fn NCryptSetProperty(
            object: Handle,
            property_name: *const u16,
            input: *const u8,
            input_bytes: Dword,
            flags: Dword,
        ) -> Status;
        fn NCryptFinalizeKey(
            key: Handle,
            flags: Dword,
        ) -> Status;
        fn NCryptExportKey(
            key: Handle,
            export_key: Handle,
            blob_type: *const u16,
            parameter_list: *mut c_void,
            output: *mut u8,
            output_bytes: Dword,
            result_bytes: *mut Dword,
            flags: Dword,
        ) -> Status;
        fn NCryptSignHash(
            key: Handle,
            padding_info: *mut c_void,
            hash: *const u8,
            hash_bytes: Dword,
            signature: *mut u8,
            signature_bytes: Dword,
            result_bytes: *mut Dword,
            flags: Dword,
        ) -> Status;
        fn NCryptDeleteKey(
            key: Handle,
            flags: Dword,
        ) -> Status;
        fn NCryptFreeObject(
            object: Handle,
        ) -> Status;
    }

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptOpenAlgorithmProvider(
            ph_algorithm: *mut Handle,
            algorithm_id: *const u16,
            implementation: *const u16,
            flags: Dword,
        ) -> Status;
        fn BCryptImportKeyPair(
            algorithm: Handle,
            import_key: Handle,
            blob_type: *const u16,
            ph_key: *mut Handle,
            input: *const u8,
            input_bytes: Dword,
            flags: Dword,
        ) -> Status;
        fn BCryptVerifySignature(
            key: Handle,
            padding_info: *mut c_void,
            hash: *const u8,
            hash_bytes: Dword,
            signature: *const u8,
            signature_bytes: Dword,
            flags: Dword,
        ) -> Status;
        fn BCryptDestroyKey(key: Handle) -> Status;
        fn BCryptCloseAlgorithmProvider(
            algorithm: Handle,
            flags: Dword,
        ) -> Status;
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn check(status: Status, context: &str) -> Result<()> {
        if status == SUCCESS {
            Ok(())
        } else {
            Err(AsymmetricError::Provider(format!(
                "{context} failed with status 0x{:08X}",
                status as u32,
            )))
        }
    }

    struct NcryptObject(Handle);

    impl Drop for NcryptObject {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe {
                    let _ = NCryptFreeObject(self.0);
                }
                self.0 = 0;
            }
        }
    }

    struct BcryptAlgorithm(Handle);

    impl Drop for BcryptAlgorithm {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe {
                    let _ = BCryptCloseAlgorithmProvider(
                        self.0,
                        0,
                    );
                }
                self.0 = 0;
            }
        }
    }

    struct BcryptKey(Handle);

    impl Drop for BcryptKey {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe {
                    let _ = BCryptDestroyKey(self.0);
                }
                self.0 = 0;
            }
        }
    }

    fn open_provider(provider_name: &str) -> Result<NcryptObject> {
        let provider_name_wide = wide(provider_name);
        let mut handle = 0usize;
        let status = unsafe {
            NCryptOpenStorageProvider(
                &mut handle,
                provider_name_wide.as_ptr(),
                0,
            )
        };
        check(status, "NCryptOpenStorageProvider")?;
        if handle == 0 {
            return Err(AsymmetricError::Provider(
                "NCryptOpenStorageProvider returned null handle"
                    .to_string(),
            ));
        }
        Ok(NcryptObject(handle))
    }

    fn open_key(
        provider: Handle,
        provider_key_name: &str,
    ) -> Result<NcryptObject> {
        let key_name_wide = wide(provider_key_name);
        let mut key = 0usize;
        let status = unsafe {
            NCryptOpenKey(
                provider,
                &mut key,
                key_name_wide.as_ptr(),
                0,
                NCRYPT_SILENT_FLAG,
            )
        };
        check(status, "NCryptOpenKey")?;
        if key == 0 {
            return Err(AsymmetricError::Provider(
                "NCryptOpenKey returned null handle".to_string(),
            ));
        }
        Ok(NcryptObject(key))
    }

    fn export_blob(
        key: Handle,
        blob_type: &str,
    ) -> Result<Vec<u8>> {
        let blob_type_wide = wide(blob_type);
        let mut required = 0u32;
        let first = unsafe {
            NCryptExportKey(
                key,
                0,
                blob_type_wide.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                &mut required,
                0,
            )
        };
        check(first, "NCryptExportKey(size)")?;
        if required == 0 || required > 1024 * 1024 {
            return Err(AsymmetricError::Provider(format!(
                "NCryptExportKey returned invalid size {required}",
            )));
        }
        let mut output = vec![0u8; required as usize];
        let mut written = 0u32;
        let second = unsafe {
            NCryptExportKey(
                key,
                0,
                blob_type_wide.as_ptr(),
                ptr::null_mut(),
                output.as_mut_ptr(),
                output.len() as u32,
                &mut written,
                0,
            )
        };
        check(second, "NCryptExportKey(data)")?;
        if written as usize > output.len() {
            return Err(AsymmetricError::Provider(
                "NCryptExportKey wrote beyond allocation".to_string(),
            ));
        }
        output.truncate(written as usize);
        Ok(output)
    }

    fn private_export_rejected_inner(key: Handle) -> bool {
        let blob_type_wide = wide(PRIVATE_BLOB_TYPE);
        let mut required = 0u32;
        let status = unsafe {
            NCryptExportKey(
                key,
                0,
                blob_type_wide.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                &mut required,
                NCRYPT_SILENT_FLAG,
            )
        };
        status != SUCCESS
    }

    pub fn create_persisted_key(
        provider_name: &str,
        provider_key_name: &str,
    ) -> Result<ProviderKeyMaterial> {
        if provider_name != SOFTWARE_KSP {
            return Err(AsymmetricError::Invalid(format!(
                "unsupported T6B provider: {provider_name}",
            )));
        }
        crate::validate_identifier(
            "provider_key_name",
            provider_key_name,
        )?;
        let provider = open_provider(provider_name)?;
        let algorithm_wide = wide(ALGORITHM_ECDSA_P256);
        let key_name_wide = wide(provider_key_name);
        let mut key = 0usize;
        let create_status = unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut key,
                algorithm_wide.as_ptr(),
                key_name_wide.as_ptr(),
                0,
                0,
            )
        };
        check(create_status, "NCryptCreatePersistedKey")?;
        if key == 0 {
            return Err(AsymmetricError::Provider(
                "NCryptCreatePersistedKey returned null handle"
                    .to_string(),
            ));
        }
        let key = NcryptObject(key);

        let export_policy = 0u32.to_le_bytes();
        let property_wide = wide(NCRYPT_EXPORT_POLICY_PROPERTY);
        let set_status = unsafe {
            NCryptSetProperty(
                key.0,
                property_wide.as_ptr(),
                export_policy.as_ptr(),
                export_policy.len() as u32,
                0,
            )
        };
        check(set_status, "NCryptSetProperty(Export Policy)")?;

        let finalize_status = unsafe {
            NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG)
        };
        check(finalize_status, "NCryptFinalizeKey")?;

        let public_blob = export_blob(key.0, PUBLIC_BLOB_TYPE)?;
        validate_public_blob(&public_blob)?;
        let private_export_rejected =
            private_export_rejected_inner(key.0);
        if !private_export_rejected {
            return Err(AsymmetricError::Provider(
                "private-key export was unexpectedly allowed"
                    .to_string(),
            ));
        }
        Ok(ProviderKeyMaterial {
            provider_name: provider_name.to_string(),
            provider_key_name: provider_key_name.to_string(),
            public_blob,
            private_export_rejected,
        })
    }

    pub fn export_public_blob(
        provider_name: &str,
        provider_key_name: &str,
    ) -> Result<Vec<u8>> {
        let provider = open_provider(provider_name)?;
        let key = open_key(provider.0, provider_key_name)?;
        let public_blob = export_blob(key.0, PUBLIC_BLOB_TYPE)?;
        validate_public_blob(&public_blob)?;
        Ok(public_blob)
    }

    pub fn sign_digest(
        provider_name: &str,
        provider_key_name: &str,
        digest: &[u8; 32],
    ) -> Result<[u8; 64]> {
        let provider = open_provider(provider_name)?;
        let key = open_key(provider.0, provider_key_name)?;
        let mut required = 0u32;
        let first = unsafe {
            NCryptSignHash(
                key.0,
                ptr::null_mut(),
                digest.as_ptr(),
                digest.len() as u32,
                ptr::null_mut(),
                0,
                &mut required,
                NCRYPT_SILENT_FLAG,
            )
        };
        check(first, "NCryptSignHash(size)")?;
        if required as usize != ECDSA_P256_SIGNATURE_BYTES {
            return Err(AsymmetricError::Provider(format!(
                "unexpected ECDSA P-256 signature size {required}",
            )));
        }
        let mut signature = [0u8; ECDSA_P256_SIGNATURE_BYTES];
        let mut written = 0u32;
        let second = unsafe {
            NCryptSignHash(
                key.0,
                ptr::null_mut(),
                digest.as_ptr(),
                digest.len() as u32,
                signature.as_mut_ptr(),
                signature.len() as u32,
                &mut written,
                NCRYPT_SILENT_FLAG,
            )
        };
        check(second, "NCryptSignHash(data)")?;
        if written as usize != signature.len() {
            return Err(AsymmetricError::Provider(format!(
                "unexpected ECDSA signature bytes {written}",
            )));
        }
        Ok(signature)
    }

    pub fn verify_digest(
        public_blob: &[u8],
        digest: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<bool> {
        validate_public_blob(public_blob)?;
        let algorithm_wide = wide(ALGORITHM_ECDSA_P256);
        let blob_type_wide = wide(PUBLIC_BLOB_TYPE);
        let mut algorithm = 0usize;
        let open_status = unsafe {
            BCryptOpenAlgorithmProvider(
                &mut algorithm,
                algorithm_wide.as_ptr(),
                ptr::null(),
                0,
            )
        };
        check(open_status, "BCryptOpenAlgorithmProvider")?;
        if algorithm == 0 {
            return Err(AsymmetricError::Provider(
                "BCryptOpenAlgorithmProvider returned null handle"
                    .to_string(),
            ));
        }
        let algorithm = BcryptAlgorithm(algorithm);
        let mut key = 0usize;
        let import_status = unsafe {
            BCryptImportKeyPair(
                algorithm.0,
                0,
                blob_type_wide.as_ptr(),
                &mut key,
                public_blob.as_ptr(),
                public_blob.len() as u32,
                0,
            )
        };
        check(import_status, "BCryptImportKeyPair")?;
        if key == 0 {
            return Err(AsymmetricError::Provider(
                "BCryptImportKeyPair returned null handle"
                    .to_string(),
            ));
        }
        let key = BcryptKey(key);
        let verify_status = unsafe {
            BCryptVerifySignature(
                key.0,
                ptr::null_mut(),
                digest.as_ptr(),
                digest.len() as u32,
                signature.as_ptr(),
                signature.len() as u32,
                0,
            )
        };
        Ok(verify_status == SUCCESS)
    }

    pub fn delete_persisted_key(
        provider_name: &str,
        provider_key_name: &str,
    ) -> Result<()> {
        let provider = open_provider(provider_name)?;
        let mut key = open_key(provider.0, provider_key_name)?;
        let status = unsafe {
            NCryptDeleteKey(key.0, NCRYPT_SILENT_FLAG)
        };
        check(status, "NCryptDeleteKey")?;
        key.0 = 0;
        Ok(())
    }

    pub fn private_export_rejected(
        provider_name: &str,
        provider_key_name: &str,
    ) -> Result<bool> {
        let provider = open_provider(provider_name)?;
        let key = open_key(provider.0, provider_key_name)?;
        Ok(private_export_rejected_inner(key.0))
    }

    pub fn provider_key_exists(
        provider_name: &str,
        provider_key_name: &str,
    ) -> bool {
        let provider = match open_provider(provider_name) {
            Ok(value) => value,
            Err(_) => return false,
        };
        open_key(provider.0, provider_key_name).is_ok()
    }

    pub fn write_public_blob(
        path: &Path,
        public_blob: &[u8],
    ) -> Result<()> {
        validate_public_blob(public_blob)?;
        std::fs::write(path, public_blob)?;
        Ok(())
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    use std::path::Path;

    fn unsupported<T>() -> Result<T> {
        Err(AsymmetricError::Provider(
            "Windows CNG is required for T6B".to_string(),
        ))
    }

    pub fn create_persisted_key(
        _provider_name: &str,
        _provider_key_name: &str,
    ) -> Result<ProviderKeyMaterial> {
        unsupported()
    }

    pub fn export_public_blob(
        _provider_name: &str,
        _provider_key_name: &str,
    ) -> Result<Vec<u8>> {
        unsupported()
    }

    pub fn sign_digest(
        _provider_name: &str,
        _provider_key_name: &str,
        _digest: &[u8; 32],
    ) -> Result<[u8; 64]> {
        unsupported()
    }

    pub fn verify_digest(
        _public_blob: &[u8],
        _digest: &[u8; 32],
        _signature: &[u8; 64],
    ) -> Result<bool> {
        unsupported()
    }

    pub fn delete_persisted_key(
        _provider_name: &str,
        _provider_key_name: &str,
    ) -> Result<()> {
        unsupported()
    }

    pub fn private_export_rejected(
        _provider_name: &str,
        _provider_key_name: &str,
    ) -> Result<bool> {
        unsupported()
    }

    pub fn provider_key_exists(
        _provider_name: &str,
        _provider_key_name: &str,
    ) -> bool {
        false
    }

    pub fn write_public_blob(
        _path: &Path,
        _public_blob: &[u8],
    ) -> Result<()> {
        unsupported()
    }
}

pub use platform::{
    create_persisted_key, delete_persisted_key,
    export_public_blob, private_export_rejected,
    provider_key_exists, sign_digest, verify_digest,
    write_public_blob,
};

pub fn validate_public_blob(public_blob: &[u8]) -> Result<()> {
    if public_blob.len() != ECDSA_P256_PUBLIC_BLOB_BYTES {
        return Err(AsymmetricError::Invalid(format!(
            "ECDSA P-256 public blob must be {} bytes, got {}",
            ECDSA_P256_PUBLIC_BLOB_BYTES,
            public_blob.len(),
        )));
    }
    let magic = u32::from_le_bytes(
        public_blob[0..4]
            .try_into()
            .expect("public blob magic"),
    );
    let key_bytes = u32::from_le_bytes(
        public_blob[4..8]
            .try_into()
            .expect("public blob key length"),
    );
    const BCRYPT_ECDSA_PUBLIC_P256_MAGIC: u32 = 0x31534345;
    if magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC
        || key_bytes != 32
    {
        return Err(AsymmetricError::Invalid(format!(
            "invalid ECDSA P-256 public blob header: magic=0x{magic:08X} key_bytes={key_bytes}",
        )));
    }
    Ok(())
}
