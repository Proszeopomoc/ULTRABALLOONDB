use crate::{
    create_persisted_key, export_public_blob, private_export_rejected,
    sign_digest, verify_digest, AsymmetricError, ProviderKeyMaterial,
    Result, SOFTWARE_KSP,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProviderClass {
    Software = 1,
    Hardware = 2,
    Tpm = 3,
}

impl ProviderClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Software => "SOFTWARE",
            Self::Hardware => "HARDWARE",
            Self::Tpm => "TPM",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderRequirement {
    SoftwareAllowed,
    HardwareRequired,
    TpmRequired,
}

impl ProviderRequirement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SoftwareAllowed => "SOFTWARE_ALLOWED",
            Self::HardwareRequired => "HARDWARE_REQUIRED",
            Self::TpmRequired => "TPM_REQUIRED",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderCapabilities {
    pub provider_name: String,
    pub provider_class: ProviderClass,
    pub available: bool,
    pub persistent_keys: bool,
    pub private_export_rejected: bool,
    pub hardware_bound: bool,
    pub tpm_used: bool,
    pub evidence_digest: [u8; 32],
}

impl ProviderCapabilities {
    pub fn satisfies(&self, requirement: ProviderRequirement) -> bool {
        if !self.available
            || !self.persistent_keys
            || !self.private_export_rejected
        {
            return false;
        }
        match requirement {
            ProviderRequirement::SoftwareAllowed => true,
            ProviderRequirement::HardwareRequired => self.hardware_bound,
            ProviderRequirement::TpmRequired => self.tpm_used,
        }
    }
}

pub trait SigningProvider {
    fn capabilities(&self) -> ProviderCapabilities;
    fn create_key(&self, key_name: &str) -> Result<ProviderKeyMaterial>;
    fn export_public(&self, key_name: &str) -> Result<Vec<u8>>;
    fn sign(&self, key_name: &str, digest: &[u8; 32]) -> Result<[u8; 64]>;
    fn verify(
        &self,
        public_blob: &[u8],
        digest: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<bool>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SoftwareCngProvider;

impl SigningProvider for SoftwareCngProvider {
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            provider_name: SOFTWARE_KSP.to_string(),
            provider_class: ProviderClass::Software,
            available: cfg!(windows),
            persistent_keys: true,
            private_export_rejected: true,
            hardware_bound: false,
            tpm_used: false,
            evidence_digest: [0; 32],
        }
    }

    fn create_key(&self, key_name: &str) -> Result<ProviderKeyMaterial> {
        let material = create_persisted_key(SOFTWARE_KSP, key_name)?;
        if !material.private_export_rejected
            || !private_export_rejected(SOFTWARE_KSP, key_name)?
        {
            return Err(AsymmetricError::Provider(
                "software CNG private export rejection not proven".to_string(),
            ));
        }
        Ok(material)
    }

    fn export_public(&self, key_name: &str) -> Result<Vec<u8>> {
        export_public_blob(SOFTWARE_KSP, key_name)
    }

    fn sign(&self, key_name: &str, digest: &[u8; 32]) -> Result<[u8; 64]> {
        sign_digest(SOFTWARE_KSP, key_name, digest)
    }

    fn verify(
        &self,
        public_blob: &[u8],
        digest: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<bool> {
        verify_digest(public_blob, digest, signature)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnavailableProvider {
    pub name: String,
    pub class: ProviderClass,
    pub evidence_digest: [u8; 32],
}

impl SigningProvider for UnavailableProvider {
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            provider_name: self.name.clone(),
            provider_class: self.class,
            available: false,
            persistent_keys: false,
            private_export_rejected: false,
            hardware_bound: self.class >= ProviderClass::Hardware,
            tpm_used: self.class == ProviderClass::Tpm,
            evidence_digest: self.evidence_digest,
        }
    }

    fn create_key(&self, _key_name: &str) -> Result<ProviderKeyMaterial> {
        self.no_go()
    }

    fn export_public(&self, _key_name: &str) -> Result<Vec<u8>> {
        self.no_go()
    }

    fn sign(&self, _key_name: &str, _digest: &[u8; 32]) -> Result<[u8; 64]> {
        self.no_go()
    }

    fn verify(
        &self,
        _public_blob: &[u8],
        _digest: &[u8; 32],
        _signature: &[u8; 64],
    ) -> Result<bool> {
        self.no_go()
    }
}

impl UnavailableProvider {
    fn no_go<T>(&self) -> Result<T> {
        Err(AsymmetricError::Provider(format!(
            "provider unavailable: {} class={} evidence_digest={}",
            self.name,
            self.class.as_str(),
            crate::hex(&self.evidence_digest),
        )))
    }
}

pub fn enforce_provider_requirement(
    provider: &dyn SigningProvider,
    requirement: ProviderRequirement,
) -> Result<ProviderCapabilities> {
    let capabilities = provider.capabilities();
    if !capabilities.satisfies(requirement) {
        return Err(AsymmetricError::Provider(format!(
            "provider requirement rejected: requirement={} provider={} class={} available={} hardware_bound={} tpm_used={}",
            requirement.as_str(),
            capabilities.provider_name,
            capabilities.provider_class.as_str(),
            capabilities.available,
            capabilities.hardware_bound,
            capabilities.tpm_used,
        )));
    }
    Ok(capabilities)
}

pub fn select_provider<'a>(
    candidates: &'a [&'a dyn SigningProvider],
    requirement: ProviderRequirement,
) -> Result<&'a dyn SigningProvider> {
    candidates
        .iter()
        .copied()
        .find(|provider| provider.capabilities().satisfies(requirement))
        .ok_or_else(|| {
            AsymmetricError::Provider(format!(
                "no provider satisfies requirement {}",
                requirement.as_str(),
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_hardware_never_satisfies_requirement() {
        let provider = UnavailableProvider {
            name: "Microsoft Platform Crypto Provider".to_string(),
            class: ProviderClass::Tpm,
            evidence_digest: [7; 32],
        };
        assert!(!provider.capabilities().satisfies(ProviderRequirement::SoftwareAllowed));
        assert!(enforce_provider_requirement(
            &provider,
            ProviderRequirement::TpmRequired,
        ).is_err());
    }

    #[test]
    fn software_capabilities_are_not_hardware_claims() {
        let capabilities = SoftwareCngProvider.capabilities();
        assert_eq!(capabilities.provider_name, SOFTWARE_KSP);
        assert!(!capabilities.hardware_bound);
        assert!(!capabilities.tpm_used);
    }
}
