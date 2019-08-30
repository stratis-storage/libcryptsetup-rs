use std::marker::PhantomData;

use crate::{device::CryptDevice, err::LibcryptErr, runtime::CryptActivateFlags};

pub enum CryptFlagsType {
    Activation = cryptsetup_sys::crypt_flags_type_CRYPT_FLAGS_ACTIVATION as isize,
    Requirements = cryptsetup_sys::crypt_flags_type_CRYPT_FLAGS_REQUIREMENTS as isize,
}

/// Wrapper enum for `CRYPT_REQUIREMENT_*` flags
pub enum CryptRequirement {
    #[allow(missing_docs)]
    OfflineReencrypt = cryptsetup_sys::CRYPT_REQUIREMENT_OFFLINE_REENCRYPT as isize,
    #[allow(missing_docs)]
    OnlineReencrypt = cryptsetup_sys::CRYPT_REQUIREMENT_ONLINE_REENCRYPT as isize,
    #[allow(missing_docs)]
    Unknown,
}

/// Set of `CryptRequirement` flags
pub struct CryptRequirementFlags(Vec<CryptRequirement>);

impl Into<u32> for CryptRequirementFlags {
    fn into(self) -> u32 {
        self.0.into_iter().fold(0, |acc, flag| {
            acc | match flag {
                CryptRequirement::Unknown => cryptsetup_sys::CRYPT_REQUIREMENT_UNKNOWN,
                any_other => any_other as u32,
            }
        })
    }
}

/// Handle for LUKS2 persistent flag operations
pub struct CryptLuks2Flags<'a, T> {
    reference: &'a mut CryptDevice,
    data: PhantomData<T>,
}

impl<'a, T> CryptLuks2Flags<'a, T> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptLuks2Flags {
            reference,
            data: PhantomData,
        }
    }
}

impl<'a> CryptLuks2Flags<'a, CryptActivateFlags> {
    /// Implementation for setting persistent flags for activation
    pub fn persistent_flags_set(&mut self, flags: CryptActivateFlags) -> Result<(), LibcryptErr> {
        let flags_u32: u32 = flags.into();
        errno!(unsafe {
            cryptsetup_sys::crypt_persistent_flags_set(
                self.reference.as_ptr(),
                CryptFlagsType::Activation as u32,
                flags_u32,
            )
        })
    }
}

impl<'a> CryptLuks2Flags<'a, CryptRequirementFlags> {
    /// Implementation for setting persistent flags for requirements
    pub fn persistent_flags_set(
        &mut self,
        flags: CryptRequirementFlags,
    ) -> Result<(), LibcryptErr> {
        let flags_u32: u32 = flags.into();
        errno!(unsafe {
            cryptsetup_sys::crypt_persistent_flags_set(
                self.reference.as_ptr(),
                CryptFlagsType::Requirements as u32,
                flags_u32,
            )
        })
    }
}
