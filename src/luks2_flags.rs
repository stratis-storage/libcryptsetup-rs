use std::{convert::TryFrom, marker::PhantomData};

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

impl Into<u32> for CryptRequirement {
    fn into(self) -> u32 {
        match self {
            CryptRequirement::Unknown => cryptsetup_sys::CRYPT_REQUIREMENT_UNKNOWN,
            any_else => any_else as u32,
        }
    }
}

impl TryFrom<u32> for CryptRequirement {
    type Error = LibcryptErr;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        Ok(match v {
            i if i == CryptRequirement::OfflineReencrypt as u32 => {
                CryptRequirement::OfflineReencrypt
            }
            i if i == CryptRequirement::OnlineReencrypt as u32 => CryptRequirement::OnlineReencrypt,
            i if i == cryptsetup_sys::CRYPT_REQUIREMENT_UNKNOWN => CryptRequirement::Unknown,
            _ => return Err(LibcryptErr::InvalidConversion),
        })
    }
}

/// Set of `CryptRequirement` flags
pub struct CryptRequirementFlags(Vec<CryptRequirement>);

impl Into<u32> for CryptRequirementFlags {
    fn into(self) -> u32 {
        self.0.into_iter().fold(0, |acc, flag| {
            let flags_u32: u32 = flag.into();
            acc | flags_u32
        })
    }
}

bitflags_to_enum!(CryptRequirementFlags, CryptRequirement, u32);

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

    /// Implementation for getting persistent flags for activation
    pub fn persistent_flags_get(&mut self) -> Result<CryptActivateFlags, LibcryptErr> {
        let mut flags_u32 = 0u32;
        errno!(unsafe {
            cryptsetup_sys::crypt_persistent_flags_get(
                self.reference.as_ptr(),
                CryptFlagsType::Activation as u32,
                &mut flags_u32 as *mut _,
            )
        })
        .and_then(|_| CryptActivateFlags::try_from(flags_u32))
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

    /// Implementation for getting persistent flags for requirements
    pub fn persistent_flags_get(&mut self) -> Result<CryptRequirementFlags, LibcryptErr> {
        let mut flags_u32 = 0u32;
        errno!(unsafe {
            cryptsetup_sys::crypt_persistent_flags_get(
                self.reference.as_ptr(),
                CryptFlagsType::Requirements as u32,
                &mut flags_u32 as *mut _,
            )
        })
        .and_then(|_| CryptRequirementFlags::try_from(flags_u32))
    }
}
