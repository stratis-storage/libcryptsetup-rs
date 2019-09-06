use std::{convert::TryFrom, marker::PhantomData};

use crate::{device::CryptDevice, err::LibcryptErr, runtime::CryptActivateFlags};

enum CryptFlagsType {
    Activation = cryptsetup_sys::crypt_flags_type_CRYPT_FLAGS_ACTIVATION as isize,
    Requirements = cryptsetup_sys::crypt_flags_type_CRYPT_FLAGS_REQUIREMENTS as isize,
}

consts_to_from_enum!(
    /// Wrapper enum for `CRYPT_REQUIREMENT_*` flags
    CryptRequirementFlag, u32,
    OfflineReencrypt => cryptsetup_sys::CRYPT_REQUIREMENT_OFFLINE_REENCRYPT,
    OnlineReencrypt => cryptsetup_sys::CRYPT_REQUIREMENT_ONLINE_REENCRYPT,
    Unknown => cryptsetup_sys::CRYPT_REQUIREMENT_UNKNOWN
);

bitflags_to_from_struct!(
    /// Set of `CryptRequirementFlag`s
    CryptRequirementFlags,
    CryptRequirementFlag,
    u32
);

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
