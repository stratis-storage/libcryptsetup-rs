// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{convert::TryFrom, marker::PhantomData};

use crate::{activate::CryptActivateFlags, device::CryptDevice, err::LibcryptErr};

enum CryptFlagsType {
    Activation = libcryptsetup_rs_sys::crypt_flags_type_CRYPT_FLAGS_ACTIVATION as isize,
    Requirements = libcryptsetup_rs_sys::crypt_flags_type_CRYPT_FLAGS_REQUIREMENTS as isize,
}

consts_to_from_enum!(
    /// Wrapper enum for `CRYPT_REQUIREMENT_*` flags
    CryptRequirementFlag, u32,
    OfflineReencrypt => libcryptsetup_rs_sys::CRYPT_REQUIREMENT_OFFLINE_REENCRYPT,
    OnlineReencrypt => libcryptsetup_rs_sys::CRYPT_REQUIREMENT_ONLINE_REENCRYPT,
    Unknown => libcryptsetup_rs_sys::CRYPT_REQUIREMENT_UNKNOWN
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
            libcryptsetup_rs_sys::crypt_persistent_flags_set(
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
            libcryptsetup_rs_sys::crypt_persistent_flags_get(
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
            libcryptsetup_rs_sys::crypt_persistent_flags_set(
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
            libcryptsetup_rs_sys::crypt_persistent_flags_get(
                self.reference.as_ptr(),
                CryptFlagsType::Requirements as u32,
                &mut flags_u32 as *mut _,
            )
        })
        .and_then(|_| CryptRequirementFlags::try_from(flags_u32))
    }
}
