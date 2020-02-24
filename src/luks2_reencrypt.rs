// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    convert::{TryFrom, TryInto},
    ffi::CString,
    os::raw::{c_int, c_void},
    ptr,
};

use crate::{
    device::CryptDevice,
    err::LibcryptErr,
    format::{CryptParamsLuks2, CryptParamsLuks2Ref},
};

type ReencryptProgress = unsafe extern "C" fn(size: u64, offset: u64, *mut c_void) -> c_int;

consts_to_from_enum!(
    /// Encryption mode flags
    CryptReencryptInfo,
    u32,
    None => libcryptsetup_rs_sys::crypt_reencrypt_info_CRYPT_REENCRYPT_NONE,
    Clean => libcryptsetup_rs_sys::crypt_reencrypt_info_CRYPT_REENCRYPT_CLEAN,
    Crash => libcryptsetup_rs_sys::crypt_reencrypt_info_CRYPT_REENCRYPT_CRASH,
    Invalid => libcryptsetup_rs_sys::crypt_reencrypt_info_CRYPT_REENCRYPT_INVALID
);

consts_to_from_enum!(
    /// Encryption mode flags
    CryptReencryptModeInfo,
    u32,
    Reencrypt => libcryptsetup_rs_sys::crypt_reencrypt_mode_info_CRYPT_REENCRYPT_REENCRYPT,
    Encrypt => libcryptsetup_rs_sys::crypt_reencrypt_mode_info_CRYPT_REENCRYPT_ENCRYPT,
    Decrypt => libcryptsetup_rs_sys::crypt_reencrypt_mode_info_CRYPT_REENCRYPT_DECRYPT
);

consts_to_from_enum!(
    /// Reencryption direction flags
    CryptReencryptDirectionInfo,
    u32,
    Forward => libcryptsetup_rs_sys::crypt_reencrypt_direction_info_CRYPT_REENCRYPT_FORWARD,
    Backward => libcryptsetup_rs_sys::crypt_reencrypt_direction_info_CRYPT_REENCRYPT_BACKWARD
);

consts_to_from_enum!(
    /// Enum for `CRYPT_REENCRYPT_*` flags
    CryptReencryptFlag,
    u32,
    InitializeOnly => libcryptsetup_rs_sys::CRYPT_REENCRYPT_INITIALIZE_ONLY,
    MoveFirstSegment => libcryptsetup_rs_sys::CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT,
    ResumeOnly => libcryptsetup_rs_sys::CRYPT_REENCRYPT_RESUME_ONLY,
    Recovery => libcryptsetup_rs_sys::CRYPT_REENCRYPT_RECOVERY
);

bitflags_to_from_struct!(
    /// Wrapper for a set of CryptReencryptFlag
    CryptReencryptFlags,
    CryptReencryptFlag,
    u32
);

struct_ref_to_bitflags!(CryptReencryptFlags, CryptReencryptFlag, u32);

/// A struct representing a reference with a lifetime to a `CryptParamsReencrypt`
/// struct
pub struct CryptParamsReencryptRef<'a> {
    #[allow(missing_docs)]
    pub inner: libcryptsetup_rs_sys::crypt_params_reencrypt,
    #[allow(dead_code)]
    reference: &'a CryptParamsReencrypt,
    #[allow(dead_code)]
    luks2_params: CryptParamsLuks2Ref<'a>,
    #[allow(dead_code)]
    resilience_cstring: CString,
    #[allow(dead_code)]
    hash_cstring: CString,
}

/// Parameters for reencryption operations
pub struct CryptParamsReencrypt {
    /// Type of reencryption operation
    pub mode: CryptReencryptModeInfo,
    /// Start at beginning or end of disk
    pub direction: CryptReencryptDirectionInfo,
    #[allow(missing_docs)]
    pub resilience: String,
    #[allow(missing_docs)]
    pub hash: String,
    #[allow(missing_docs)]
    pub data_shift: u64,
    #[allow(missing_docs)]
    pub max_hotzone_size: u64,
    /// Size of the device
    pub device_size: u64,
    /// LUKS2-specific parameters
    pub luks2: CryptParamsLuks2,
    /// Reencryption flags
    pub flags: CryptReencryptFlags,
}

impl<'a> TryInto<CryptParamsReencryptRef<'a>> for &'a CryptParamsReencrypt {
    type Error = LibcryptErr;

    fn try_into(self) -> Result<CryptParamsReencryptRef<'a>, Self::Error> {
        let luks2_params: CryptParamsLuks2Ref<'a> = (&self.luks2).try_into()?;

        let resilience_cstring = to_cstring!(self.resilience)?;
        let hash_cstring = to_cstring!(self.hash)?;

        let inner = libcryptsetup_rs_sys::crypt_params_reencrypt {
            mode: self.mode.into(),
            direction: self.direction.into(),
            resilience: resilience_cstring.as_ptr(),
            hash: hash_cstring.as_ptr(),
            data_shift: self.data_shift,
            max_hotzone_size: self.max_hotzone_size,
            device_size: self.device_size,
            luks2: &luks2_params.inner as *const _,
            flags: (&self.flags).into(),
        };
        Ok(CryptParamsReencryptRef {
            inner,
            reference: self,
            luks2_params,
            resilience_cstring,
            hash_cstring,
        })
    }
}

/// Handle for reencryption operations
pub struct CryptLuks2Reencrypt<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptLuks2Reencrypt<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptLuks2Reencrypt { reference }
    }

    /// Initialize reencryption metadata on a device by passphrase
    pub fn reencrypt_init_by_passphrase(
        &mut self,
        name: Option<&str>,
        passphrase: &[u8],
        keyslot_old: c_int,
        keyslot_new: c_int,
        cipher_and_mode: (&str, &str),
        params: CryptParamsReencrypt,
    ) -> Result<c_int, LibcryptErr> {
        let name_cstring = match name {
            Some(n) => Some(to_cstring!(n)?),
            None => None,
        };
        let (cipher, cipher_mode) = cipher_and_mode;
        let params_reencrypt: CryptParamsReencryptRef<'_> = (&params).try_into()?;

        let cipher_cstring = to_cstring!(cipher)?;
        let cipher_mode_cstring = to_cstring!(cipher_mode)?;
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_reencrypt_init_by_passphrase(
                self.reference.as_ptr(),
                name_cstring.map(|cs| cs.as_ptr()).unwrap_or(ptr::null()),
                to_byte_ptr!(passphrase),
                passphrase.len(),
                keyslot_old,
                keyslot_new,
                cipher_cstring.as_ptr(),
                cipher_mode_cstring.as_ptr(),
                &params_reencrypt.inner as *const _,
            )
        })
    }

    /// Initialize reencryption metadata on a device by passphrase in a keyring
    pub fn reecrypt_init_by_keyring(
        &mut self,
        name: Option<&str>,
        key_description: &str,
        keyslot_old: c_int,
        keyslot_new: c_int,
        cipher_and_mode: (&str, &str),
        params: CryptParamsReencrypt,
    ) -> Result<c_int, LibcryptErr> {
        let name_cstring = match name {
            Some(n) => Some(to_cstring!(n)?),
            None => None,
        };
        let (cipher, cipher_mode) = cipher_and_mode;
        let params_reencrypt: CryptParamsReencryptRef<'_> = (&params).try_into()?;

        let description_cstring = to_cstring!(key_description)?;
        let cipher_cstring = to_cstring!(cipher)?;
        let cipher_mode_cstring = to_cstring!(cipher_mode)?;
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_reencrypt_init_by_keyring(
                self.reference.as_ptr(),
                name_cstring.map(|cs| cs.as_ptr()).unwrap_or(ptr::null()),
                description_cstring.as_ptr(),
                keyslot_old,
                keyslot_new,
                cipher_cstring.as_ptr(),
                cipher_mode_cstring.as_ptr(),
                &params_reencrypt.inner as *const _,
            )
        })
    }

    /// Run data reencryption
    pub fn reencrypt(&mut self, progress: Option<ReencryptProgress>) -> Result<(), LibcryptErr> {
        errno!(unsafe { libcryptsetup_rs_sys::crypt_reencrypt(self.reference.as_ptr(), progress) })
    }

    /// LUKS2 reencryption status
    pub fn status(
        &mut self,
        params: CryptParamsReencrypt,
    ) -> Result<CryptReencryptInfo, LibcryptErr> {
        let mut params_reencrypt: CryptParamsReencryptRef<'_> = (&params).try_into()?;
        try_int_to_return!(
            unsafe {
                libcryptsetup_rs_sys::crypt_reencrypt_status(
                    self.reference.as_ptr(),
                    &mut params_reencrypt.inner as *mut _,
                )
            },
            CryptReencryptInfo
        )
    }
}
