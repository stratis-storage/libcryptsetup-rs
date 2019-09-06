use std::{
    convert::{TryFrom, TryInto},
    marker::PhantomData,
    os::raw::{c_int, c_void},
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
    None => cryptsetup_sys::crypt_reencrypt_info_CRYPT_REENCRYPT_NONE,
    Clean => cryptsetup_sys::crypt_reencrypt_info_CRYPT_REENCRYPT_CLEAN,
    Crash => cryptsetup_sys::crypt_reencrypt_info_CRYPT_REENCRYPT_CRASH,
    Invalid => cryptsetup_sys::crypt_reencrypt_info_CRYPT_REENCRYPT_INVALID
);

consts_to_from_enum!(
    /// Encryption mode flags
    CryptReencryptModeInfo,
    u32,
    Reencrypt => cryptsetup_sys::crypt_reencrypt_mode_info_CRYPT_REENCRYPT_REENCRYPT,
    Encrypt => cryptsetup_sys::crypt_reencrypt_mode_info_CRYPT_REENCRYPT_ENCRYPT,
    Decrypt => cryptsetup_sys::crypt_reencrypt_mode_info_CRYPT_REENCRYPT_DECRYPT
);

consts_to_from_enum!(
    /// Reencryption direction flags
    CryptReencryptDirectionInfo,
    u32,
    Forward => cryptsetup_sys::crypt_reencrypt_direction_info_CRYPT_REENCRYPT_FORWARD,
    Backward => cryptsetup_sys::crypt_reencrypt_direction_info_CRYPT_REENCRYPT_BACKWARD
);

consts_to_from_enum!(
    /// Enum for `CRYPT_REENCRYPT_*` flags
    CryptReencryptFlag,
    u32,
    InitializeOnly => cryptsetup_sys::CRYPT_REENCRYPT_INITIALIZE_ONLY,
    MoveFirstSegment => cryptsetup_sys::CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT,
    ResumeOnly => cryptsetup_sys::CRYPT_REENCRYPT_RESUME_ONLY,
    Recovery => cryptsetup_sys::CRYPT_REENCRYPT_RECOVERY
);

bitflags_to_from_struct!(
    /// Wrapper for a set of CryptReencryptFlag
    CryptReencryptFlags,
    CryptReencryptFlag,
    u32
);

struct_ref_to_bitflags!(CryptReencryptFlags, CryptReencryptFlag, u32);

pub struct CryptParamsReencryptRef<'a> {
    pub inner: cryptsetup_sys::crypt_params_reencrypt,
    #[allow(dead_code)]
    data: &'a PhantomData<()>,
}

pub struct CryptParamsReencrypt {
    mode: CryptReencryptModeInfo,
    direction: CryptReencryptDirectionInfo,
    resilience: String,
    hash: String,
    data_shift: u64,
    max_hotzone_size: u64,
    device_size: u64,
    luks2: CryptParamsLuks2,
    flags: CryptReencryptFlags,
}

impl<'a> TryInto<CryptParamsReencryptRef<'a>> for &'a CryptParamsReencrypt {
    type Error = LibcryptErr;

    fn try_into(self) -> Result<CryptParamsReencryptRef<'a>, Self::Error> {
        let luks: CryptParamsLuks2Ref<'a> = (&self.luks2).try_into()?;
        let inner = cryptsetup_sys::crypt_params_reencrypt {
            mode: self.mode.into(),
            direction: self.direction.into(),
            resilience: to_str_ptr!(self.resilience)?,
            hash: to_str_ptr!(self.hash)?,
            data_shift: self.data_shift,
            max_hotzone_size: self.max_hotzone_size,
            device_size: self.device_size,
            luks2: &luks.inner as *const _,
            flags: (&self.flags).into(),
        };
        Ok(CryptParamsReencryptRef {
            inner,
            data: &PhantomData,
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
        let name_ptr = match name {
            Some(n) => to_str_ptr!(n)?,
            None => std::ptr::null(),
        };
        let (cipher, cipher_mode) = cipher_and_mode;
        let params_reencrypt: CryptParamsReencryptRef<'_> = (&params).try_into()?;
        errno_int_success!(unsafe {
            cryptsetup_sys::crypt_reencrypt_init_by_passphrase(
                self.reference.as_ptr(),
                name_ptr,
                to_byte_ptr!(passphrase),
                passphrase.len(),
                keyslot_old,
                keyslot_new,
                to_str_ptr!(cipher)?,
                to_str_ptr!(cipher_mode)?,
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
        let name_ptr = match name {
            Some(n) => to_str_ptr!(n)?,
            None => std::ptr::null(),
        };
        let (cipher, cipher_mode) = cipher_and_mode;
        let params_reencrypt: CryptParamsReencryptRef<'_> = (&params).try_into()?;
        errno_int_success!(unsafe {
            cryptsetup_sys::crypt_reencrypt_init_by_keyring(
                self.reference.as_ptr(),
                name_ptr,
                to_str_ptr!(key_description)?,
                keyslot_old,
                keyslot_new,
                to_str_ptr!(cipher)?,
                to_str_ptr!(cipher_mode)?,
                &params_reencrypt.inner as *const _,
            )
        })
    }

    /// Run data reencryption
    pub fn reencrypt(&mut self, progress: Option<ReencryptProgress>) -> Result<(), LibcryptErr> {
        errno!(unsafe { cryptsetup_sys::crypt_reencrypt(self.reference.as_ptr(), progress) })
    }

    /// LUKS2 reencryption status
    pub fn status(
        &mut self,
        params: CryptParamsReencrypt,
    ) -> Result<CryptReencryptInfo, LibcryptErr> {
        let mut params_reencrypt: CryptParamsReencryptRef<'_> = (&params).try_into()?;
        try_int_to_return!(
            unsafe {
                cryptsetup_sys::crypt_reencrypt_status(
                    self.reference.as_ptr(),
                    &mut params_reencrypt.inner as *mut _,
                )
            },
            CryptReencryptInfo
        )
    }
}
