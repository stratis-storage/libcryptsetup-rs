use std::{
    convert::TryFrom,
    os::raw::c_int,
    path::{Path, PathBuf},
    ptr,
};

use crate::{device::CryptDevice, err::LibcryptErr, CryptPbkdfType, Format};

use cryptsetup_sys::*;

pub enum CryptVolumeKey {
    NoSegment = cryptsetup_sys::CRYPT_VOLUME_KEY_NO_SEGMENT as isize,
    Set = cryptsetup_sys::CRYPT_VOLUME_KEY_SET as isize,
    DigestReuse = cryptsetup_sys::CRYPT_VOLUME_KEY_DIGEST_REUSE as isize,
}

pub struct CryptVolumeKeyFlags(Vec<CryptVolumeKey>);

impl CryptVolumeKeyFlags {
    pub fn new(vec: Vec<CryptVolumeKey>) -> Self {
        CryptVolumeKeyFlags(vec)
    }
}

impl Into<u32> for CryptVolumeKeyFlags {
    fn into(self) -> u32 {
        self.0.into_iter().fold(0, |acc, flag| acc | flag as u32)
    }
}

pub enum KeyslotInfo {
    Invalid = cryptsetup_sys::crypt_keyslot_info_CRYPT_SLOT_INVALID as isize,
    Inactive = cryptsetup_sys::crypt_keyslot_info_CRYPT_SLOT_INACTIVE as isize,
    Active = cryptsetup_sys::crypt_keyslot_info_CRYPT_SLOT_ACTIVE as isize,
    ActiveLast = cryptsetup_sys::crypt_keyslot_info_CRYPT_SLOT_ACTIVE_LAST as isize,
    Unbound = cryptsetup_sys::crypt_keyslot_info_CRYPT_SLOT_UNBOUND as isize,
}

impl TryFrom<u32> for KeyslotInfo {
    type Error = LibcryptErr;

    fn try_from(v: u32) -> Result<KeyslotInfo, LibcryptErr> {
        let ki = match v {
            i if i == KeyslotInfo::Invalid as u32 => KeyslotInfo::Invalid,
            i if i == KeyslotInfo::Inactive as u32 => KeyslotInfo::Inactive,
            i if i == KeyslotInfo::Active as u32 => KeyslotInfo::Active,
            i if i == KeyslotInfo::ActiveLast as u32 => KeyslotInfo::ActiveLast,
            i if i == KeyslotInfo::Unbound as u32 => KeyslotInfo::Unbound,
            _ => return Err(LibcryptErr::InvalidConversion),
        };
        Ok(ki)
    }
}

pub enum KeyslotPriority {
    Invalid = cryptsetup_sys::crypt_keyslot_priority_CRYPT_SLOT_PRIORITY_INVALID as isize,
    Ignore = cryptsetup_sys::crypt_keyslot_priority_CRYPT_SLOT_PRIORITY_IGNORE as isize,
    Normal = cryptsetup_sys::crypt_keyslot_priority_CRYPT_SLOT_PRIORITY_NORMAL as isize,
    Prefer = cryptsetup_sys::crypt_keyslot_priority_CRYPT_SLOT_PRIORITY_PREFER as isize,
}

impl TryFrom<i32> for KeyslotPriority {
    type Error = LibcryptErr;

    fn try_from(v: i32) -> Result<KeyslotPriority, LibcryptErr> {
        let kp = match v {
            i if i == KeyslotPriority::Invalid as i32 => KeyslotPriority::Invalid,
            i if i == KeyslotPriority::Ignore as i32 => KeyslotPriority::Ignore,
            i if i == KeyslotPriority::Normal as i32 => KeyslotPriority::Normal,
            i if i == KeyslotPriority::Prefer as i32 => KeyslotPriority::Prefer,
            _ => return Err(LibcryptErr::InvalidConversion),
        };
        Ok(kp)
    }
}

/// Handle for keyslot operations
pub struct CryptKeyslot<'a> {
    reference: &'a mut CryptDevice,
    keyslot: c_int,
}

impl<'a> CryptKeyslot<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice, keyslot: c_int) -> Self {
        CryptKeyslot { reference, keyslot }
    }

    /// Add key slot using a passphrase
    pub fn add_by_passphrase(
        &mut self,
        passphrase: &str,
        new_passphrase: &str,
    ) -> Result<c_int, LibcryptErr> {
        errno_int_success!(unsafe {
            crypt_keyslot_add_by_passphrase(
                self.reference.as_ptr(),
                self.keyslot,
                to_str_ptr!(passphrase)?,
                passphrase.len(),
                to_str_ptr!(new_passphrase)?,
                new_passphrase.len(),
            )
        })
    }

    /// Change allocated key slot using a passphrase
    pub fn change_by_passphrase(
        &mut self,
        keyslot_old: c_int,
        keyslot_new: c_int,
        passphrase: &str,
        new_passphrase: &str,
    ) -> Result<c_int, LibcryptErr> {
        errno_int_success!(unsafe {
            crypt_keyslot_change_by_passphrase(
                self.reference.as_ptr(),
                keyslot_old,
                keyslot_new,
                to_str_ptr!(passphrase)?,
                passphrase.len(),
                to_str_ptr!(new_passphrase)?,
                new_passphrase.len(),
            )
        })
    }

    /// Add key slot using key file
    pub fn add_by_keyfile_device_offset(
        &mut self,
        keyfile_and_size: (&Path, crate::SizeT),
        keyfile_offset: u64,
        new_keyfile_and_size: (&Path, crate::SizeT),
        new_keyfile_offset: u64,
    ) -> Result<c_int, LibcryptErr> {
        let (keyfile, keyfile_size) = keyfile_and_size;
        let (new_keyfile, new_keyfile_size) = new_keyfile_and_size;
        errno_int_success!(unsafe {
            crypt_keyslot_add_by_keyfile_device_offset(
                self.reference.as_ptr(),
                self.keyslot,
                path_to_str_ptr!(keyfile)?,
                keyfile_size,
                keyfile_offset,
                path_to_str_ptr!(new_keyfile)?,
                new_keyfile_size,
                new_keyfile_offset,
            )
        })
    }

    /// Add key slot with volume key
    pub fn add_by_volume_key(
        &mut self,
        volume_key: Option<&str>,
        passphrase: &str,
    ) -> Result<c_int, LibcryptErr> {
        let (vk_ptr, vk_len) = match volume_key {
            Some(vk) => (to_str_ptr!(vk)?, vk.len()),
            None => (std::ptr::null(), 0),
        };
        errno_int_success!(unsafe {
            crypt_keyslot_add_by_volume_key(
                self.reference.as_ptr(),
                self.keyslot,
                vk_ptr,
                vk_len,
                to_str_ptr!(passphrase)?,
                passphrase.len(),
            )
        })
    }

    /// Add key slot with a key
    pub fn add_by_key(
        &mut self,
        volume_key: Option<&str>,
        passphrase: &str,
        flags: CryptVolumeKeyFlags,
    ) -> Result<c_int, LibcryptErr> {
        let (vk_ptr, vk_len) = match volume_key {
            Some(vk) => (to_str_ptr!(vk)?, vk.len()),
            None => (std::ptr::null(), 0),
        };
        errno_int_success!(unsafe {
            crypt_keyslot_add_by_key(
                self.reference.as_ptr(),
                self.keyslot,
                vk_ptr,
                vk_len,
                to_str_ptr!(passphrase)?,
                passphrase.len(),
                flags.into(),
            )
        })
    }

    /// Destroy key slot
    pub fn destroy(&mut self) -> Result<(), LibcryptErr> {
        errno!(unsafe { crypt_keyslot_destroy(self.reference.as_ptr(), self.keyslot) })
    }

    /// Get keyslot status
    pub fn status(&mut self) -> Result<KeyslotInfo, LibcryptErr> {
        try_int_to_return!(
            unsafe { crypt_keyslot_status(self.reference.as_ptr(), self.keyslot) },
            KeyslotInfo
        )
    }

    /// Get keyslot priority (LUKS2 specific)
    pub fn get_priority(&mut self) -> Result<KeyslotPriority, LibcryptErr> {
        try_int_to_return!(
            unsafe { crypt_keyslot_get_priority(self.reference.as_ptr(), self.keyslot) },
            KeyslotPriority
        )
    }

    /// Get keyslot priority (LUKS2 specific)
    pub fn set_priority(&mut self, priority: KeyslotPriority) -> Result<(), LibcryptErr> {
        errno!(unsafe {
            crypt_keyslot_set_priority(self.reference.as_ptr(), self.keyslot, priority as i32)
        })
    }

    /// Get maximum keyslots supported for device type
    pub fn max_keyslots(fmt: Format) -> Result<c_int, LibcryptErr> {
        errno_int_success!(unsafe { crypt_keyslot_max(fmt.as_ptr()) })
    }

    /// Get keyslot area pointers
    pub fn area(&mut self) -> Result<(u64, u64), LibcryptErr> {
        let mut offset = 0u64;
        let mut length = 0u64;
        errno!(unsafe {
            crypt_keyslot_area(
                self.reference.as_ptr(),
                self.keyslot,
                &mut offset as *mut u64,
                &mut length as *mut u64,
            )
        })
        .map(|_| (offset, length))
    }

    /// Get size of key in keyslot - only different from `crypt_get_volume_key_size()` binding
    /// in the case of LUKS2 using unbound keyslots
    pub fn get_key_size(&mut self) -> Result<c_int, LibcryptErr> {
        errno_int_success!(unsafe {
            crypt_keyslot_get_key_size(self.reference.as_ptr(), self.keyslot)
        })
    }

    /// Get encryption cipher and key size of keyslot (not data)
    pub fn get_encryption(&mut self) -> Result<(&str, crate::SizeT), LibcryptErr> {
        let mut key_size: crate::SizeT = 0;
        ptr_to_result!(unsafe {
            crypt_keyslot_get_encryption(
                self.reference.as_ptr(),
                self.keyslot,
                &mut key_size as *mut crate::SizeT,
            )
        })
        .and_then(|ptr| from_str_ptr!(ptr))
        .map(|st| (st, key_size))
    }

    /// Get PBDKF parameters for a keyslot
    pub fn get_pbkdf(&mut self) -> Result<CryptPbkdfType, LibcryptErr> {
        let mut type_ = cryptsetup_sys::crypt_pbkdf_type {
            type_: ptr::null(),
            hash: ptr::null(),
            time_ms: 0,
            iterations: 0,
            max_memory_kb: 0,
            parallel_threads: 0,
            flags: 0,
        };
        errno!(unsafe {
            crypt_keyslot_get_pbkdf(self.reference.as_ptr(), self.keyslot, &mut type_ as *mut _)
        })
        .and_then(|_| CryptPbkdfType::try_from(type_))
    }

    /// Set encryption used for keyslot
    pub fn set_encryption(
        &mut self,
        cipher: &str,
        key_size: crate::SizeT,
    ) -> Result<(), LibcryptErr> {
        errno!(unsafe {
            crypt_keyslot_set_encryption(self.reference.as_ptr(), to_str_ptr!(cipher)?, key_size)
        })
    }

    /// Get directory where crypt devices are mapped
    pub fn get_dir() -> Result<Box<Path>, LibcryptErr> {
        ptr_to_result!(unsafe { cryptsetup_sys::crypt_get_dir() })
            .and_then(|s| from_str_ptr_to_owned!(s))
            .map(PathBuf::from)
            .map(|b| b.into_boxed_path())
    }
}
