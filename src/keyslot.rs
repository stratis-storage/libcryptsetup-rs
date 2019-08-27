use std::{convert::TryFrom, path::Path};

use crate::{device::CryptDevice, err::LibcryptErr};

use cryptsetup_sys::*;

pub enum CryptVolumeKeyFlag {
    NoSegment = cryptsetup_sys::CRYPT_VOLUME_KEY_NO_SEGMENT as isize,
    Set = cryptsetup_sys::CRYPT_VOLUME_KEY_SET as isize,
    DigestReuse = cryptsetup_sys::CRYPT_VOLUME_KEY_DIGEST_REUSE as isize,
}

pub struct KeyFlags(Vec<CryptVolumeKeyFlag>);

impl KeyFlags {
    pub fn new(no_segment: bool, set: bool, digest_reuse: bool) -> Self {
        let mut vec = vec![];
        if no_segment {
            vec.push(CryptVolumeKeyFlag::NoSegment);
        }
        if set {
            vec.push(CryptVolumeKeyFlag::Set);
        }
        if digest_reuse {
            vec.push(CryptVolumeKeyFlag::DigestReuse);
        }
        KeyFlags(vec)
    }
}

impl Into<u32> for KeyFlags {
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
}

impl<'a> CryptKeyslot<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptKeyslot { reference }
    }

    /// Add key slot using a passphrase
    pub fn add_by_passphrase(
        &mut self,
        keyslot: std::os::raw::c_int,
        passphrase: &str,
        new_passphrase: &str,
    ) -> Result<std::os::raw::c_int, LibcryptErr> {
        errno_int_success!(unsafe {
            crypt_keyslot_add_by_passphrase(
                self.reference.as_ptr(),
                keyslot,
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
        keyslot_old: std::os::raw::c_int,
        keyslot_new: std::os::raw::c_int,
        passphrase: &str,
        new_passphrase: &str,
    ) -> Result<std::os::raw::c_int, LibcryptErr> {
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
        keyslot: std::os::raw::c_int,
        keyfile_and_size: (&Path, crate::SizeT),
        keyfile_offset: u64,
        new_keyfile_and_size: (&Path, crate::SizeT),
        new_keyfile_offset: u64,
    ) -> Result<std::os::raw::c_int, LibcryptErr> {
        let (keyfile, keyfile_size) = keyfile_and_size;
        let (new_keyfile, new_keyfile_size) = new_keyfile_and_size;
        errno_int_success!(unsafe {
            crypt_keyslot_add_by_keyfile_device_offset(
                self.reference.as_ptr(),
                keyslot,
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
        keyslot: std::os::raw::c_int,
        volume_key: Option<&str>,
        passphrase: &str,
    ) -> Result<std::os::raw::c_int, LibcryptErr> {
        let (vk_ptr, vk_len) = match volume_key {
            Some(vk) => (to_str_ptr!(vk)?, vk.len()),
            None => (std::ptr::null(), 0),
        };
        errno_int_success!(unsafe {
            crypt_keyslot_add_by_volume_key(
                self.reference.as_ptr(),
                keyslot,
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
        keyslot: std::os::raw::c_int,
        volume_key: Option<&str>,
        passphrase: &str,
        flags: KeyFlags,
    ) -> Result<std::os::raw::c_int, LibcryptErr> {
        let (vk_ptr, vk_len) = match volume_key {
            Some(vk) => (to_str_ptr!(vk)?, vk.len()),
            None => (std::ptr::null(), 0),
        };
        errno_int_success!(unsafe {
            crypt_keyslot_add_by_key(
                self.reference.as_ptr(),
                keyslot,
                vk_ptr,
                vk_len,
                to_str_ptr!(passphrase)?,
                passphrase.len(),
                flags.into(),
            )
        })
    }

    /// Destroy key slot
    pub fn destroy(&mut self, keyslot: std::os::raw::c_int) -> Result<(), LibcryptErr> {
        errno!(unsafe { crypt_keyslot_destroy(self.reference.as_ptr(), keyslot) })
    }

    /// Get keyslot status
    pub fn status(&mut self, keyslot: std::os::raw::c_int) -> Result<KeyslotInfo, LibcryptErr> {
        try_int_to_return!(
            unsafe { crypt_keyslot_status(self.reference.as_ptr(), keyslot) },
            KeyslotInfo
        )
    }

    /// Get keyslot priority (LUKS2 specific)
    pub fn priority(
        &mut self,
        keyslot: std::os::raw::c_int,
    ) -> Result<KeyslotPriority, LibcryptErr> {
        try_int_to_return!(
            unsafe { crypt_keyslot_get_priority(self.reference.as_ptr(), keyslot) },
            KeyslotPriority
        )
    }
}
