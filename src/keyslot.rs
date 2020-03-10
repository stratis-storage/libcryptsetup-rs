// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    convert::TryFrom,
    path::{Path, PathBuf},
    ptr,
};

use libc::{c_int, c_uint};

use crate::{
    device::CryptDevice, err::LibcryptErr, format::EncryptionFormat, settings::CryptPbkdfType,
};

consts_to_from_enum!(
    /// Flags for tunable options when operating with volume keys
    CryptVolumeKeyFlag,
    u32,
    NoSegment => libcryptsetup_rs_sys::CRYPT_VOLUME_KEY_NO_SEGMENT,
    Set => libcryptsetup_rs_sys::CRYPT_VOLUME_KEY_SET,
    DigestReuse => libcryptsetup_rs_sys::CRYPT_VOLUME_KEY_DIGEST_REUSE
);

bitflags_to_from_struct!(
    /// Set of volume key flags
    CryptVolumeKeyFlags,
    CryptVolumeKeyFlag,
    u32
);

consts_to_from_enum!(
    /// Value indicating the status of a keyslot
    KeyslotInfo,
    u32,
    Invalid => libcryptsetup_rs_sys::crypt_keyslot_info_CRYPT_SLOT_INVALID,
    Inactive => libcryptsetup_rs_sys::crypt_keyslot_info_CRYPT_SLOT_INACTIVE,
    Active => libcryptsetup_rs_sys::crypt_keyslot_info_CRYPT_SLOT_ACTIVE,
    ActiveLast => libcryptsetup_rs_sys::crypt_keyslot_info_CRYPT_SLOT_ACTIVE_LAST,
    Unbound => libcryptsetup_rs_sys::crypt_keyslot_info_CRYPT_SLOT_UNBOUND
);

consts_to_from_enum!(
    /// Value indicating the priority of a keyslot
    KeyslotPriority,
    i32,
    Invalid => libcryptsetup_rs_sys::crypt_keyslot_priority_CRYPT_SLOT_PRIORITY_INVALID,
    Ignore => libcryptsetup_rs_sys::crypt_keyslot_priority_CRYPT_SLOT_PRIORITY_IGNORE,
    Normal => libcryptsetup_rs_sys::crypt_keyslot_priority_CRYPT_SLOT_PRIORITY_NORMAL,
    Prefer => libcryptsetup_rs_sys::crypt_keyslot_priority_CRYPT_SLOT_PRIORITY_PREFER
);

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
        keyslot: Option<c_uint>,
        passphrase: &[u8],
        new_passphrase: &[u8],
    ) -> Result<c_uint, LibcryptErr> {
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_keyslot_add_by_passphrase(
                self.reference.as_ptr(),
                keyslot
                    .map(|k| k as c_int)
                    .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_SLOT),
                to_byte_ptr!(passphrase),
                passphrase.len(),
                to_byte_ptr!(new_passphrase),
                new_passphrase.len(),
            )
        })
        .map(|k| k as c_uint)
    }

    /// Change allocated key slot using a passphrase
    pub fn change_by_passphrase(
        &mut self,
        keyslot_old: Option<c_uint>,
        keyslot_new: Option<c_uint>,
        passphrase: &[u8],
        new_passphrase: &[u8],
    ) -> Result<c_int, LibcryptErr> {
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_keyslot_change_by_passphrase(
                self.reference.as_ptr(),
                keyslot_old
                    .map(|k| k as c_int)
                    .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_SLOT),
                keyslot_new
                    .map(|k| k as c_int)
                    .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_SLOT),
                to_byte_ptr!(passphrase),
                passphrase.len(),
                to_byte_ptr!(new_passphrase),
                new_passphrase.len(),
            )
        })
    }

    /// Add key slot using key file
    pub fn add_by_keyfile_device_offset(
        &mut self,
        keyslot: Option<c_uint>,
        keyfile_and_size: (&Path, crate::size_t),
        keyfile_offset: u64,
        new_keyfile_and_size: (&Path, crate::size_t),
        new_keyfile_offset: u64,
    ) -> Result<c_uint, LibcryptErr> {
        let (keyfile, keyfile_size) = keyfile_and_size;
        let (new_keyfile, new_keyfile_size) = new_keyfile_and_size;
        let keyfile_cstring = path_to_cstring!(keyfile)?;
        let new_keyfile_cstring = path_to_cstring!(new_keyfile)?;
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_keyslot_add_by_keyfile_device_offset(
                self.reference.as_ptr(),
                keyslot
                    .map(|k| k as c_int)
                    .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_SLOT),
                keyfile_cstring.as_ptr(),
                keyfile_size,
                keyfile_offset,
                new_keyfile_cstring.as_ptr(),
                new_keyfile_size,
                new_keyfile_offset,
            )
        })
        .map(|k| k as c_uint)
    }

    /// Add key slot with a key
    pub fn add_by_key(
        &mut self,
        keyslot: Option<c_uint>,
        volume_key: Option<&[u8]>,
        passphrase: &[u8],
        flags: CryptVolumeKeyFlags,
    ) -> Result<c_uint, LibcryptErr> {
        let (vk_ptr, vk_len) = match volume_key {
            Some(vk) => (to_byte_ptr!(vk), vk.len()),
            None => (std::ptr::null(), 0),
        };
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_keyslot_add_by_key(
                self.reference.as_ptr(),
                keyslot
                    .map(|k| k as c_int)
                    .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_SLOT),
                vk_ptr,
                vk_len,
                to_byte_ptr!(passphrase),
                passphrase.len(),
                flags.into(),
            )
        })
        .map(|k| k as c_uint)
    }

    /// Destroy key slot
    pub fn destroy(&mut self, keyslot: c_uint) -> Result<(), LibcryptErr> {
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_keyslot_destroy(self.reference.as_ptr(), keyslot as c_int)
        })
    }

    /// Get keyslot status
    pub fn status(&mut self, keyslot: c_uint) -> Result<KeyslotInfo, LibcryptErr> {
        try_int_to_return!(
            unsafe {
                libcryptsetup_rs_sys::crypt_keyslot_status(
                    self.reference.as_ptr(),
                    keyslot as c_int,
                )
            },
            KeyslotInfo
        )
    }

    /// Get keyslot priority (LUKS2 specific)
    pub fn get_priority(&mut self, keyslot: c_uint) -> Result<KeyslotPriority, LibcryptErr> {
        try_int_to_return!(
            unsafe {
                libcryptsetup_rs_sys::crypt_keyslot_get_priority(
                    self.reference.as_ptr(),
                    keyslot as c_int,
                )
            },
            KeyslotPriority
        )
    }

    /// Get keyslot priority (LUKS2 specific)
    pub fn set_priority(
        &mut self,
        keyslot: c_uint,
        priority: KeyslotPriority,
    ) -> Result<(), LibcryptErr> {
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_keyslot_set_priority(
                self.reference.as_ptr(),
                keyslot as c_int,
                priority.into(),
            )
        })
    }

    /// Get maximum keyslots supported for device type
    pub fn max_keyslots(fmt: EncryptionFormat) -> Result<c_uint, LibcryptErr> {
        errno_int_success!(unsafe { libcryptsetup_rs_sys::crypt_keyslot_max(fmt.as_ptr()) })
            .map(|k| k as c_uint)
    }

    /// Get keyslot area pointers
    pub fn area(&mut self, keyslot: c_uint) -> Result<(u64, u64), LibcryptErr> {
        let mut offset = 0u64;
        let mut length = 0u64;
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_keyslot_area(
                self.reference.as_ptr(),
                keyslot as c_int,
                &mut offset as *mut u64,
                &mut length as *mut u64,
            )
        })
        .map(|_| (offset, length))
    }

    /// Get size of key in keyslot - only different from `crypt_get_volume_key_size()` binding
    /// in the case of LUKS2 using unbound keyslots
    pub fn get_key_size(&mut self, keyslot: c_uint) -> Result<c_uint, LibcryptErr> {
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_keyslot_get_key_size(
                self.reference.as_ptr(),
                keyslot as c_int,
            )
        })
        .map(|k| k as c_uint)
    }

    /// Get encryption cipher and key size of keyslot (not data)
    pub fn get_encryption(
        &mut self,
        keyslot: Option<c_uint>,
    ) -> Result<(&str, crate::size_t), LibcryptErr> {
        let mut key_size: crate::size_t = 0;
        ptr_to_result!(unsafe {
            libcryptsetup_rs_sys::crypt_keyslot_get_encryption(
                self.reference.as_ptr(),
                keyslot
                    .map(|k| k as c_int)
                    .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_SLOT),
                &mut key_size as *mut crate::size_t,
            )
        })
        .and_then(|ptr| from_str_ptr!(ptr))
        .map(|st| (st, key_size))
    }

    /// Get PBDKF parameters for a keyslot
    pub fn get_pbkdf(&mut self, keyslot: c_uint) -> Result<CryptPbkdfType, LibcryptErr> {
        let mut type_ = libcryptsetup_rs_sys::crypt_pbkdf_type {
            type_: ptr::null(),
            hash: ptr::null(),
            time_ms: 0,
            iterations: 0,
            max_memory_kb: 0,
            parallel_threads: 0,
            flags: 0,
        };
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_keyslot_get_pbkdf(
                self.reference.as_ptr(),
                keyslot as c_int,
                &mut type_ as *mut _,
            )
        })
        .and_then(|_| CryptPbkdfType::try_from(type_))
    }

    /// Set encryption used for keyslot
    pub fn set_encryption(
        &mut self,
        cipher: &str,
        key_size: crate::size_t,
    ) -> Result<(), LibcryptErr> {
        let cipher_cstring = to_cstring!(cipher)?;
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_keyslot_set_encryption(
                self.reference.as_ptr(),
                cipher_cstring.as_ptr(),
                key_size,
            )
        })
    }

    /// Get directory where crypt devices are mapped
    pub fn get_dir() -> Result<Box<Path>, LibcryptErr> {
        ptr_to_result!(unsafe { libcryptsetup_rs_sys::crypt_get_dir() })
            .and_then(|s| from_str_ptr_to_owned!(s))
            .map(PathBuf::from)
            .map(|b| b.into_boxed_path())
    }
}
