// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{path::Path, ptr};

use libc::{c_int, c_uint};

use crate::{device::CryptDevice, err::LibcryptErr};

consts_to_from_enum!(
    /// Enum wrapping `CRYPT_ACTIVATE_*` flags
    CryptActivateFlag,
    u32,
    Readonly => libcryptsetup_rs_sys::CRYPT_ACTIVATE_READONLY,
    NoUuid => libcryptsetup_rs_sys::CRYPT_ACTIVATE_NO_UUID,
    Shared => libcryptsetup_rs_sys::CRYPT_ACTIVATE_SHARED,
    AllowDiscards => libcryptsetup_rs_sys::CRYPT_ACTIVATE_ALLOW_DISCARDS,
    Private => libcryptsetup_rs_sys::CRYPT_ACTIVATE_PRIVATE,
    Corrupted => libcryptsetup_rs_sys::CRYPT_ACTIVATE_CORRUPTED,
    SameCpuCrypt => libcryptsetup_rs_sys::CRYPT_ACTIVATE_SAME_CPU_CRYPT,
    SubmitFromCryptCpus => libcryptsetup_rs_sys::CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS,
    IgnoreCorruption => libcryptsetup_rs_sys::CRYPT_ACTIVATE_IGNORE_CORRUPTION,
    RestartOnCorruption => libcryptsetup_rs_sys::CRYPT_ACTIVATE_RESTART_ON_CORRUPTION,
    IgnoreZeroBlocks => libcryptsetup_rs_sys::CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS,
    KeyringKey => libcryptsetup_rs_sys::CRYPT_ACTIVATE_KEYRING_KEY,
    NoJournal => libcryptsetup_rs_sys::CRYPT_ACTIVATE_NO_JOURNAL,
    Recovery => libcryptsetup_rs_sys::CRYPT_ACTIVATE_RECOVERY,
    IgnorePersistent => libcryptsetup_rs_sys::CRYPT_ACTIVATE_IGNORE_PERSISTENT,
    CheckAtMostOnce => libcryptsetup_rs_sys::CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE,
    AllowUnboundKey => libcryptsetup_rs_sys::CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY,
    Recalculate => libcryptsetup_rs_sys::CRYPT_ACTIVATE_RECALCULATE,
    Refresh => libcryptsetup_rs_sys::CRYPT_ACTIVATE_REFRESH,
    SerializeMemoryHardPbkdf => libcryptsetup_rs_sys::CRYPT_ACTIVATE_SERIALIZE_MEMORY_HARD_PBKDF,
    NoJournalBitmap => libcryptsetup_rs_sys::CRYPT_ACTIVATE_NO_JOURNAL_BITMAP
);

bitflags_to_from_struct!(
    /// Enum wrapping `CRYPT_ACTIVATE_*` flags
    CryptActivateFlags,
    CryptActivateFlag,
    u32
);

consts_to_from_enum!(
    /// Flags for crypt deactivate operations
    CryptDeactivateFlag,
    u32,
    Deferred => libcryptsetup_rs_sys::CRYPT_DEACTIVATE_DEFERRED,
    Force => libcryptsetup_rs_sys::CRYPT_DEACTIVATE_FORCE
);

bitflags_to_from_struct!(
    /// Set of flags for crypt deactivate operations
    CryptDeactivateFlags,
    CryptDeactivateFlag,
    u32
);

/// Handle for activation options
pub struct CryptActivation<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptActivation<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptActivation { reference }
    }

    /// Activate device by passphrase.
    ///
    /// A value of `None` for the name will only check the passphrase and will
    /// not activate the keyslot.
    pub fn activate_by_passphrase(
        &mut self,
        name: Option<&str>,
        keyslot: Option<c_uint>,
        passphrase: &[u8],
        flags: CryptActivateFlags,
    ) -> Result<c_uint, LibcryptErr> {
        let name_cstring_option = match name {
            Some(n) => Some(to_cstring!(n)?),
            None => None,
        };
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_activate_by_passphrase(
                self.reference.as_ptr(),
                match name_cstring_option {
                    Some(ref cs) => cs.as_ptr(),
                    None => ptr::null_mut(),
                },
                keyslot
                    .map(|k| k as c_int)
                    .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_SLOT),
                to_byte_ptr!(passphrase),
                passphrase.len(),
                flags.into(),
            )
        })
        .map(|k| k as c_uint)
    }

    /// Activate device by key file
    pub fn activate_by_keyfile_device_offset(
        &mut self,
        name: Option<&str>,
        keyslot: Option<c_uint>,
        keyfile: &Path,
        keyfile_size: Option<crate::size_t>,
        keyfile_offset: u64,
        flags: CryptActivateFlags,
    ) -> Result<c_uint, LibcryptErr> {
        let name_cstring_option = match name {
            Some(n) => Some(to_cstring!(n)?),
            None => None,
        };
        let keyfile_cstring = path_to_cstring!(keyfile)?;
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_activate_by_keyfile_device_offset(
                self.reference.as_ptr(),
                match name_cstring_option {
                    Some(ref cs) => cs.as_ptr(),
                    None => ptr::null_mut(),
                },
                keyslot
                    .map(|k| k as c_int)
                    .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_SLOT),
                keyfile_cstring.as_ptr(),
                match keyfile_size {
                    Some(i) => i,
                    None => std::fs::metadata(keyfile)
                        .map_err(LibcryptErr::IOError)?
                        .len() as crate::size_t,
                },
                keyfile_offset,
                flags.into(),
            )
        })
        .map(|k| k as c_uint)
    }

    /// Activate device by volume key
    pub fn activate_by_volume_key(
        &mut self,
        name: Option<&str>,
        volume_key: Option<&[u8]>,
        flags: CryptActivateFlags,
    ) -> Result<(), LibcryptErr> {
        let name_cstring_option = match name {
            Some(n) => Some(to_cstring!(n)?),
            None => None,
        };
        let (volume_key_ptr, volume_key_len) = match volume_key {
            Some(vk) => (to_byte_ptr!(vk), vk.len()),
            None => (ptr::null(), 0),
        };
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_activate_by_volume_key(
                self.reference.as_ptr(),
                match name_cstring_option {
                    Some(ref cs) => cs.as_ptr(),
                    None => ptr::null_mut(),
                },
                volume_key_ptr,
                volume_key_len,
                flags.into(),
            )
        })
    }

    /// Activeate device using passphrase in kernel keyring
    pub fn activate_by_keyring(
        &mut self,
        name: Option<&str>,
        key_description: &str,
        keyslot: Option<c_uint>,
        flags: CryptActivateFlags,
    ) -> Result<c_uint, LibcryptErr> {
        let name_cstring_option = match name {
            Some(n) => Some(to_cstring!(n)?),
            None => None,
        };
        let description_cstring = to_cstring!(key_description)?;
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_activate_by_keyring(
                self.reference.as_ptr(),
                match name_cstring_option {
                    Some(ref cs) => cs.as_ptr(),
                    None => ptr::null_mut(),
                },
                description_cstring.as_ptr(),
                keyslot
                    .map(|k| k as c_int)
                    .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_SLOT),
                flags.into(),
            )
        })
        .map(|k| k as c_uint)
    }

    /// Deactivate crypt device
    pub fn deactivate(
        &mut self,
        name: &str,
        flags: CryptDeactivateFlags,
    ) -> Result<(), LibcryptErr> {
        let name_cstring = to_cstring!(name)?;
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_deactivate_by_name(
                self.reference.as_ptr(),
                name_cstring.as_ptr(),
                flags.into(),
            )
        })
    }
}
