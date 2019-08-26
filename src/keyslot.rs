use std::path::Path;

use crate::{device::CryptDevice, err::LibcryptErr};

use cryptsetup_sys::*;

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
}
