use std::{
    os::raw::{c_char, c_int, c_void},
    path::Path,
};

use crate::{device::CryptDevice, err::LibcryptErr, Bool, Format};

use cryptsetup_sys::*;
use uuid::Uuid;

/// Cryptographic context for device
pub struct CryptContext<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptContext<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptContext { reference }
    }

    /// Set cryptography format
    pub fn format<T>(
        &mut self,
        type_: Format,
        cipher_and_mode: (&str, &str),
        uuid: Uuid,
        volume_key: &str,
        params: &mut T,
    ) -> Result<(), LibcryptErr> {
        errno!(unsafe {
            crypt_format(
                self.reference.as_ptr(),
                type_.as_ptr(),
                to_str_ptr!(cipher_and_mode.0)?,
                to_str_ptr!(cipher_and_mode.1)?,
                uuid.as_bytes().as_ptr() as *const c_char,
                to_str_ptr!(volume_key)?,
                volume_key.len() as crate::SizeT,
                params as *mut _ as *mut c_void,
            )
        })
    }

    /// Convert to new format type
    pub fn convert<T>(&mut self, type_: Format, params: &mut T) -> Result<(), LibcryptErr> {
        errno!(unsafe {
            crypt_convert(
                self.reference.as_ptr(),
                type_.as_ptr(),
                params as *mut _ as *mut c_void,
            )
        })
    }

    /// Set UUID of crypt device
    pub fn set_uuid(&mut self, uuid: Uuid) -> Result<(), LibcryptErr> {
        errno!(unsafe {
            crypt_set_uuid(
                self.reference.as_ptr(),
                uuid.as_bytes().as_ptr() as *const c_char,
            )
        })
    }

    /// Set LUKS2 device label
    pub fn set_label(&mut self, label: &str, subsystem_label: &str) -> Result<(), LibcryptErr> {
        errno!(unsafe {
            crypt_set_label(
                self.reference.as_ptr(),
                to_str_ptr!(label)?,
                to_str_ptr!(subsystem_label)?,
            )
        })
    }

    /// Set policty on loading volume keys via kernel keyring
    pub fn volume_key_keyring(&mut self, enable: Bool) -> Result<(), LibcryptErr> {
        errno!(unsafe { crypt_volume_key_keyring(self.reference.as_ptr(), enable as c_int) })
    }

    /// Load on-disk header parameters based on provided type
    pub fn load<T>(&mut self, type_: Format, params: &mut T) -> Result<(), LibcryptErr> {
        errno!(unsafe {
            crypt_load(
                self.reference.as_ptr(),
                type_.as_ptr(),
                params as *mut _ as *mut c_void,
            )
        })
    }

    /// Repair crypt device header if invalid
    pub fn repair<T>(&mut self, type_: Format, params: &mut T) -> Result<(), LibcryptErr> {
        errno!(unsafe {
            crypt_repair(
                self.reference.as_ptr(),
                type_.as_ptr(),
                params as *mut _ as *mut c_void,
            )
        })
    }

    /// Resize crypt device
    pub fn resize(&mut self, name: &str, new_size: u64) -> Result<(), LibcryptErr> {
        errno!(unsafe { crypt_resize(self.reference.as_ptr(), to_str_ptr!(name)?, new_size,) })
    }

    /// Suspend crypt device
    pub fn suspend(&mut self, name: &str) -> Result<(), LibcryptErr> {
        errno!(unsafe { crypt_suspend(self.reference.as_ptr(), to_str_ptr!(name)?,) })
    }

    /// Resume crypt device using a passphrase
    pub fn resume_by_passphrase(
        &mut self,
        name: &str,
        keyslot: c_int,
        passphrase: &str,
    ) -> Result<c_int, LibcryptErr> {
        errno_int_success!(unsafe {
            crypt_resume_by_passphrase(
                self.reference.as_ptr(),
                to_str_ptr!(name)?,
                keyslot,
                to_str_ptr!(passphrase)?,
                passphrase.len() as crate::SizeT,
            )
        })
    }

    /// Resume crypt device using a key file at an offset on disk
    pub fn resume_by_keyfile_device_offset(
        &mut self,
        name: &str,
        keyslot: c_int,
        keyfile: &Path,
        keyfile_size: crate::SizeT,
        keyfile_offset: u64,
    ) -> Result<c_int, LibcryptErr> {
        errno_int_success!(unsafe {
            crypt_resume_by_keyfile_device_offset(
                self.reference.as_ptr(),
                to_str_ptr!(name)?,
                keyslot,
                path_to_str_ptr!(keyfile)?,
                keyfile_size,
                keyfile_offset,
            )
        })
    }
}
