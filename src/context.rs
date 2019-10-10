use std::{
    os::raw::{c_char, c_int, c_void},
    path::Path,
    ptr,
};

use crate::{device::CryptDevice, err::LibcryptErr, format::Format, Bool};

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
        volume_key: Option<&[u8]>,
        params: &mut T,
    ) -> Result<(), LibcryptErr> {
        let (volume_key_ptr, volume_key_len) = match volume_key {
            Some(vk) => (to_byte_ptr!(vk), vk.len()),
            None => (ptr::null(), 0),
        };
        let (cipher, cipher_mode) = cipher_and_mode;
        let cipher_cstring = to_cstring!(cipher)?;
        let cipher_mode_cstring = to_cstring!(cipher_mode)?;
        errno!(unsafe {
            crypt_format(
                self.reference.as_ptr(),
                type_.as_ptr(),
                cipher_cstring.as_ptr(),
                cipher_mode_cstring.as_ptr(),
                uuid.as_bytes().as_ptr() as *const c_char,
                volume_key_ptr,
                volume_key_len,
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
    pub fn set_uuid(&mut self, uuid: Option<Uuid>) -> Result<(), LibcryptErr> {
        let uptr = match uuid {
            Some(u) => u.as_bytes().as_ptr() as *const c_char,
            None => std::ptr::null(),
        };
        errno!(unsafe { crypt_set_uuid(self.reference.as_ptr(), uptr) })
    }

    /// Set LUKS2 device label
    pub fn set_label(
        &mut self,
        label: Option<&str>,
        subsystem_label: Option<&str>,
    ) -> Result<(), LibcryptErr> {
        let (lcstring, slcstring) = match (label, subsystem_label) {
            (Some(l), Some(sl)) => (Some(to_cstring!(l)?), Some(to_cstring!(sl)?)),
            (Some(l), _) => (Some(to_cstring!(l)?), None),
            (_, Some(sl)) => (None, Some(to_cstring!(sl)?)),
            (_, _) => (None, None),
        };
        errno!(unsafe {
            crypt_set_label(
                self.reference.as_ptr(),
                lcstring.map(|cs| cs.as_ptr()).unwrap_or(ptr::null()),
                slcstring.map(|cs| cs.as_ptr()).unwrap_or(ptr::null()),
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
        let name_cstring = to_cstring!(name)?;
        errno!(unsafe { crypt_resize(self.reference.as_ptr(), name_cstring.as_ptr(), new_size) })
    }

    /// Suspend crypt device
    pub fn suspend(&mut self, name: &str) -> Result<(), LibcryptErr> {
        let name_cstring = to_cstring!(name)?;
        errno!(unsafe { crypt_suspend(self.reference.as_ptr(), name_cstring.as_ptr()) })
    }

    /// Resume crypt device using a passphrase
    pub fn resume_by_passphrase(
        &mut self,
        name: &str,
        keyslot: c_int,
        passphrase: &str,
    ) -> Result<c_int, LibcryptErr> {
        let name_cstring = to_cstring!(name)?;
        let passphrase_cstring = to_cstring!(passphrase)?;
        errno_int_success!(unsafe {
            crypt_resume_by_passphrase(
                self.reference.as_ptr(),
                name_cstring.as_ptr(),
                keyslot,
                passphrase_cstring.as_ptr(),
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
        let name_cstring = to_cstring!(name)?;
        let keyfile_cstring = path_to_cstring!(keyfile)?;
        errno_int_success!(unsafe {
            crypt_resume_by_keyfile_device_offset(
                self.reference.as_ptr(),
                name_cstring.as_ptr(),
                keyslot,
                keyfile_cstring.as_ptr(),
                keyfile_size,
                keyfile_offset,
            )
        })
    }
}
