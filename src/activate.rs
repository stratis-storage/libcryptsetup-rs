use std::{convert::TryFrom, os::raw::c_int, path::Path};

use crate::{device::CryptDevice, err::LibcryptErr, runtime::CryptActivateFlags};

pub enum CryptDeactivate {
    Deferred = cryptsetup_sys::CRYPT_DEACTIVATE_DEFERRED as isize,
    Force = cryptsetup_sys::CRYPT_DEACTIVATE_FORCE as isize,
}

impl TryFrom<u32> for CryptDeactivate {
    type Error = LibcryptErr;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        Ok(match v {
            i if i == CryptDeactivate::Deferred as u32 => CryptDeactivate::Deferred,
            i if i == CryptDeactivate::Force as u32 => CryptDeactivate::Force,
            _ => return Err(LibcryptErr::InvalidConversion),
        })
    }
}

pub struct CryptDeactivateFlags(Vec<CryptDeactivate>);

impl Into<u32> for CryptDeactivateFlags {
    fn into(self) -> u32 {
        self.0.into_iter().fold(0, |acc, flag| acc | flag as u32)
    }
}

bitflags_to_enum!(CryptDeactivateFlags, CryptDeactivate, u32);

/// Handle for activation options
pub struct CryptActivation<'a> {
    reference: &'a mut CryptDevice,
    name: &'a str,
}

impl<'a> CryptActivation<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice, name: &'a str) -> Self {
        CryptActivation { reference, name }
    }

    /// Activate device by passphrase
    pub fn activate_by_passphrase(
        &mut self,
        keyslot: c_int,
        passphrase: &str,
        flags: CryptActivateFlags,
    ) -> Result<c_int, LibcryptErr> {
        errno_int_success!(unsafe {
            cryptsetup_sys::crypt_activate_by_passphrase(
                self.reference.as_ptr(),
                to_str_ptr!(self.name)?,
                keyslot,
                to_str_ptr!(passphrase)?,
                passphrase.len(),
                flags.into(),
            )
        })
    }

    /// Activate device by key file
    pub fn activate_by_keyfile_device_offset(
        &mut self,
        keyslot: c_int,
        keyfile: &Path,
        keyfile_size: crate::SizeT,
        keyfile_offset: u64,
        flags: CryptActivateFlags,
    ) -> Result<c_int, LibcryptErr> {
        errno_int_success!(unsafe {
            cryptsetup_sys::crypt_activate_by_keyfile_device_offset(
                self.reference.as_ptr(),
                to_str_ptr!(self.name)?,
                keyslot,
                path_to_str_ptr!(keyfile)?,
                keyfile_size,
                keyfile_offset,
                flags.into(),
            )
        })
    }

    /// Activate device by volume key
    pub fn activate_by_volume_key(
        &mut self,
        volume_key: &str,
        flags: CryptActivateFlags,
    ) -> Result<(), LibcryptErr> {
        errno!(unsafe {
            cryptsetup_sys::crypt_activate_by_volume_key(
                self.reference.as_ptr(),
                to_str_ptr!(self.name)?,
                to_str_ptr!(volume_key)?,
                volume_key.len(),
                flags.into(),
            )
        })
    }

    /// Activeate device using passphrase in kernel keyring
    pub fn activate_by_keyring(
        &mut self,
        key_description: &str,
        keyslot: c_int,
        flags: CryptActivateFlags,
    ) -> Result<c_int, LibcryptErr> {
        errno_int_success!(unsafe {
            cryptsetup_sys::crypt_activate_by_keyring(
                self.reference.as_ptr(),
                to_str_ptr!(self.name)?,
                to_str_ptr!(key_description)?,
                keyslot,
                flags.into(),
            )
        })
    }

    /// Deactivate crypt device
    pub fn deactivate(&mut self, flags: CryptDeactivateFlags) -> Result<(), LibcryptErr> {
        errno!(unsafe {
            cryptsetup_sys::crypt_deactivate_by_name(
                self.reference.as_ptr(),
                to_str_ptr!(self.name)?,
                flags.into(),
            )
        })
    }
}
