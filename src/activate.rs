use std::{os::raw::c_int, path::Path, ptr};

use crate::{device::CryptDevice, err::LibcryptErr, runtime::CryptActivateFlags};

use cryptsetup_cli_proc_macro::wrap_fn_args;

consts_to_from_enum!(
    /// Flags for crypt deactivate operations
    CryptDeactivateFlag,
    u32,
    Deferred => cryptsetup_sys::CRYPT_DEACTIVATE_DEFERRED,
    Force => cryptsetup_sys::CRYPT_DEACTIVATE_FORCE
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
    name: &'a str,
}

impl<'a> CryptActivation<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice, name: &'a str) -> Self {
        CryptActivation { reference, name }
    }

    #[wrap_fn_args]
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
        volume_key: Option<&[u8]>,
        flags: CryptActivateFlags,
    ) -> Result<(), LibcryptErr> {
        let (volume_key_ptr, volume_key_len) = match volume_key {
            Some(vk) => (to_byte_ptr!(vk), vk.len()),
            None => (ptr::null(), 0),
        };
        errno!(unsafe {
            cryptsetup_sys::crypt_activate_by_volume_key(
                self.reference.as_ptr(),
                to_str_ptr!(self.name)?,
                volume_key_ptr,
                volume_key_len,
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
