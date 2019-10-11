use std::{os::raw::c_int, path::Path, ptr};

use crate::{device::CryptDevice, err::LibcryptErr, runtime::CryptActivateFlags};

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

    /// Activate device by passphrase
    pub fn activate_by_passphrase(
        &mut self,
        keyslot: c_int,
        passphrase: &str,
        flags: CryptActivateFlags,
    ) -> Result<c_int, LibcryptErr> {
        let name_cstring = to_cstring!(self.name)?;
        let passphrase_cstring = to_cstring!(passphrase)?;
        errno_int_success!(unsafe {
            cryptsetup_sys::crypt_activate_by_passphrase(
                self.reference.as_ptr(),
                name_cstring.as_ptr(),
                keyslot,
                passphrase_cstring.as_ptr(),
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
        keyfile_size: crate::size_t,
        keyfile_offset: u64,
        flags: CryptActivateFlags,
    ) -> Result<c_int, LibcryptErr> {
        let name_cstring = to_cstring!(self.name)?;
        let keyfile_cstring = path_to_cstring!(keyfile)?;
        errno_int_success!(unsafe {
            cryptsetup_sys::crypt_activate_by_keyfile_device_offset(
                self.reference.as_ptr(),
                name_cstring.as_ptr(),
                keyslot,
                keyfile_cstring.as_ptr(),
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
        let name_cstring = to_cstring!(self.name)?;
        errno!(unsafe {
            cryptsetup_sys::crypt_activate_by_volume_key(
                self.reference.as_ptr(),
                name_cstring.as_ptr(),
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
        let name_cstring = to_cstring!(self.name)?;
        let description_cstring = to_cstring!(key_description)?;
        errno_int_success!(unsafe {
            cryptsetup_sys::crypt_activate_by_keyring(
                self.reference.as_ptr(),
                name_cstring.as_ptr(),
                description_cstring.as_ptr(),
                keyslot,
                flags.into(),
            )
        })
    }

    /// Deactivate crypt device
    pub fn deactivate(&mut self, flags: CryptDeactivateFlags) -> Result<(), LibcryptErr> {
        let name_cstring = to_cstring!(self.name)?;
        errno!(unsafe {
            cryptsetup_sys::crypt_deactivate_by_name(
                self.reference.as_ptr(),
                name_cstring.as_ptr(),
                flags.into(),
            )
        })
    }
}
