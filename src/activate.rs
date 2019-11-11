use std::{os::raw::c_int, path::Path, ptr};

use crate::{device::CryptDevice, err::LibcryptErr, runtime::CryptActivateFlags};

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

    /// Activate device by passphrase
    pub fn activate_by_passphrase(
        &mut self,
        name: Option<&str>,
        keyslot: c_int,
        passphrase: &[u8],
        flags: CryptActivateFlags,
    ) -> Result<c_int, LibcryptErr> {
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
                keyslot,
                to_byte_ptr!(passphrase),
                passphrase.len(),
                flags.into(),
            )
        })
    }

    /// Activate device by key file
    pub fn activate_by_keyfile_device_offset(
        &mut self,
        name: Option<&str>,
        keyslot: c_int,
        keyfile: &Path,
        keyfile_size: Option<crate::size_t>,
        keyfile_offset: u64,
        flags: CryptActivateFlags,
    ) -> Result<c_int, LibcryptErr> {
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
                keyslot,
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
        keyslot: c_int,
        flags: CryptActivateFlags,
    ) -> Result<c_int, LibcryptErr> {
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
                keyslot,
                flags.into(),
            )
        })
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
