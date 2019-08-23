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
}
