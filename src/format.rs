use crate::{device::CryptDevice, err::LibcryptErr, Format};

use cryptsetup_sys::*;

/// Handle for format operations on a device
pub struct CryptFormat<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptFormat<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptFormat { reference }
    }

    /// Get the formatting type
    pub fn get_type(&mut self) -> Result<Format, LibcryptErr> {
        Format::from_ptr(unsafe { crypt_get_type(self.reference.as_ptr()) })
    }

    /// Get the default formatting type
    pub fn get_default_type() -> Result<Format, LibcryptErr> {
        Format::from_ptr(unsafe { crypt_get_default_type() })
    }
}
