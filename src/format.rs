use std::{ffi::CStr, os::raw::c_char};

use crate::{device::CryptDevice, err::LibcryptErr};

use cryptsetup_sys::*;

/// Device formatting type options
pub enum Format {
    #[allow(missing_docs)]
    Plain,
    #[allow(missing_docs)]
    Luks1,
    #[allow(missing_docs)]
    Luks2,
    #[allow(missing_docs)]
    Loopaes,
    #[allow(missing_docs)]
    Verity,
    #[allow(missing_docs)]
    Tcrypt,
    #[allow(missing_docs)]
    Integrity,
}

impl Format {
    /// Get `Format` as a char pointer
    pub(crate) fn as_ptr(&self) -> *const c_char {
        match *self {
            Format::Plain => cryptsetup_sys::CRYPT_PLAIN.as_ptr() as *const c_char,
            Format::Luks1 => cryptsetup_sys::CRYPT_LUKS1.as_ptr() as *const c_char,
            Format::Luks2 => cryptsetup_sys::CRYPT_LUKS2.as_ptr() as *const c_char,
            Format::Loopaes => cryptsetup_sys::CRYPT_LOOPAES.as_ptr() as *const c_char,
            Format::Verity => cryptsetup_sys::CRYPT_VERITY.as_ptr() as *const c_char,
            Format::Tcrypt => cryptsetup_sys::CRYPT_TCRYPT.as_ptr() as *const c_char,
            Format::Integrity => cryptsetup_sys::CRYPT_INTEGRITY.as_ptr() as *const c_char,
        }
    }

    /// Get `Format` from a char pointer
    fn from_ptr(p: *const c_char) -> Result<Self, LibcryptErr> {
        if cryptsetup_sys::CRYPT_PLAIN == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Plain)
        } else if cryptsetup_sys::CRYPT_LUKS1 == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Luks1)
        } else if cryptsetup_sys::CRYPT_LUKS2 == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Luks2)
        } else if cryptsetup_sys::CRYPT_LOOPAES == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Loopaes)
        } else if cryptsetup_sys::CRYPT_VERITY == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Verity)
        } else if cryptsetup_sys::CRYPT_TCRYPT == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Tcrypt)
        } else if cryptsetup_sys::CRYPT_INTEGRITY == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Integrity)
        } else {
            Err(LibcryptErr::InvalidConversion)
        }
    }
}

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
