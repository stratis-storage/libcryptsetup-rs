#![deny(missing_docs)]

//! This is a wrapper library for libcryptsetup. The intension is to provide as much safety as
//! possible when crossing FFI boundaries to the crypsetup C library.

extern crate cryptsetup_sys;
extern crate libc;
extern crate uuid;

use std::ffi::CStr;

pub use cryptsetup_sys::*;

#[macro_use]
mod macros;

mod context;
pub use context::CryptContext;

mod device;
pub use device::{CryptDevice, CryptInit};

mod err;
pub use err::LibcryptErr;

mod format;
pub use format::CryptFormat;

mod log;
pub use log::{CryptLog, CryptLogLevel};

mod settings;
pub use settings::CryptSettings;

/// Re-export of `libc::size_t`
pub type SizeT = libc::size_t;

/// Boolean specifying yes or no
#[derive(Debug, Eq, PartialEq)]
pub enum Bool {
    /// False
    No = 0,
    /// True
    Yes = 1,
}

impl From<std::os::raw::c_int> for Bool {
    fn from(v: std::os::raw::c_int) -> Self {
        match v {
            i if i == 0 => Bool::No,
            _ => Bool::Yes,
        }
    }
}

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
    fn as_ptr(&self) -> *const std::os::raw::c_char {
        match *self {
            Format::Plain => cryptsetup_sys::CRYPT_PLAIN.as_ptr() as *const std::os::raw::c_char,
            Format::Luks1 => cryptsetup_sys::CRYPT_LUKS1.as_ptr() as *const std::os::raw::c_char,
            Format::Luks2 => cryptsetup_sys::CRYPT_LUKS2.as_ptr() as *const std::os::raw::c_char,
            Format::Loopaes => {
                cryptsetup_sys::CRYPT_LOOPAES.as_ptr() as *const std::os::raw::c_char
            }
            Format::Verity => cryptsetup_sys::CRYPT_VERITY.as_ptr() as *const std::os::raw::c_char,
            Format::Tcrypt => cryptsetup_sys::CRYPT_TCRYPT.as_ptr() as *const std::os::raw::c_char,
            Format::Integrity => {
                cryptsetup_sys::CRYPT_INTEGRITY.as_ptr() as *const std::os::raw::c_char
            }
        }
    }

    /// Get `Format` from a char pointer
    fn from_ptr(p: *const std::os::raw::c_char) -> Result<Self, LibcryptErr> {
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
