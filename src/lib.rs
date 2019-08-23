#![deny(missing_docs)]

//! This is a wrapper library for libcryptsetup. The intension is to provide as much safety as
//! possible when crossing FFI boundaries to the crypsetup C library.

extern crate cryptsetup_sys;

#[macro_use]
mod macros;

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
