#![deny(missing_docs)]

//! This is a wrapper library for libcryptsetup. The intension is to provide as much safety as
//! possible when crossing FFI boundaries to the crypsetup C library.

extern crate cryptsetup_sys;
extern crate libc;
extern crate uuid;

use std::os::raw::c_int;

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

mod keyslot;
pub use keyslot::CryptKeyslot;

mod log;
pub use log::{CryptLog, CryptLogLevel};

mod luks2_flags;
pub use luks2_flags::{CryptLuks2Flags, CryptRequirement, CryptRequirementFlags};

mod runtime;
pub use runtime::CryptRuntime;

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

impl From<c_int> for Bool {
    fn from(v: c_int) -> Self {
        match v {
            i if i == 0 => Bool::No,
            _ => Bool::Yes,
        }
    }
}
