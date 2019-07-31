extern crate cryptsetup_sys;

#[macro_use]
mod macros;

mod device;
pub use device::{CryptDevice,CryptInit};

mod err;

use std::os::raw::c_int;

#[derive(Debug, Eq, PartialEq)]
enum Accepted {
    No = 0,
    Yes = 1,
}

impl From<c_int> for Accepted {
    fn from(v: c_int) -> Self {
        match v {
            i if i == 0 => Accepted::No,
            _ => Accepted::Yes,
        }
    }
}

impl Into<c_int> for Accepted {
    fn into(self) -> c_int {
        self as c_int
    }
}
