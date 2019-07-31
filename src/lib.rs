extern crate cryptsetup_sys;

#[macro_use]
mod macros;

mod device;
pub use device::{Accepted, CryptDevice, CryptInit, CryptLog, CryptLogLevel};

mod err;
