extern crate cryptsetup_sys;

#[macro_use]
mod macros;

mod device;
pub use device::{CryptDevice, CryptInit};

mod err;
pub use err::LibcryptErr;

mod log;
pub use log::{CryptLog, CryptLogLevel};

mod settings;
pub use settings::CryptSettings;

#[derive(Debug, Eq, PartialEq)]
pub enum Bool {
    No = 0,
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
