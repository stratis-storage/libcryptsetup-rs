extern crate cryptsetup_sys;

#[macro_use]
mod macros;

mod device;
pub use device::CryptDevice;

mod err;
