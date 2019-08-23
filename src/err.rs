use std::{
    error::Error,
    ffi::NulError,
    fmt::{self, Display},
    io,
    str::Utf8Error,
};

#[derive(Debug)]
/// Error returned from any libcryptsetup-rs function
pub enum LibcryptErr {
    /// Wrapper for `io::Error`
    IOError(io::Error),
    /// Wrapper for `ffi::NulError`
    StrError(NulError),
    /// Wrapper for `str::Utf8Error`
    Utf8Error(Utf8Error),
    /// Indicates that a Rust/C conversion was unsuccessful
    InvalidConversion,
    /// Indicates that a pointer returned was null signifying an error
    NullPtr,
}

impl Display for LibcryptErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LibcryptErr::IOError(ref e) => write!(f, "{}", e),
            LibcryptErr::StrError(ref e) => write!(f, "{}", e),
            LibcryptErr::Utf8Error(ref e) => write!(f, "{}", e),
            LibcryptErr::InvalidConversion => {
                write!(f, "Failed to perform the specified conversion")
            }
            LibcryptErr::NullPtr => write!(f, "Cryptsetup returned a null pointer"),
        }
    }
}

impl Error for LibcryptErr {}
