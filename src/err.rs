use std::{
    error::Error,
    ffi::NulError,
    fmt::{self, Display},
    io,
    str::Utf8Error,
};

#[derive(Debug)]
pub enum LibcryptErr {
    IOError(io::Error),
    StrError(NulError),
    Utf8Error(Utf8Error),
    InvalidConversion,
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
        }
    }
}

impl Error for LibcryptErr {}
