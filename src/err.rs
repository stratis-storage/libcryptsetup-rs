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
