use std::{
    error::Error,
    ffi::NulError,
    fmt::{self, Display},
    io,
    str::Utf8Error,
};

#[derive(Debug)]
pub enum CryptSetupErr {
    IOError(io::Error),
    StrError(NulError),
    Utf8Error(Utf8Error),
}

impl Display for CryptSetupErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CryptSetupErr::IOError(ref e) => write!(f, "{}", e),
            CryptSetupErr::StrError(ref e) => write!(f, "{}", e),
            CryptSetupErr::Utf8Error(ref e) => write!(f, "{}", e),
        }
    }
}

impl Error for CryptSetupErr {}
