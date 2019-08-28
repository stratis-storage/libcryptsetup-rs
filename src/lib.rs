#![deny(missing_docs)]

//! This is a wrapper library for libcryptsetup. The intension is to provide as much safety as
//! possible when crossing FFI boundaries to the crypsetup C library.

extern crate cryptsetup_sys;
extern crate libc;
extern crate uuid;

use std::{
    convert::{TryFrom, TryInto},
    ffi::{CStr, CString},
    marker::PhantomData,
    os::raw::{c_char, c_int},
};

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

/// Device formatting type options
pub enum Format {
    #[allow(missing_docs)]
    Plain,
    #[allow(missing_docs)]
    Luks1,
    #[allow(missing_docs)]
    Luks2,
    #[allow(missing_docs)]
    Loopaes,
    #[allow(missing_docs)]
    Verity,
    #[allow(missing_docs)]
    Tcrypt,
    #[allow(missing_docs)]
    Integrity,
}

impl Format {
    /// Get `Format` as a char pointer
    fn as_ptr(&self) -> *const c_char {
        match *self {
            Format::Plain => cryptsetup_sys::CRYPT_PLAIN.as_ptr() as *const c_char,
            Format::Luks1 => cryptsetup_sys::CRYPT_LUKS1.as_ptr() as *const c_char,
            Format::Luks2 => cryptsetup_sys::CRYPT_LUKS2.as_ptr() as *const c_char,
            Format::Loopaes => cryptsetup_sys::CRYPT_LOOPAES.as_ptr() as *const c_char,
            Format::Verity => cryptsetup_sys::CRYPT_VERITY.as_ptr() as *const c_char,
            Format::Tcrypt => cryptsetup_sys::CRYPT_TCRYPT.as_ptr() as *const c_char,
            Format::Integrity => cryptsetup_sys::CRYPT_INTEGRITY.as_ptr() as *const c_char,
        }
    }

    /// Get `Format` from a char pointer
    fn from_ptr(p: *const c_char) -> Result<Self, LibcryptErr> {
        if cryptsetup_sys::CRYPT_PLAIN == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Plain)
        } else if cryptsetup_sys::CRYPT_LUKS1 == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Luks1)
        } else if cryptsetup_sys::CRYPT_LUKS2 == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Luks2)
        } else if cryptsetup_sys::CRYPT_LOOPAES == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Loopaes)
        } else if cryptsetup_sys::CRYPT_VERITY == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Verity)
        } else if cryptsetup_sys::CRYPT_TCRYPT == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Tcrypt)
        } else if cryptsetup_sys::CRYPT_INTEGRITY == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Integrity)
        } else {
            Err(LibcryptErr::InvalidConversion)
        }
    }
}

/// Rust representation of random number generator enum
pub enum CryptRng {
    #[allow(missing_docs)]
    Urandom = cryptsetup_sys::CRYPT_RNG_URANDOM as isize,
    #[allow(missing_docs)]
    Random = cryptsetup_sys::CRYPT_RNG_RANDOM as isize,
}

impl TryFrom<c_int> for CryptRng {
    type Error = LibcryptErr;

    fn try_from(v: c_int) -> Result<Self, Self::Error> {
        let rng_type = match v {
            i if i == CryptRng::Urandom as c_int => CryptRng::Urandom,
            i if i == CryptRng::Random as c_int => CryptRng::Random,
            _ => return Err(LibcryptErr::InvalidConversion),
        };
        Ok(rng_type)
    }
}

/// Rust representation of key generator enum
pub enum CryptKdf {
    #[allow(missing_docs)]
    Pbkdf2,
    #[allow(missing_docs)]
    Argon2I,
    #[allow(missing_docs)]
    Argon2Id,
}

impl CryptKdf {
    /// Convert to a `char *` for C
    fn as_ptr(&self) -> *const c_char {
        match *self {
            CryptKdf::Pbkdf2 => cryptsetup_sys::CRYPT_KDF_PBKDF2.as_ptr() as *const c_char,
            CryptKdf::Argon2I => cryptsetup_sys::CRYPT_KDF_ARGON2I.as_ptr() as *const c_char,
            CryptKdf::Argon2Id => cryptsetup_sys::CRYPT_KDF_ARGON2ID.as_ptr() as *const c_char,
        }
    }

    /// Convert from a C `char *`
    fn from_ptr(ptr: *const c_char) -> Result<Self, LibcryptErr> {
        if cryptsetup_sys::CRYPT_KDF_PBKDF2 == unsafe { CStr::from_ptr(ptr) }.to_bytes() {
            Ok(CryptKdf::Pbkdf2)
        } else if cryptsetup_sys::CRYPT_KDF_ARGON2I == unsafe { CStr::from_ptr(ptr) }.to_bytes() {
            Ok(CryptKdf::Argon2I)
        } else if cryptsetup_sys::CRYPT_KDF_ARGON2ID == unsafe { CStr::from_ptr(ptr) }.to_bytes() {
            Ok(CryptKdf::Argon2Id)
        } else {
            Err(LibcryptErr::InvalidConversion)
        }
    }
}

/// Rust representation of key generator flags
pub struct CryptPbkdfFlags {
    #[allow(missing_docs)]
    pub iter_time_set: bool,
    #[allow(missing_docs)]
    pub no_benchmark: bool,
}

impl Default for CryptPbkdfFlags {
    fn default() -> Self {
        CryptPbkdfFlags {
            iter_time_set: false,
            no_benchmark: false,
        }
    }
}

impl<'a> Into<u32> for &'a CryptPbkdfFlags {
    fn into(self) -> u32 {
        let mut flags = 0u32;
        if self.iter_time_set {
            flags |= cryptsetup_sys::CRYPT_PBKDF_ITER_TIME_SET as u32;
        }
        if self.no_benchmark {
            flags |= cryptsetup_sys::CRYPT_PBKDF_NO_BENCHMARK as u32;
        }
        flags
    }
}

impl From<u32> for CryptPbkdfFlags {
    fn from(v: u32) -> Self {
        let mut flags = CryptPbkdfFlags::default();
        if v & cryptsetup_sys::CRYPT_PBKDF_ITER_TIME_SET as u32 != 0 {
            flags.iter_time_set = true;
        }
        if v & cryptsetup_sys::CRYPT_PBKDF_NO_BENCHMARK as u32 != 0 {
            flags.no_benchmark = true;
        }
        flags
    }
}

/// Rust representation of `crypt_pbkdf_type`
pub struct CryptPbkdfType {
    #[allow(missing_docs)]
    pub type_: CryptKdf,
    #[allow(missing_docs)]
    pub hash: String,
    #[allow(missing_docs)]
    pub time_ms: u32,
    #[allow(missing_docs)]
    pub iterations: u32,
    #[allow(missing_docs)]
    pub max_memory_kb: u32,
    #[allow(missing_docs)]
    pub parallel_threads: u32,
    #[allow(missing_docs)]
    pub flags: CryptPbkdfFlags,
}

impl TryFrom<cryptsetup_sys::crypt_pbkdf_type> for CryptPbkdfType {
    type Error = LibcryptErr;

    fn try_from(type_: cryptsetup_sys::crypt_pbkdf_type) -> Result<CryptPbkdfType, LibcryptErr> {
        Ok(CryptPbkdfType {
            type_: CryptKdf::from_ptr(type_.type_)?,
            hash: String::from(from_str_ptr!(type_.hash)?),
            time_ms: type_.time_ms,
            iterations: type_.iterations,
            max_memory_kb: type_.max_memory_kb,
            parallel_threads: type_.parallel_threads,
            flags: CryptPbkdfFlags::from(type_.flags),
        })
    }
}

impl<'a> TryFrom<&'a cryptsetup_sys::crypt_pbkdf_type> for CryptPbkdfType {
    type Error = LibcryptErr;

    fn try_from(v: &'a cryptsetup_sys::crypt_pbkdf_type) -> Result<Self, Self::Error> {
        Ok(CryptPbkdfType {
            type_: CryptKdf::from_ptr(v.type_)?,
            hash: from_str_ptr!(v.hash)?.to_string(),
            time_ms: v.time_ms,
            iterations: v.iterations,
            max_memory_kb: v.max_memory_kb,
            parallel_threads: v.parallel_threads,
            flags: CryptPbkdfFlags::from(v.flags),
        })
    }
}

/// A type wrapping a PBKDF type with pointers derived from Rust data types and lifetimes to ensure
/// pointer validity
pub struct CryptPbkdfTypeRef<'a> {
    /// Field containing a `crypt_pbkdf_type` that contains pointers valid for the supplied struct lifetime
    pub inner: crypt_pbkdf_type,
    #[allow(dead_code)]
    phantomdata: &'a PhantomData<()>,
}

impl<'a> CryptPbkdfTypeRef<'a> {
    /// Create a new `CryptPbkdfTypeRef` type
    pub fn new(inner: crypt_pbkdf_type) -> Self {
        CryptPbkdfTypeRef {
            inner,
            phantomdata: &PhantomData,
        }
    }
}

impl<'a> TryInto<CryptPbkdfTypeRef<'a>> for &'a CryptPbkdfType {
    type Error = LibcryptErr;

    fn try_into(self) -> Result<CryptPbkdfTypeRef<'a>, Self::Error> {
        let inner = cryptsetup_sys::crypt_pbkdf_type {
            type_: self.type_.as_ptr(),
            hash: {
                let bytes = self.hash.as_bytes();
                CString::new(bytes).map_err(LibcryptErr::StrError)?.as_ptr()
            },
            time_ms: self.time_ms,
            iterations: self.iterations,
            max_memory_kb: self.max_memory_kb,
            parallel_threads: self.parallel_threads,
            flags: (&self.flags).into(),
        };
        Ok(CryptPbkdfTypeRef {
            inner,
            phantomdata: &PhantomData,
        })
    }
}
