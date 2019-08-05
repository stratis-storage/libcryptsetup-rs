use std::{
    convert::{TryInto, TryFrom},
    ffi::CString,
    marker::PhantomData,
};

use crate::{device::CryptDevice, err::LibcryptErr};

use cryptsetup_sys::*;

pub enum CryptRng {
    Urandom = cryptsetup_sys::CRYPT_RNG_URANDOM as isize,
    Random = cryptsetup_sys::CRYPT_RNG_RANDOM as isize,
}

impl TryFrom<std::os::raw::c_int> for CryptRng {
    type Error = LibcryptErr;

    fn try_from(v: std::os::raw::c_int) -> Result<Self, Self::Error> {
        let rng_type = match v {
            i if i == CryptRng::Urandom as std::os::raw::c_int => CryptRng::Urandom,
            i if i == CryptRng::Random as std::os::raw::c_int => CryptRng::Random,
            _ => return Err(LibcryptErr::InvalidConversion),
        };
        Ok(rng_type)
    }
}

pub enum CryptKdf {
    Pbkdf2,
    Argon2I,
    Argon2Id,
}

impl CryptKdf {
    pub fn as_ptr(&self) -> *const std::os::raw::c_char {
        match *self {
            CryptKdf::Pbkdf2 => cryptsetup_sys::CRYPT_KDF_PBKDF2.as_ptr() as *const std::os::raw::c_char,
            CryptKdf::Argon2I => cryptsetup_sys::CRYPT_KDF_ARGON2I.as_ptr() as *const std::os::raw::c_char,
            CryptKdf::Argon2Id => cryptsetup_sys::CRYPT_KDF_ARGON2ID.as_ptr() as *const std::os::raw::c_char,
        }
    }

    pub fn from_ptr(ptr: *const std::os::raw::c_char) -> Result<Self, LibcryptErr> {
        let ptr_cast = ptr as *const u8;
        if cryptsetup_sys::CRYPT_KDF_PBKDF2 == unsafe {
            std::slice::from_raw_parts(ptr_cast, cryptsetup_sys::CRYPT_KDF_PBKDF2.len())
        } {
            Ok(CryptKdf::Pbkdf2)
        } else if cryptsetup_sys::CRYPT_KDF_ARGON2I == unsafe {
            std::slice::from_raw_parts(ptr_cast, cryptsetup_sys::CRYPT_KDF_ARGON2I.len())
        } {
            Ok(CryptKdf::Argon2I)
        } else if cryptsetup_sys::CRYPT_KDF_ARGON2ID == unsafe {
            std::slice::from_raw_parts(ptr_cast, cryptsetup_sys::CRYPT_KDF_ARGON2ID.len())
        } {
            Ok(CryptKdf::Argon2Id)
        } else {
            Err(LibcryptErr::InvalidConversion)
        }
    }
}

pub struct CryptPbkdfFlags {
    pub iter_time_set: bool,
    pub no_benchmark: bool,
}

impl Default for CryptPbkdfFlags {
    fn default() -> Self {
        CryptPbkdfFlags { iter_time_set: false, no_benchmark: false }
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
        let mut flags =  CryptPbkdfFlags::default();
        if v & cryptsetup_sys::CRYPT_PBKDF_ITER_TIME_SET as u32 != 0 {
            flags.iter_time_set = true;
        }
        if v & cryptsetup_sys::CRYPT_PBKDF_NO_BENCHMARK as u32 != 0 {
            flags.no_benchmark = true;
        }
        flags
    }
}

pub struct CryptPbkdfType<'a> {
    pub type_: CryptKdf,
    pub hash: &'a str,
    pub time_ms: u32,
    pub iterations: u32,
    pub max_memory_kb: u32,
    pub parallel_threads: u32,
    pub flags: CryptPbkdfFlags,
}

pub struct CryptPbkdfTypeRef<'a> {
    pub inner: crypt_pbkdf_type,
    #[allow(dead_code)]
    phantomdata: &'a PhantomData<()>,
}

impl<'a> CryptPbkdfTypeRef<'a> {
    pub fn new(inner: crypt_pbkdf_type) -> Self {
        CryptPbkdfTypeRef {
            inner,
            phantomdata: &PhantomData,
        }
    }
}

impl<'a: 'b, 'b> TryInto<CryptPbkdfTypeRef<'a>> for &'b CryptPbkdfType<'a> {
    type Error = LibcryptErr;

    fn try_into(self) -> Result<CryptPbkdfTypeRef<'a>, Self::Error> {
        let type_ = cryptsetup_sys::crypt_pbkdf_type {
            type_: self.type_.as_ptr(),
            hash: {
                let bytes = self.hash.as_bytes();
                CString::new(bytes).map_err(|e| {
                    LibcryptErr::StrError(e)
                })?.as_ptr()
            },
            time_ms: self.time_ms,
            iterations: self.iterations,
            max_memory_kb: self.max_memory_kb,
            parallel_threads: self.parallel_threads,
            flags: (&self.flags).into(),
        };
        Ok(CryptPbkdfTypeRef::new(type_))
    }
}

impl<'a, 'b: 'a> TryFrom<&'b cryptsetup_sys::crypt_pbkdf_type> for CryptPbkdfType<'a> {
    type Error = LibcryptErr;

    fn try_from(v: &'a cryptsetup_sys::crypt_pbkdf_type) -> Result<Self, Self::Error> {
        Ok(CryptPbkdfType {
            type_: CryptKdf::from_ptr(v.type_)?,
            hash: from_str_ptr!(v.hash)?,
            time_ms: v.time_ms,
            iterations: v.iterations,
            max_memory_kb: v.max_memory_kb,
            parallel_threads: v.parallel_threads,
            flags: CryptPbkdfFlags::from(v.flags),
        })
    }
}

pub struct CryptSettings<'a> { reference: &'a mut CryptDevice }

impl<'a> CryptSettings<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptSettings { reference }
    }

    pub fn set_rng_type(&mut self, rng_type: CryptRng) {
        unsafe { crypt_set_rng_type(self.reference.as_ptr(), rng_type as std::os::raw::c_int) }
    }

    pub fn get_rng_type(&mut self) -> CryptRng {
        CryptRng::try_from(unsafe { crypt_get_rng_type(self.reference.as_ptr()) }).expect("The only allowed values to set should be able to be converted back to CryptRng")
    }

    pub fn set_pbkdf_type<'b>(&mut self, pbkdf_type: &'b CryptPbkdfType) -> Result<(), LibcryptErr> {
        let type_: CryptPbkdfTypeRef<'b> = pbkdf_type.try_into()?;
        errno!(unsafe { crypt_set_pbkdf_type(self.reference.as_ptr(), &type_.inner as *const crypt_pbkdf_type) })
    }
}
