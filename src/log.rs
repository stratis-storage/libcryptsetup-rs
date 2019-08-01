use std::{convert::TryFrom, ptr};

use crate::{device::CryptDevice, err::LibcryptErr};

pub use cryptsetup_sys::crypt_set_log_callback;
use cryptsetup_sys::*;

type LoggingCallback = unsafe extern "C" fn(
    level: std::os::raw::c_int,
    msg: *const std::os::raw::c_char,
    usrptr: *mut std::ffi::c_void,
);

pub struct CryptLog<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptLog<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptLog { reference }
    }

    pub fn log(&mut self, level: CryptLogLevel, msg: &str) -> Result<(), LibcryptErr> {
        let msg_ptr = to_str_ptr!(msg)?;
        unsafe {
            crypt_log(
                self.reference.as_ptr(),
                level as std::os::raw::c_int,
                msg_ptr,
            )
        };
        Ok(())
    }

    pub fn set_log_callback<T>(
        &mut self,
        callback: Option<LoggingCallback>,
        usrdata: Option<&mut T>,
    ) {
        unsafe {
            crypt_set_log_callback(
                self.reference.as_ptr(),
                callback,
                match usrdata {
                    Some(ud) => ud as *mut _ as *mut std::ffi::c_void,
                    None => ptr::null_mut(),
                },
            )
        }
    }
}

pub enum CryptLogLevel {
    Normal = 0,
    Error = 1,
    Verbose = 2,
    Debug = -1,
    DebugJson = -2,
}

impl TryFrom<std::os::raw::c_int> for CryptLogLevel {
    type Error = LibcryptErr;

    fn try_from(
        v: std::os::raw::c_int,
    ) -> Result<Self, <Self as TryFrom<std::os::raw::c_int>>::Error> {
        let level = match v {
            i if i == cryptsetup_sys::CRYPT_LOG_NORMAL as i32 => CryptLogLevel::Normal,
            i if i == cryptsetup_sys::CRYPT_LOG_ERROR as i32 => CryptLogLevel::Error,
            i if i == cryptsetup_sys::CRYPT_LOG_VERBOSE as i32 => CryptLogLevel::Verbose,
            i if i == cryptsetup_sys::CRYPT_LOG_DEBUG => CryptLogLevel::Debug,
            i if i == cryptsetup_sys::CRYPT_LOG_DEBUG_JSON => CryptLogLevel::DebugJson,
            _ => return Err(LibcryptErr::InvalidConversion),
        };
        Ok(level)
    }
}
