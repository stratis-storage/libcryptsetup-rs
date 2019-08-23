use std::{convert::TryFrom, ptr};

use crate::{device::CryptDevice, err::LibcryptErr};

use cryptsetup_sys::*;

type LoggingCallback = unsafe extern "C" fn(
    level: std::os::raw::c_int,
    msg: *const std::os::raw::c_char,
    usrptr: *mut std::ffi::c_void,
);

/// Logging levels
pub enum CryptLogLevel {
    #[allow(missing_docs)]
    Normal = cryptsetup_sys::CRYPT_LOG_NORMAL as isize,
    #[allow(missing_docs)]
    Error = cryptsetup_sys::CRYPT_LOG_ERROR as isize,
    #[allow(missing_docs)]
    Verbose = cryptsetup_sys::CRYPT_LOG_VERBOSE as isize,
    #[allow(missing_docs)]
    Debug = cryptsetup_sys::CRYPT_LOG_DEBUG as isize,
    #[allow(missing_docs)]
    DebugJson = cryptsetup_sys::CRYPT_LOG_DEBUG_JSON as isize,
}

impl TryFrom<std::os::raw::c_int> for CryptLogLevel {
    type Error = LibcryptErr;

    fn try_from(
        v: std::os::raw::c_int,
    ) -> Result<Self, <Self as TryFrom<std::os::raw::c_int>>::Error> {
        let level = match v {
            i if i == CryptLogLevel::Normal as std::os::raw::c_int => CryptLogLevel::Normal,
            i if i == CryptLogLevel::Error as std::os::raw::c_int => CryptLogLevel::Error,
            i if i == CryptLogLevel::Verbose as std::os::raw::c_int => CryptLogLevel::Verbose,
            i if i == CryptLogLevel::Debug as std::os::raw::c_int => CryptLogLevel::Debug,
            i if i == CryptLogLevel::DebugJson as std::os::raw::c_int => CryptLogLevel::DebugJson,
            _ => return Err(LibcryptErr::InvalidConversion),
        };
        Ok(level)
    }
}

/// Handle for logging operations
pub struct CryptLog<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptLog<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptLog { reference }
    }

    /// Generate a log entry
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

    /// Set the callback to be executed on logging events
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
