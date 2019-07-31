use std::{convert::TryFrom, io, ptr};

use crate::err::LibcryptErr;

pub use cryptsetup_sys::crypt_set_log_callback;
use cryptsetup_sys::*;

#[derive(Debug, Eq, PartialEq)]
pub enum Accepted {
    No = 0,
    Yes = 1,
}

impl From<std::os::raw::c_int> for Accepted {
    fn from(v: std::os::raw::c_int) -> Self {
        match v {
            i if i == 0 => Accepted::No,
            _ => Accepted::Yes,
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

pub struct CryptLog;

impl CryptLog {
    pub fn log(
        device: &mut CryptDevice,
        level: CryptLogLevel,
        msg: &str,
    ) -> Result<(), LibcryptErr> {
        let msg_ptr = to_str_ptr!(msg)?;
        unsafe { crypt_log(device.as_ptr(), level as std::os::raw::c_int, msg_ptr) };
        Ok(())
    }
}

pub struct CryptInit;

impl CryptInit {
    pub fn init(device_path: &str) -> Result<CryptDevice, LibcryptErr> {
        let mut cdevice: *mut crypt_device = ptr::null_mut();
        let cstr = to_str_ptr!(device_path)?;
        errno!(unsafe { crypt_init(&mut cdevice as *mut *mut crypt_device, cstr) })?;
        Ok(CryptDevice { ptr: cdevice })
    }

    pub fn init_with_data_device(
        device_path: &str,
        data_device_path: &str,
    ) -> Result<CryptDevice, LibcryptErr> {
        let mut cdevice: *mut crypt_device = ptr::null_mut();
        let device_path_cstr = to_str_ptr!(device_path)?;
        let data_device_path_cstr = to_str_ptr!(data_device_path)?;
        errno!(unsafe {
            crypt_init_data_device(
                &mut cdevice as *mut *mut crypt_device,
                device_path_cstr,
                data_device_path_cstr,
            )
        })?;
        Ok(CryptDevice { ptr: cdevice })
    }

    pub fn init_by_name_and_header(
        name: &str,
        header_device_path: &str,
    ) -> Result<CryptDevice, LibcryptErr> {
        let mut cdevice: *mut crypt_device = ptr::null_mut();
        let name_cstr = to_str_ptr!(name)?;
        let header_device_path_cstr = to_str_ptr!(header_device_path)?;
        errno!(unsafe {
            crypt_init_by_name_and_header(
                &mut cdevice as *mut *mut crypt_device,
                name_cstr,
                header_device_path_cstr,
            )
        })?;
        Ok(CryptDevice { ptr: cdevice })
    }

    pub fn init_by_name(name: &str) -> Result<CryptDevice, LibcryptErr> {
        let mut cdevice: *mut crypt_device = ptr::null_mut();
        let name_cstr = to_str_ptr!(name)?;
        errno!(unsafe { crypt_init_by_name(&mut cdevice as *mut *mut crypt_device, name_cstr) })?;
        Ok(CryptDevice { ptr: cdevice })
    }
}

pub struct CryptDevice {
    ptr: *mut crypt_device,
}

type ConfirmCallback = unsafe extern "C" fn(
    msg: *const std::os::raw::c_char,
    usrptr: *mut std::ffi::c_void,
) -> std::os::raw::c_int;

impl CryptDevice {
    pub fn set_confirm_callback<T>(
        &mut self,
        confirm: Option<ConfirmCallback>,
        usrdata: Option<&mut T>,
    ) {
        unsafe {
            crypt_set_confirm_callback(
                self.ptr,
                confirm,
                match usrdata {
                    Some(ud) => ud as *mut _ as *mut std::ffi::c_void,
                    None => ptr::null_mut(),
                },
            )
        }
    }

    pub fn set_data_device(&mut self, device_path: &str) -> Result<(), LibcryptErr> {
        let device_path_cstr = to_str_ptr!(device_path)?;
        errno!(unsafe { crypt_set_data_device(self.ptr, device_path_cstr) })
    }

    pub fn set_data_offset(&mut self, offset: u64) -> Result<(), LibcryptErr> {
        errno!(unsafe { crypt_set_data_offset(self.ptr, offset) })
    }

    fn as_ptr(&mut self) -> *mut crypt_device {
        self.ptr
    }
}

impl Drop for CryptDevice {
    fn drop(&mut self) {
        unsafe { crypt_free(self.ptr) }
    }
}
