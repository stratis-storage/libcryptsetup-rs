use std::ptr;

use crate::{err::LibcryptErr, log::CryptLog, settings::CryptSettings};

use cryptsetup_sys::*;

type ConfirmCallback = unsafe extern "C" fn(
    msg: *const std::os::raw::c_char,
    usrptr: *mut std::ffi::c_void,
) -> std::os::raw::c_int;

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

impl CryptDevice {
    pub fn logging_handle(&mut self) -> CryptLog {
        CryptLog::new(self)
    }

    pub fn settings_handle(&mut self) -> CryptSettings {
        CryptSettings::new(self)
    }

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

    pub(crate) fn as_ptr(&mut self) -> *mut crypt_device {
        self.ptr
    }
}

impl Drop for CryptDevice {
    fn drop(&mut self) {
        unsafe { crypt_free(self.ptr) }
    }
}
