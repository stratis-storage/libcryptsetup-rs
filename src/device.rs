use std::{path::Path, ptr};

use crate::{
    context::CryptContext, err::LibcryptErr, format::CryptFormat, log::CryptLog,
    settings::CryptSettings,
};

use cryptsetup_sys::*;

type ConfirmCallback = unsafe extern "C" fn(
    msg: *const std::os::raw::c_char,
    usrptr: *mut std::ffi::c_void,
) -> std::os::raw::c_int;

/// Initialization handle for devices
pub struct CryptInit;

impl CryptInit {
    /// Initialize by device path
    pub fn init(device_path: &Path) -> Result<CryptDevice, LibcryptErr> {
        let mut cdevice: *mut crypt_device = ptr::null_mut();
        let cstr = path_to_str_ptr!(device_path)?;
        errno!(unsafe { crypt_init(&mut cdevice as *mut *mut crypt_device, cstr) })?;
        Ok(CryptDevice { ptr: cdevice })
    }

    /// Initialize by device path and data device path
    pub fn init_with_data_device(
        device_path: &Path,
        data_device_path: &Path,
    ) -> Result<CryptDevice, LibcryptErr> {
        let mut cdevice: *mut crypt_device = ptr::null_mut();
        let device_path_cstr = path_to_str_ptr!(device_path)?;
        let data_device_path_cstr = path_to_str_ptr!(data_device_path)?;
        errno!(unsafe {
            crypt_init_data_device(
                &mut cdevice as *mut *mut crypt_device,
                device_path_cstr,
                data_device_path_cstr,
            )
        })?;
        Ok(CryptDevice { ptr: cdevice })
    }

    /// Initialize by name and header device path
    pub fn init_by_name_and_header(
        name: &str,
        header_device_path: &Path,
    ) -> Result<CryptDevice, LibcryptErr> {
        let mut cdevice: *mut crypt_device = ptr::null_mut();
        let name_cstr = to_str_ptr!(name)?;
        let header_device_path_cstr = path_to_str_ptr!(header_device_path)?;
        errno!(unsafe {
            crypt_init_by_name_and_header(
                &mut cdevice as *mut *mut crypt_device,
                name_cstr,
                header_device_path_cstr,
            )
        })?;
        Ok(CryptDevice { ptr: cdevice })
    }

    /// Initialize by name
    pub fn init_by_name(name: &str) -> Result<CryptDevice, LibcryptErr> {
        let mut cdevice: *mut crypt_device = ptr::null_mut();
        let name_cstr = to_str_ptr!(name)?;
        errno!(unsafe { crypt_init_by_name(&mut cdevice as *mut *mut crypt_device, name_cstr) })?;
        Ok(CryptDevice { ptr: cdevice })
    }
}

/// Data type that is a handle for a crypt device
pub struct CryptDevice {
    ptr: *mut crypt_device,
}

impl CryptDevice {
    /// Get a logging option handle
    pub fn logging_handle(&mut self) -> CryptLog {
        CryptLog::new(self)
    }

    /// Get a settings option handle
    pub fn settings_handle(&mut self) -> CryptSettings {
        CryptSettings::new(self)
    }

    /// Get a format option handle
    pub fn format_handle(&mut self) -> CryptFormat {
        CryptFormat::new(self)
    }

    /// Get a context option handle
    pub fn context_handle(&mut self) -> CryptContext {
        CryptContext::new(self)
    }

    /// Set the callback that prompts the user to confirm an action
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

    /// Set the device path for a data device
    pub fn set_data_device(&mut self, device_path: &Path) -> Result<(), LibcryptErr> {
        let device_path_cstr = path_to_str_ptr!(device_path)?;
        errno!(unsafe { crypt_set_data_device(self.ptr, device_path_cstr) })
    }

    /// Set the offset for the data section on a device
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
