// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{ffi::CString, path::Path, ptr};

use either::Either;
use libc::{c_char, c_int, c_void};

use libcryptsetup_rs_sys::crypt_device;

use crate::{
    activate::CryptActivation, backup::CryptBackup, context::CryptContext, debug::CryptDebug,
    err::LibcryptErr, format::CryptFormat, key::CryptVolumeKey, keyfile::CryptKeyfile,
    keyslot::CryptKeyslot, log::CryptLog, luks2_flags::CryptLuks2Flags,
    luks2_reencrypt::CryptLuks2Reencrypt, luks2_token::CryptLuks2Token, runtime::CryptRuntime,
    settings::CryptSettings, status::CryptDeviceStatus, wipe::CryptWipe,
};

type ConfirmCallback = unsafe extern "C" fn(msg: *const c_char, usrptr: *mut c_void) -> c_int;

/// Initialization handle for devices
pub struct CryptInit;

impl CryptInit {
    /// Initialize by device path
    pub fn init(device_path: &Path) -> Result<CryptDevice, LibcryptErr> {
        let mut cdevice: *mut crypt_device = ptr::null_mut();
        let device_path_cstring = path_to_cstring!(device_path)?;
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_init(
                &mut cdevice as *mut *mut crypt_device,
                device_path_cstring.as_ptr(),
            )
        })?;
        Ok(CryptDevice { ptr: cdevice })
    }

    /// Initialize by device path or a header path and a data device path
    pub fn init_with_data_device(
        device_paths: Either<&Path, (&Path, &Path)>,
    ) -> Result<CryptDevice, LibcryptErr> {
        let mut cdevice: *mut crypt_device = ptr::null_mut();
        let (device_path_cstring, data_device_option) = match device_paths {
            Either::Left(device) => (path_to_cstring!(device)?, None),
            Either::Right((header_device, data_device)) => (
                path_to_cstring!(header_device)?,
                Some(path_to_cstring!(data_device)?),
            ),
        };

        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_init_data_device(
                &mut cdevice as *mut *mut crypt_device,
                device_path_cstring.as_ptr(),
                match data_device_option {
                    Some(ref d) => d.as_ptr(),
                    None => ptr::null(),
                },
            )
        })?;
        Ok(CryptDevice { ptr: cdevice })
    }

    /// Initialize by name and header device path
    pub fn init_by_name_and_header(
        name: &str,
        header_device_path: Option<&Path>,
    ) -> Result<CryptDevice, LibcryptErr> {
        let mut cdevice: *mut crypt_device = ptr::null_mut();
        let name_cstring = to_cstring!(name)?;

        let mut header_device_path_cstring = CString::default();
        if let Some(path) = header_device_path {
            header_device_path_cstring = path_to_cstring!(path)?;
        }

        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_init_by_name_and_header(
                &mut cdevice as *mut *mut crypt_device,
                name_cstring.as_ptr(),
                if header_device_path.is_some() {
                    header_device_path_cstring.as_ptr()
                } else {
                    ptr::null()
                },
            )
        })?;
        Ok(CryptDevice { ptr: cdevice })
    }
}

/// Data type that is a handle for a crypt device
pub struct CryptDevice {
    ptr: *mut crypt_device,
}

impl CryptDevice {
    /// Reconstruct a `CryptDevice` object from a pointer
    pub fn from_ptr(ptr: *mut crypt_device) -> Self {
        CryptDevice { ptr }
    }

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

    /// Get a keyslot option handle
    pub fn keyslot_handle(&mut self) -> CryptKeyslot {
        CryptKeyslot::new(self)
    }

    /// Get a runtime attribute option handle
    pub fn runtime_handle<'a>(&'a mut self, name: &'a str) -> CryptRuntime<'a> {
        CryptRuntime::new(self, name)
    }

    /// Get LUKS2 flags option handle
    pub fn luks2_flag_handle<T>(&mut self) -> CryptLuks2Flags<T> {
        CryptLuks2Flags::new(self)
    }

    /// Get activation option handle
    pub fn activate_handle(&mut self) -> CryptActivation {
        CryptActivation::new(self)
    }

    /// Get volume key option handle
    pub fn volume_key_handle(&mut self) -> CryptVolumeKey {
        CryptVolumeKey::new(self)
    }

    /// Get crypt device status option handle
    pub fn status_handle(&mut self) -> CryptDeviceStatus {
        CryptDeviceStatus::new(self)
    }

    /// Get crypt device backup option handle
    pub fn backup_handle(&mut self) -> CryptBackup {
        CryptBackup::new(self)
    }

    /// Get crypt debug option handle
    pub fn debug_handle() -> CryptDebug {
        CryptDebug
    }

    /// Get crypt device keyfile option handle
    pub fn keyfile_handle(&mut self) -> CryptKeyfile {
        CryptKeyfile::new(self)
    }

    /// Get crypt device wipe option handle
    pub fn wipe_handle(&mut self) -> CryptWipe {
        CryptWipe::new(self)
    }

    /// Get crypt device LUKS2 token option handle
    pub fn token_handle(&mut self) -> CryptLuks2Token {
        CryptLuks2Token::new(self)
    }

    /// Get crypt device reencryption option handle
    pub fn reencrypt_handle(&mut self) -> CryptLuks2Reencrypt {
        CryptLuks2Reencrypt::new(self)
    }

    /// Set the callback that prompts the user to confirm an action
    pub fn set_confirm_callback<T>(
        &mut self,
        confirm: Option<ConfirmCallback>,
        usrdata: Option<&mut T>,
    ) {
        unsafe {
            libcryptsetup_rs_sys::crypt_set_confirm_callback(
                self.ptr,
                confirm,
                match usrdata {
                    Some(ud) => ud as *mut _ as *mut c_void,
                    None => ptr::null_mut(),
                },
            )
        }
    }

    /// Set the device path for a data device
    pub fn set_data_device(&mut self, device_path: &Path) -> Result<(), LibcryptErr> {
        let device_path_cstring = path_to_cstring!(device_path)?;
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_set_data_device(self.ptr, device_path_cstring.as_ptr())
        })
    }

    /// Set the offset in 4096-byte sectors for the data section on a device
    pub fn set_data_offset(&mut self, offset: u64) -> Result<(), LibcryptErr> {
        errno!(unsafe { libcryptsetup_rs_sys::crypt_set_data_offset(self.ptr, offset * 8) })
    }

    pub(crate) fn as_ptr(&mut self) -> *mut crypt_device {
        self.ptr
    }
}

impl Drop for CryptDevice {
    fn drop(&mut self) {
        unsafe { libcryptsetup_rs_sys::crypt_free(self.ptr) }
    }
}
