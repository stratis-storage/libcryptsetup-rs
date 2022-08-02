// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    os::raw::{c_char, c_int, c_void},
    ptr,
};

use crate::{consts::vals::CryptLogLevel, device::CryptDevice, err::LibcryptErr};

type LoggingCallback = unsafe extern "C" fn(level: c_int, msg: *const c_char, usrptr: *mut c_void);

/// Handle for logging operations
pub struct CryptLogHandle<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptLogHandle<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptLogHandle { reference }
    }

    /// Generate a log entry
    pub fn log(&mut self, level: CryptLogLevel, msg: &str) -> Result<(), LibcryptErr> {
        let msg_cstring = to_cstring!(msg)?;
        mutex!(libcryptsetup_rs_sys::crypt_log(
            self.reference.as_ptr(),
            level as c_int,
            msg_cstring.as_ptr(),
        ));
        Ok(())
    }

    /// Set the callback to be executed on logging events
    pub fn set_log_callback<T>(
        &mut self,
        callback: Option<LoggingCallback>,
        usrdata: Option<&mut T>,
    ) {
        mutex!(libcryptsetup_rs_sys::crypt_set_log_callback(
            self.reference.as_ptr(),
            callback,
            match usrdata {
                Some(ud) => ud as *mut _ as *mut c_void,
                None => ptr::null_mut(),
            },
        ))
    }
}
