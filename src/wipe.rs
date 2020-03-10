// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    os::raw::{c_int, c_void},
    path::Path,
};

use crate::{device::CryptDevice, err::LibcryptErr};

type WipeProgressCallback =
    unsafe extern "C" fn(size: u64, offset: u64, usrptr: *mut c_void) -> c_int;

consts_to_from_enum!(
    /// Pattern for disk wipe
    CryptWipePattern, u32,
    Zero => libcryptsetup_rs_sys::crypt_wipe_pattern_CRYPT_WIPE_ZERO,
    Random => libcryptsetup_rs_sys::crypt_wipe_pattern_CRYPT_WIPE_RANDOM,
    EncryptedZero => libcryptsetup_rs_sys::crypt_wipe_pattern_CRYPT_WIPE_ENCRYPTED_ZERO,
    Special => libcryptsetup_rs_sys::crypt_wipe_pattern_CRYPT_WIPE_SPECIAL
);

/// Handle for volume key operations
pub struct CryptWipe<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptWipe<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptWipe { reference }
    }

    /// Wipe a device with the selected pattern
    #[allow(clippy::too_many_arguments)]
    pub fn wipe<T>(
        &mut self,
        dev_path: &Path,
        pattern: CryptWipePattern,
        offset: u64,
        length: u64,
        wipe_block_size: crate::size_t,
        wipe_no_direct_io: bool,
        callback: Option<WipeProgressCallback>,
        usrptr: Option<&mut T>,
    ) -> Result<(), LibcryptErr> {
        let dev_path_cstring = path_to_cstring!(dev_path)?;
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_wipe(
                self.reference.as_ptr(),
                dev_path_cstring.as_ptr(),
                pattern.into(),
                offset,
                length,
                wipe_block_size,
                if wipe_no_direct_io {
                    libcryptsetup_rs_sys::CRYPT_WIPE_NO_DIRECT_IO
                } else {
                    0
                },
                callback,
                match usrptr {
                    Some(up) => up as *mut _ as *mut c_void,
                    None => std::ptr::null_mut(),
                },
            )
        })
    }
}
