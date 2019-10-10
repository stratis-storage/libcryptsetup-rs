use std::{
    os::raw::{c_int, c_void},
    path::Path,
};

use crate::{device::CryptDevice, err::LibcryptErr};

type WipeProgressCallback =
    unsafe extern "C" fn(size: u64, offset: u64, usrptr: *mut c_void) -> c_int;

pub enum CryptWipePattern {
    Zero = cryptsetup_sys::crypt_wipe_pattern_CRYPT_WIPE_ZERO as isize,
    Random = cryptsetup_sys::crypt_wipe_pattern_CRYPT_WIPE_RANDOM as isize,
    EncryptedZero = cryptsetup_sys::crypt_wipe_pattern_CRYPT_WIPE_ENCRYPTED_ZERO as isize,
    Special = cryptsetup_sys::crypt_wipe_pattern_CRYPT_WIPE_SPECIAL as isize,
}

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
        wipe_block_size: crate::SizeT,
        wipe_no_direct_io: bool,
        callback: Option<WipeProgressCallback>,
        usrptr: &mut T,
    ) -> Result<(), LibcryptErr> {
        let dev_path_cstring = path_to_cstring!(dev_path)?;
        errno!(unsafe {
            cryptsetup_sys::crypt_wipe(
                self.reference.as_ptr(),
                dev_path_cstring.as_ptr(),
                pattern as u32,
                offset,
                length,
                wipe_block_size,
                if wipe_no_direct_io {
                    cryptsetup_sys::CRYPT_WIPE_NO_DIRECT_IO
                } else {
                    0
                },
                callback,
                usrptr as *mut _ as *mut c_void,
            )
        })
    }
}
