// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::os::raw::c_int;

use crate::{device::CryptDevice, err::LibcryptErr};

/// Handle for volume key operations
pub struct CryptVolumeKey<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptVolumeKey<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptVolumeKey { reference }
    }

    /// Get volume key from crypt device - first tuple element is key slot, second is volume key
    /// size
    pub fn get(
        &mut self,
        keyslot: c_int,
        volume_key: &mut [u8],
        passphrase: &str,
    ) -> Result<(c_int, crate::size_t), LibcryptErr> {
        let mut volume_key_size_t = volume_key.len();
        let passphrase_cstring = to_cstring!(passphrase)?;
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_volume_key_get(
                self.reference.as_ptr(),
                keyslot,
                to_mut_byte_ptr!(volume_key),
                &mut volume_key_size_t as *mut _,
                passphrase_cstring.as_ptr(),
                passphrase.len(),
            )
        })
        .map(|i| (i, volume_key_size_t))
    }

    /// Verify that volume key is valid for crypt device
    pub fn verify(&mut self, volume_key: &[u8]) -> Result<(), LibcryptErr> {
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_volume_key_verify(
                self.reference.as_ptr(),
                to_byte_ptr!(volume_key),
                volume_key.len(),
            )
        })
    }
}
