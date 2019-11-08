use std::{path::Path, ptr};

use libc::{c_char, c_void};

use crate::{device::CryptDevice, err::LibcryptErr};

pub struct CryptKeyfileContents {
    key: *mut c_char,
    key_size: crate::size_t,
}

impl CryptKeyfileContents {
    /// Expose keyfile contents as a pointer
    pub fn as_ptr(&self) -> *const c_char {
        self.key
    }
}

impl AsRef<[u8]> for CryptKeyfileContents {
    fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.key as *const u8, self.key_size) }
    }
}

impl Drop for CryptKeyfileContents {
    fn drop(&mut self) {
        unsafe { libcryptsetup_rs_sys::crypt_safe_free(self.as_ptr() as *mut c_void) }
    }
}

consts_to_from_enum!(
    /// Flags for reading keyfiles
    CryptKeyfileFlag,
    u32,
    StopEol => libcryptsetup_rs_sys::CRYPT_KEYFILE_STOP_EOL
);

bitflags_to_from_struct!(
    /// Set of flags for reading keyfiles
    CryptKeyfileFlags,
    CryptKeyfileFlag,
    u32
);

/// Handle for keyfile operations
pub struct CryptKeyfile<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptKeyfile<'a> {
    /// Create a new keyfile operation handle
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptKeyfile { reference }
    }

    /// Read keyfile into memory - these bindings will automatically
    /// safely clean it up after `CryptKeyfileContents` is dropped
    pub fn device_read(
        &mut self,
        keyfile: &Path,
        keyfile_offset: u64,
        key_size: Option<crate::size_t>,
        flags: CryptKeyfileFlags,
    ) -> Result<CryptKeyfileContents, LibcryptErr> {
        let keyfile_cstring = path_to_cstring!(keyfile)?;
        let keyfile_size = match key_size {
            Some(i) => i,
            None => std::fs::metadata(keyfile)
                .map_err(LibcryptErr::IOError)?
                .len() as crate::size_t,
        };

        let mut key: *mut c_char = ptr::null_mut();
        let mut size: crate::size_t = 0;
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_keyfile_device_read(
                self.reference.as_ptr(),
                keyfile_cstring.as_ptr(),
                &mut key as *mut *mut c_char,
                &mut size as *mut crate::size_t,
                keyfile_offset,
                keyfile_size,
                flags.into(),
            )
        })?;
        Ok(CryptKeyfileContents {
            key,
            key_size: size,
        })
    }
}
