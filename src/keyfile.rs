use std::{
    error::Error,
    path::{Path, PathBuf},
    ptr,
};

use libc::{c_char, c_void};
use libloading::{Library, Symbol};
use pkg_config::Config;

use crate::{device::CryptDevice, err::LibcryptErr};

type CryptSafeFree = unsafe extern "C" fn(data: *mut c_void);

fn get_cryptsetup_lib_path() -> Result<PathBuf, Box<dyn Error>> {
    let lib = Config::new().probe("libcryptsetup")?;
    for mut path in lib.link_paths.into_iter() {
        path.push("libcryptsetup.so");
        if path.exists() {
            return Ok(path);
        }
    }
    Err(Box::new(LibcryptErr::Other(
        "libcryptsetup.so not found".to_string(),
    )))
}

fn get_cryptsetup_lib_handle(lib_path: &Path) -> Result<Library, Box<dyn Error>> {
    Ok(Library::new(lib_path)?)
}

pub struct CryptKeyfileContents<'a> {
    sym: Symbol<'a, CryptSafeFree>,
    key: *mut c_char,
}

impl<'a> CryptKeyfileContents<'a> {
    /// Expose keyfile contents as a pointer
    pub fn as_ptr(&self) -> *const c_char {
        self.key
    }
}

impl<'a> Drop for CryptKeyfileContents<'a> {
    fn drop(&mut self) {
        let sym = &self.sym;
        unsafe { sym(self.key as *mut c_void) };
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
    cryptsetup_library: Option<Library>,
}

impl<'a, 'b: 'a> CryptKeyfile<'a> {
    /// Create a new keyfile operation handle
    pub fn new(reference: &'a mut CryptDevice) -> Self {
        let cryptsetup_library = match get_cryptsetup_lib_path() {
            Ok(p) => match get_cryptsetup_lib_handle(p.as_path()) {
                Ok(l) => Some(l),
                Err(e) => {
                    println!("Failed to load libcryptsetup.so: {}", e);
                    None
                }
            },
            Err(e) => {
                println!("Failed to find libcryptsetup.so: {}", e);
                None
            }
        };
        CryptKeyfile {
            reference,
            cryptsetup_library,
        }
    }

    /// Read keyfile into memory - these bindings will automatically
    /// safely clean it up after `CryptKeyfileContents` is dropped
    pub fn device_read(
        &'b mut self,
        keyfile: &Path,
        keyfile_offset: u64,
        key_size: crate::size_t,
        flags: CryptKeyfileFlags,
    ) -> Result<(CryptKeyfileContents<'b>, crate::size_t), LibcryptErr> {
        let keyfile_cstring = path_to_cstring!(keyfile)?;

        let mut key: *mut c_char = ptr::null_mut();
        let mut size: crate::size_t = 0;
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_keyfile_device_read(
                self.reference.as_ptr(),
                keyfile_cstring.as_ptr(),
                &mut key as *mut *mut c_char,
                &mut size as *mut crate::size_t,
                keyfile_offset,
                key_size,
                flags.into(),
            )
        })?;
        let sym = match self.cryptsetup_library {
            Some(ref l) => unsafe { l.get(b"crypt_safe_free\0") }
                .map_err(|e| LibcryptErr::Other(e.to_string()))?,
            None => {
                return Err(LibcryptErr::Other(
                    "libcryptsetup library handle is not initialized".to_string(),
                ))
            }
        };
        Ok((CryptKeyfileContents { key, sym }, size))
    }
}
