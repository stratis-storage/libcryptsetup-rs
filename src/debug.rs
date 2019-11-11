use std::os::raw::c_int;

pub enum CryptDebugLevel {
    All = libcryptsetup_rs_sys::CRYPT_DEBUG_ALL as isize,
    Json = libcryptsetup_rs_sys::CRYPT_DEBUG_JSON as isize,
    None = libcryptsetup_rs_sys::CRYPT_DEBUG_NONE as isize,
}

/// Handle for backup operations on a device
pub struct CryptDebug;

impl CryptDebug {
    /// Set library debug level
    pub fn set_debug_level(level: CryptDebugLevel) {
        unsafe { libcryptsetup_rs_sys::crypt_set_debug_level(level as c_int) }
    }
}
