use std::os::raw::c_int;

pub enum CryptDebugLevel {
    All = cryptsetup_sys::CRYPT_DEBUG_ALL as isize,
    Json = cryptsetup_sys::CRYPT_DEBUG_JSON as isize,
    None = cryptsetup_sys::CRYPT_DEBUG_NONE as isize,
}

/// Handle for backup operations on a device
pub struct CryptDebug;

impl CryptDebug {
    /// Set library debug level
    pub fn set_debug_level(level: CryptDebugLevel) {
        unsafe { cryptsetup_sys::crypt_set_debug_level(level as c_int) }
    }
}
