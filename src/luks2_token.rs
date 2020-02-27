// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{convert::TryFrom, ptr};

use crate::{activate::CryptActivateFlags, device::CryptDevice, err::LibcryptErr, Bool};

use libc::{c_char, c_int, c_uint, c_void};

consts_to_from_enum!(
    /// Wrapper enum for `CRYPT_TOKEN_*` values
    CryptTokenInfo,
    u32,
    Invalid => libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_INVALID,
    Inactive => libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_INACTIVE,
    Internal => libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_INTERNAL,
    InternalUnknown => libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_INTERNAL_UNKNOWN,
    External => libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_EXTERNAL,
    ExternalUnknown => libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_EXTERNAL_UNKNOWN
);

/// Handle for LUKS2 token operations
pub struct CryptLuks2Token<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptLuks2Token<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptLuks2Token { reference }
    }

    /// Get contents of a token in JSON format
    pub fn json_get(&mut self, token: c_uint) -> Result<serde_json::Value, LibcryptErr> {
        let mut ptr: *const c_char = std::ptr::null();
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_token_json_get(
                self.reference.as_ptr(),
                token as c_int,
                &mut ptr as *mut _,
            )
        })
        .and_then(|_| from_str_ptr!(ptr))
        .and_then(|s| serde_json::from_str(s).map_err(LibcryptErr::JsonError))
    }

    /// Set contents of a token in JSON format
    pub fn json_set(
        &mut self,
        token: Option<c_uint>,
        json: &serde_json::Value,
    ) -> Result<c_uint, LibcryptErr> {
        let json_cstring =
            to_cstring!(serde_json::to_string(json).map_err(LibcryptErr::JsonError)?)?;
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_token_json_set(
                self.reference.as_ptr(),
                token
                    .map(|t| t as c_int)
                    .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_TOKEN),
                json_cstring.as_ptr(),
            )
        })
        .map(|rc| rc as c_uint)
    }

    /// Get the token info for a specific token
    pub fn status(&mut self, token: c_uint) -> Result<(CryptTokenInfo, String), LibcryptErr> {
        let mut ptr: *const c_char = std::ptr::null();
        try_int_to_return!(
            unsafe {
                libcryptsetup_rs_sys::crypt_token_status(
                    self.reference.as_ptr(),
                    token as c_int,
                    &mut ptr as *mut _,
                )
            },
            CryptTokenInfo
        )
        .and_then(|cti| from_str_ptr_to_owned!(ptr).map(|s| (cti, s)))
    }

    /// Create new LUKS2 keyring token
    pub fn luks2_keyring_set(
        &mut self,
        token: Option<c_uint>,
        key_description: &str,
    ) -> Result<c_uint, LibcryptErr> {
        let description_cstring = to_cstring!(key_description)?;
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_token_luks2_keyring_set(
                self.reference.as_ptr(),
                token
                    .map(|t| t as c_int)
                    .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_TOKEN),
                &libcryptsetup_rs_sys::crypt_token_params_luks2_keyring {
                    key_description: description_cstring.as_ptr(),
                } as *const _,
            )
        })
        .map(|rc| rc as c_uint)
    }

    /// Get LUKS2 keyring token description
    pub fn luks2_keyring_get(&mut self, token: c_uint) -> Result<String, LibcryptErr> {
        let mut params = libcryptsetup_rs_sys::crypt_token_params_luks2_keyring {
            key_description: std::ptr::null(),
        };
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_token_luks2_keyring_get(
                self.reference.as_ptr(),
                token as c_int,
                &mut params as *mut _,
            )
        })
        .and_then(|_| from_str_ptr!(params.key_description).map(|s| s.to_string()))
    }

    /// Assign token to keyslot
    ///
    /// `None` for keyslot assigns all keyslots to the token
    pub fn assign_keyslot(
        &mut self,
        token: c_uint,
        keyslot: Option<c_uint>,
    ) -> Result<(), LibcryptErr> {
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_token_assign_keyslot(
                self.reference.as_ptr(),
                token as c_int,
                keyslot
                    .map(|k| k as c_int)
                    .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_SLOT),
            )
        })
        .map(|_| ())
    }

    /// Unassign token from keyslot
    ///
    /// `None` for keyslot unassigns the token from all active keyslots
    pub fn unassign_keyslot(
        &mut self,
        token: c_uint,
        keyslot: Option<c_uint>,
    ) -> Result<(), LibcryptErr> {
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_token_unassign_keyslot(
                self.reference.as_ptr(),
                token as c_int,
                keyslot
                    .map(|k| k as c_int)
                    .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_SLOT),
            )
        })
        .map(|_| ())
    }

    /// Check if token is assigned
    #[allow(clippy::wrong_self_convention)]
    pub fn is_assigned(&mut self, token: c_uint, keyslot: c_uint) -> Result<Bool, LibcryptErr> {
        let rc = unsafe {
            libcryptsetup_rs_sys::crypt_token_is_assigned(
                self.reference.as_ptr(),
                token as c_int,
                keyslot as c_int,
            )
        };
        if rc == 0 {
            Ok(Bool::Yes)
        } else if rc == libc::ENOENT {
            Ok(Bool::No)
        } else {
            Err(LibcryptErr::IOError(std::io::Error::from_raw_os_error(-rc)))
        }
    }

    /// Register token handler
    pub fn register(
        name: &'static str,
        open: libcryptsetup_rs_sys::crypt_token_open_func,
        buffer_free: libcryptsetup_rs_sys::crypt_token_buffer_free_func,
        validate: libcryptsetup_rs_sys::crypt_token_validate_func,
        dump: libcryptsetup_rs_sys::crypt_token_dump_func,
    ) -> Result<(), LibcryptErr> {
        if name.get(name.len() - 1..) != Some("\0") {
            return Err(LibcryptErr::NoNull(name));
        }
        let handler = libcryptsetup_rs_sys::crypt_token_handler {
            name: name.as_ptr() as *const c_char,
            open,
            buffer_free,
            validate,
            dump,
        };
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_token_register(
                &handler as *const libcryptsetup_rs_sys::crypt_token_handler,
            )
        })
    }

    /// Activate device or check key using a token
    pub fn activate_by_token<T>(
        &mut self,
        name: Option<&str>,
        token: Option<c_uint>,
        usrdata: Option<&mut T>,
        flags: CryptActivateFlags,
    ) -> Result<c_uint, LibcryptErr> {
        let name_cstring_option = match name {
            Some(n) => Some(to_cstring!(n)?),
            None => None,
        };
        let usrdata_ptr = match usrdata {
            Some(reference) => reference as *mut _ as *mut c_void,
            None => ptr::null_mut(),
        };
        errno_int_success!(unsafe {
            libcryptsetup_rs_sys::crypt_activate_by_token(
                self.reference.as_ptr(),
                match name_cstring_option {
                    Some(ref s) => s.as_ptr(),
                    None => std::ptr::null(),
                },
                token
                    .map(|t| t as c_int)
                    .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_TOKEN),
                usrdata_ptr,
                flags.into(),
            )
        })
        .map(|rc| rc as c_uint)
    }
}
