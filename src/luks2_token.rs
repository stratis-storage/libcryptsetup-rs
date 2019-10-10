use std::{
    convert::TryFrom,
    os::raw::{c_char, c_int},
};

use crate::{device::CryptDevice, err::LibcryptErr, runtime::CryptActivateFlags, Bool};

consts_to_from_enum!(
    /// Wrapper enum for `CRYPT_TOKEN_*` values
    CryptTokenInfo,
    u32,
    Invalid => cryptsetup_sys::crypt_token_info_CRYPT_TOKEN_INVALID,
    Inactive => cryptsetup_sys::crypt_token_info_CRYPT_TOKEN_INACTIVE,
    Internal => cryptsetup_sys::crypt_token_info_CRYPT_TOKEN_INTERNAL,
    InternalUnknown => cryptsetup_sys::crypt_token_info_CRYPT_TOKEN_INTERNAL_UNKNOWN,
    External => cryptsetup_sys::crypt_token_info_CRYPT_TOKEN_EXTERNAL,
    ExternalUnknown => cryptsetup_sys::crypt_token_info_CRYPT_TOKEN_EXTERNAL_UNKNOWN
);

/// Handle for LUKS2 token operations
pub struct CryptLuks2Token<'a> {
    reference: &'a mut CryptDevice,
    token: c_int,
}

impl<'a> CryptLuks2Token<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice, token: c_int) -> Self {
        CryptLuks2Token { reference, token }
    }

    /// Get contents of a token in JSON format
    pub fn json_get(&mut self) -> Result<serde_json::Value, LibcryptErr> {
        let mut ptr: *const c_char = std::ptr::null();
        errno_int_success!(unsafe {
            cryptsetup_sys::crypt_token_json_get(
                self.reference.as_ptr(),
                self.token,
                &mut ptr as *mut _,
            )
        })
        .and_then(|_| from_str_ptr!(ptr))
        .and_then(|s| serde_json::from_str(s).map_err(LibcryptErr::JsonError))
    }

    /// Set contents of a token in JSON format
    pub fn json_set(
        &mut self,
        json: &serde_json::Value,
        allocate_new: bool,
    ) -> Result<c_int, LibcryptErr> {
        let json_cstring =
            to_cstring!(serde_json::to_string(json).map_err(LibcryptErr::JsonError)?)?;
        errno_int_success!(unsafe {
            cryptsetup_sys::crypt_token_json_set(
                self.reference.as_ptr(),
                if allocate_new {
                    cryptsetup_sys::CRYPT_ANY_TOKEN
                } else {
                    self.token
                },
                json_cstring.as_ptr(),
            )
        })
    }

    /// Get the token info for a specific token
    pub fn status(&mut self) -> Result<(CryptTokenInfo, String), LibcryptErr> {
        let mut ptr: *const c_char = std::ptr::null();
        try_int_to_return!(
            unsafe {
                cryptsetup_sys::crypt_token_status(
                    self.reference.as_ptr(),
                    self.token,
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
        key_description: &str,
        allocate_new: bool,
    ) -> Result<c_int, LibcryptErr> {
        let description_cstring = to_cstring!(key_description)?;
        errno_int_success!(unsafe {
            cryptsetup_sys::crypt_token_luks2_keyring_set(
                self.reference.as_ptr(),
                if allocate_new {
                    cryptsetup_sys::CRYPT_ANY_TOKEN
                } else {
                    self.token
                },
                &cryptsetup_sys::crypt_token_params_luks2_keyring {
                    key_description: description_cstring.as_ptr(),
                } as *const _,
            )
        })
    }

    /// Get LUKS2 keyring token description
    pub fn luks2_keyring_get(&mut self) -> Result<String, LibcryptErr> {
        let mut params = cryptsetup_sys::crypt_token_params_luks2_keyring {
            key_description: std::ptr::null(),
        };
        errno_int_success!(unsafe {
            cryptsetup_sys::crypt_token_luks2_keyring_get(
                self.reference.as_ptr(),
                self.token,
                &mut params as *mut _,
            )
        })
        .and_then(|_| from_str_ptr!(params.key_description).map(|s| s.to_string()))
    }

    /// Assign token to keyslot
    pub fn assign_keyslot(&mut self, keyslot: c_int) -> Result<(), LibcryptErr> {
        errno_int_success!(unsafe {
            cryptsetup_sys::crypt_token_assign_keyslot(self.reference.as_ptr(), self.token, keyslot)
        })
        .map(|_| ())
    }

    /// Unassign token from keyslot
    pub fn unassign_keyslot(&mut self, keyslot: c_int) -> Result<(), LibcryptErr> {
        errno_int_success!(unsafe {
            cryptsetup_sys::crypt_token_unassign_keyslot(
                self.reference.as_ptr(),
                self.token,
                keyslot,
            )
        })
        .map(|_| ())
    }

    /// Check if token is assigned
    #[allow(clippy::wrong_self_convention)]
    pub fn is_assigned(&mut self, keyslot: c_int) -> Result<Bool, LibcryptErr> {
        let rc = unsafe {
            cryptsetup_sys::crypt_token_is_assigned(self.reference.as_ptr(), self.token, keyslot)
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
        open: cryptsetup_sys::crypt_token_open_func,
        buffer_free: cryptsetup_sys::crypt_token_buffer_free_func,
        validate: cryptsetup_sys::crypt_token_validate_func,
        dump: cryptsetup_sys::crypt_token_dump_func,
    ) -> Result<(), LibcryptErr> {
        if name.get(name.len() - 1..) != Some("\0") {
            return Err(LibcryptErr::NoNull(name));
        }
        let handler = cryptsetup_sys::crypt_token_handler {
            name: name.as_ptr() as *const c_char,
            open,
            buffer_free,
            validate,
            dump,
        };
        errno!(unsafe {
            cryptsetup_sys::crypt_token_register(
                &handler as *const cryptsetup_sys::crypt_token_handler,
            )
        })
    }

    /// Activate device or check key using a token
    pub fn activate_by_token<T>(
        &mut self,
        name: &str,
        token: c_int,
        usrdata: &mut T,
        flags: CryptActivateFlags,
    ) -> Result<c_int, LibcryptErr> {
        let name_cstring = to_cstring!(name)?;
        errno_int_success!(unsafe {
            cryptsetup_sys::crypt_activate_by_token(
                self.reference.as_ptr(),
                name_cstring.as_ptr(),
                token,
                usrdata as *mut _ as *mut std::os::raw::c_void,
                flags.into(),
            )
        })
    }
}
