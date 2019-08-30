#[macro_export]
/// Convert an errno-zero-success return pattern into a `Result<(), LibcryptErr>`
macro_rules! errno {
    ( $rc:expr ) => {
        match $rc {
            i if i < 0 => {
                return Err($crate::err::LibcryptErr::IOError(
                    std::io::Error::from_raw_os_error(-i),
                ))
            }
            i if i > 0 => panic!("Unexpected return value {}", i),
            _ => Result::<(), $crate::err::LibcryptErr>::Ok(()),
        }
    };
}

#[macro_export]
/// Convert an errno-positive-int-success return pattern into a `Result<std::os::raw::c_int, LibcryptErr>`
macro_rules! errno_int_success {
    ( $rc:expr ) => {
        match $rc {
            i if i < 0 => {
                return Err($crate::err::LibcryptErr::IOError(
                    std::io::Error::from_raw_os_error(-i),
                ))
            }
            i => Result::<_, $crate::err::LibcryptErr>::Ok(i),
        }
    };
}

#[macro_export]
/// Convert an integer return value into specified type
macro_rules! int_to_return {
    ( $rc:expr, $type:ty ) => {
        <$type>::from($rc)
    };
}

#[macro_export]
/// Try converting an integer return value into specified type
macro_rules! try_int_to_return {
    ( $rc:expr, $type:ty ) => {
        <$type>::try_from($rc)
    };
}

#[macro_export]
/// Convert a pointer to an `Option` containing a pointer
macro_rules! ptr_to_option {
    ( $ptr:expr ) => {{
        let p = $ptr;
        if p.is_null() {
            None
        } else {
            Some(p)
        }
    }};
}

#[macro_export]
/// Convert a pointer to an `Result` containing a pointer
macro_rules! ptr_to_result {
    ( $ptr:expr ) => {{
        ptr_to_option!($ptr).ok_or($crate::err::LibcryptErr::NullPtr)
    }};
}

#[macro_export]
/// Convert a pointer to a `Option` containing a reference
macro_rules! ptr_to_option_with_reference {
    ( $ptr:expr ) => {{
        let p = $ptr;
        unsafe { p.as_ref() }
    }};
}

#[macro_export]
/// Convert a pointer to a `Result` containing a reference
macro_rules! ptr_to_result_with_reference {
    ( $ptr:expr ) => {{
        let p = $ptr;
        unsafe { p.as_ref() }.ok_or($crate::err::LibcryptErr::NullPtr)
    }};
}

#[macro_export]
/// Convert a `Path` type into `*const c_char`
macro_rules! path_to_str_ptr {
    ( $path:expr ) => {
        match $path
            .to_str()
            .ok_or_else(|| LibcryptErr::InvalidConversion)
            .and_then(|s| std::ffi::CString::new(s).map_err(LibcryptErr::StrError))
        {
            Ok(s) => Ok(s.as_ptr()),
            Err(e) => Err(e),
        }
    };
}

#[macro_export]
/// Convert a string type into `*const c_char`
macro_rules! to_str_ptr {
    ( $str:expr ) => {
        match std::ffi::CString::new($str.as_bytes()) {
            Ok(s) => Ok(s.as_ptr()),
            Err(e) => Err($crate::err::LibcryptErr::StrError(e)),
        }
    };
}

#[macro_export]
/// Convert a `*const c_char` into a `&str` type
macro_rules! from_str_ptr {
    ( $str_ptr:expr ) => {
        unsafe { ::std::ffi::CStr::from_ptr($str_ptr) }
            .to_str()
            .map_err($crate::err::LibcryptErr::Utf8Error)
    };
}

#[macro_export]
/// Convert a `*const c_char` into a `String` type
macro_rules! from_str_ptr_to_owned {
    ( $str_ptr:expr ) => {
        unsafe { ::std::ffi::CStr::from_ptr($str_ptr) }
            .to_str()
            .map_err($crate::err::LibcryptErr::Utf8Error)
            .map(|s| s.to_string())
    };
}

#[macro_export]
/// Convert bit flags to enum
macro_rules! bitflags_to_enum {
    ( $flags_type:ident, $flag_type:ty, $bitflags_type:ty ) => {
        impl $flags_type {
            /// Create a new set of flags
            pub fn new(vec: Vec<$flag_type>) -> Self {
                $flags_type(vec)
            }
        }

        impl std::convert::TryFrom<$bitflags_type> for $flags_type {
            type Error = LibcryptErr;

            fn try_from(v: $bitflags_type) -> Result<Self, Self::Error> {
                let mut vec = vec![];
                for i in 0..std::mem::size_of::<$bitflags_type>() * 8 {
                    if (v & (1 << i)) == (1 << i) {
                        vec.push(<$flag_type>::try_from(1 << i)?);
                    }
                }
                Ok(<$flags_type>::new(vec))
            }
        }
    };
}

#[macro_export]
/// Create a C-compatible callback to determine user confirmation which wraps safe Rust code
macro_rules! c_confirm_callback {
    ( $fn_name:ident, $type:ty, $safe_fn_name:ident ) => {
        extern "C" fn $fn_name(
            msg: *const std::os::raw::c_char,
            usrptr: *mut std::os::raw::c_void,
        ) -> std::os::raw::c_int {
            let msg_str =
                from_str_ptr!(msg).expect("Invalid message string passed to cryptsetup-rs");
            let generic_ptr = usrptr as *mut $type;
            let generic_ref = unsafe { generic_ptr.as_mut() };

            $safe_fn_name(msg_str, generic_ref) as std::os::raw::c_int
        }
    };
}

#[macro_export]
/// Create a C-compatible logging callback which wraps safe Rust code
macro_rules! c_logging_callback {
    ( $fn_name:ident, $type:ty, $safe_fn_name:ident ) => {
        extern "C" fn $fn_name(
            level: std::os::raw::c_int,
            msg: *const std::os::raw::c_char,
            usrptr: *mut std::os::raw::c_void,
        ) {
            let level =
                <$crate::CryptLogLevel as std::convert::TryFrom<std::os::raw::c_int>>::try_from(
                    level,
                )
                .expect("Invalid logging level passed to cryptsetup-rs");
            let msg_str =
                from_str_ptr!(msg).expect("Invalid message string passed to cryptsetup-rs");
            let generic_ptr = usrptr as *mut $type;
            let generic_ref = unsafe { generic_ptr.as_mut() };

            $safe_fn_name(level, msg_str, generic_ref);
        }
    };
}

#[cfg(test)]
mod test {
    use crate::{log::CryptLogLevel, Bool};

    fn safe_confirm_callback(_msg: &str, usrdata: Option<&mut u64>) -> Bool {
        Bool::from(*usrdata.unwrap() as i32)
    }

    c_confirm_callback!(confirm_callback, u64, safe_confirm_callback);

    fn safe_logging_callback(_level: CryptLogLevel, _msg: &str, _usrdata: Option<&mut u64>) {}

    c_logging_callback!(logging_callback, u64, safe_logging_callback);

    #[test]
    fn test_c_confirm_callback() {
        let ret = confirm_callback(
            "".as_ptr() as *const std::os::raw::c_char,
            &mut 1 as *mut _ as *mut std::os::raw::c_void,
        );
        assert_eq!(1, ret);
        assert_eq!(Bool::Yes, Bool::from(ret));

        let ret = confirm_callback(
            "".as_ptr() as *const std::os::raw::c_char,
            &mut 0 as *mut _ as *mut std::os::raw::c_void,
        );
        assert_eq!(0, ret);
        assert_eq!(Bool::No, Bool::from(ret));
    }

    #[test]
    fn test_c_logging_callback() {
        logging_callback(
            crate::cryptsetup_sys::CRYPT_LOG_ERROR as i32,
            "".as_ptr() as *const std::os::raw::c_char,
            &mut 1 as *mut _ as *mut std::os::raw::c_void,
        );

        logging_callback(
            crate::cryptsetup_sys::CRYPT_LOG_DEBUG as i32,
            "".as_ptr() as *const std::os::raw::c_char,
            &mut 0 as *mut _ as *mut std::os::raw::c_void,
        );
    }
}
