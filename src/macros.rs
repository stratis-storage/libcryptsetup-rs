#[macro_export]
macro_rules! errno {
    ( $func:expr ) => {
        match $func {
            i if i < 0 => {
                return Err($crate::err::LibcryptErr::IOError(
                    io::Error::from_raw_os_error(i * -1),
                ))
            }
            i if i > 0 => panic!("Unexpected return value {}", i),
            _ => Result::<(), $crate::err::LibcryptErr>::Ok(()),
        }
    };
}

#[macro_export]
macro_rules! to_str_ptr {
    ( $str:expr ) => {
        match std::ffi::CString::new($str.as_bytes()) {
            Ok(s) => Ok(s.as_ptr()),
            Err(e) => Err($crate::err::LibcryptErr::StrError(e)),
        }
    };
}

#[macro_export]
macro_rules! from_str_ptr {
    ( $str_ptr:expr ) => {
        unsafe { ::std::ffi::CStr::from_ptr($str_ptr) }
            .to_str()
            .map_err(|e| $crate::err::LibcryptErr::Utf8Error(e))
    };
}

#[macro_export]
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
macro_rules! c_logging_callback {
    ( $fn_name:ident, $type:ty, $safe_fn_name:ident ) => {
        extern "C" fn $fn_name(
            level: std::os::raw::c_int,
            msg: *const std::os::raw::c_char,
            usrptr: *mut std::ffi::c_void,
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
    use crate::{Accepted, CryptLogLevel};

    fn safe_confirm_callback(_msg: &str, usrdata: Option<&mut u64>) -> Accepted {
        Accepted::from(*usrdata.unwrap() as i32)
    }

    c_confirm_callback!(confirm_callback, u64, safe_confirm_callback);

    fn safe_logging_callback(_level: CryptLogLevel, _msg: &str, _usrdata: Option<&mut u64>) {}

    c_logging_callback!(logging_callback, u64, safe_logging_callback);

    #[test]
    fn test_c_confirm_callback() {
        let ret = confirm_callback(
            "".as_ptr() as *const std::os::raw::c_char,
            &mut 1 as *mut _ as *mut std::ffi::c_void,
        );
        assert_eq!(1, ret);
        assert_eq!(Accepted::Yes, Accepted::from(ret));

        let ret = confirm_callback(
            "".as_ptr() as *const std::os::raw::c_char,
            &mut 0 as *mut _ as *mut std::ffi::c_void,
        );
        assert_eq!(0, ret);
        assert_eq!(Accepted::No, Accepted::from(ret));
    }

    #[test]
    fn test_c_logging_callback() {
        logging_callback(
            crate::cryptsetup_sys::CRYPT_LOG_ERROR as i32,
            "".as_ptr() as *const std::os::raw::c_char,
            &mut 1 as *mut _ as *mut std::ffi::c_void,
        );

        logging_callback(
            crate::cryptsetup_sys::CRYPT_LOG_DEBUG as i32,
            "".as_ptr() as *const std::os::raw::c_char,
            &mut 0 as *mut _ as *mut std::ffi::c_void,
        );
    }
}
