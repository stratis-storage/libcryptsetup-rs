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
        unsafe { ::std::ffi::CStr::from_ptr($str_ptr) }.to_str().map_err(|e| {
            $crate::err::LibcryptErr::Utf8Error(e)
        })
    };
}

#[macro_export]
macro_rules! c_confirm_callback {
    ( $fn_name:ident, $type:ty, $safe_fn_name:ident ) => {
        extern "C" fn $fn_name(msg: *const std::os::raw::c_char, usrptr: *mut std::os::raw::c_void) -> std::os::raw::c_int {
            let msg_str = from_str_ptr!(msg).expect("Invalid confirm string passed to cryptsetup-rs");
            let generic_ptr = usrptr as *mut $type;
            let generic_ref = unsafe { generic_ptr.as_mut() };

            $safe_fn_name(msg_str, generic_ref) as std::os::raw::c_int
        }
    }
}

#[cfg(test)]
mod test {
    use crate::device::Accepted;

    fn safe_callback(_msg: &str, usrdata: Option<&mut u64>) -> Accepted {
        Accepted::from(*usrdata.unwrap() as i32)
    }

    c_confirm_callback!(callback, u64, safe_callback);

    // To run this test, run `cargo test -- --ignored --nocapture` - it is interactive
    #[test]
    #[ignore]
    fn test_safe_callback() {
        let ret = callback("".as_ptr() as *const std::os::raw::c_char, &mut 1 as *mut _ as *mut std::ffi::c_void);
        assert_eq!(1, ret);
        assert_eq!(Accepted::Yes, Accepted::from(ret));

        let ret = callback("".as_ptr() as *const std::os::raw::c_char, &mut 0 as *mut _ as *mut std::ffi::c_void);
        assert_eq!(0, ret);
        assert_eq!(Accepted::No, Accepted::from(ret));
    }
}
