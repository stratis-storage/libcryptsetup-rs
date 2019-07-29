#[macro_export]
macro_rules! errno {
    ( $func:expr ) => {
        match $func {
            i if i < 0 => {
                return Err($crate::err::CryptSetupErr::IOError(
                    io::Error::from_raw_os_error(i * -1),
                ))
            }
            i if i > 0 => panic!("Unexpected return value {}", i),
            _ => Result::<(), $crate::err::CryptSetupErr>::Ok(()),
        }
    };
}

#[macro_export]
macro_rules! to_str_ptr {
    ( $str:expr ) => {
        match std::ffi::CString::new($str.as_bytes()) {
            Ok(s) => Ok(s.as_ptr()),
            Err(e) => Err($crate::err::CryptSetupErr::StrError(e)),
        }
    };
}
