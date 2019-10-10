use crate::{device::CryptInit, tests::loopback};

pub fn test_init() {
    loopback::use_loopback(8192, true, true, |dev_path, file_path| {
        CryptInit::init(dev_path)?;
        println!("{}", file_path.display());
        Ok(())
    })
    .unwrap();
}
