use std::{
    fs::File,
    io::{Read, Write},
};

use crate::{
    activate::CryptDeactivateFlags, device::CryptInit, err::LibcryptErr, format::Format,
    runtime::CryptActivateFlags, tests::loopback, Either,
};

pub fn test_encrypt() {
    loopback::use_loopback(
        1024 * 1024 * 1024,
        super::format_with_zeros(),
        super::do_cleanup(),
        |dev_path, file_path| {
            let keyslot = {
                let mut dev = CryptInit::init(dev_path)?;
                {
                    let mut ctxt = dev.context_handle();
                    ctxt.format::<()>(
                        Format::Luks2,
                        ("aes", "xts-plain"),
                        None,
                        Either::Right(512 / 8),
                        None,
                    )?;
                }
                let mut keyslot = dev.keyslot_handle(None);
                keyslot.add_by_volume_key(None, "adumbpassphrase")?
            };

            {
                let mut dev = CryptInit::init(dev_path)?;
                {
                    let mut context = dev.context_handle();
                    context.load::<()>(Format::Luks2, None)?;
                }
                {
                    let mut activation = dev.activate_handle("test-device");
                    activation.activate_by_passphrase(
                        keyslot,
                        "adumbpassphrase",
                        CryptActivateFlags::empty(),
                    )?;
                }
            }

            std::process::Command::new("/usr/sbin/mkfs.ext4")
                .arg("/dev/mapper/test-device")
                .output()
                .unwrap();

            let mount_path = format!(c_str!("{}-mount"), file_path.display());
            assert_eq!(
                unsafe { libc::mkdir(mount_path.as_ptr() as *const libc::c_char, 0) },
                0
            );
            assert_eq!(
                unsafe {
                    libc::mount(
                        c_str!("/dev/mapper/test-device").as_ptr() as *const libc::c_char,
                        mount_path.as_ptr() as *const libc::c_char,
                        c_str!("ext4").as_ptr() as *const libc::c_char,
                        0,
                        std::ptr::null(),
                    )
                },
                0
            );

            {
                let mut file = File::create(format!("{}-mount/file", file_path.display()))
                    .map_err(LibcryptErr::IOError)?;
                file.write(b"I contain a test string")
                    .map_err(LibcryptErr::IOError)?;
            }

            assert_eq!(
                unsafe { libc::umount(mount_path.as_ptr() as *const libc::c_char) },
                0
            );
            assert_eq!(
                unsafe { libc::rmdir(mount_path.as_ptr() as *const libc::c_char) },
                0
            );

            if super::do_cleanup() {
                let mut dev = CryptInit::init_by_name("test-device")?;
                let mut activation = dev.activate_handle("test-device");
                activation.deactivate(CryptDeactivateFlags::empty())?;
            }

            let file_contents = {
                let mut file = File::open(file_path).map_err(LibcryptErr::IOError)?;
                let mut file_bytes = Vec::new();
                file.read_to_end(&mut file_bytes)
                    .map_err(LibcryptErr::IOError)?;
                let cow = String::from_utf8_lossy(file_bytes.as_slice());
                cow.into_owned()
            };
            assert!(!file_contents.contains("I contain a test string"));

            Ok(())
        },
    )
    .unwrap();

    loopback::use_loopback(
        1024 * 1024 * 1024,
        super::format_with_zeros(),
        super::do_cleanup(),
        |dev_path, file_path| {
            std::process::Command::new("/usr/sbin/mkfs.ext4")
                .arg(dev_path.to_str().unwrap())
                .output()
                .unwrap();

            let mount_path = format!(c_str!("{}-mount"), file_path.display());
            assert_eq!(
                unsafe { libc::mkdir(mount_path.as_ptr() as *const libc::c_char, 0) },
                0
            );
            assert_eq!(
                unsafe {
                    libc::mount(
                        format!(c_str!("{}"), dev_path.display()).as_ptr() as *const libc::c_char,
                        mount_path.as_ptr() as *const libc::c_char,
                        c_str!("ext4").as_ptr() as *const libc::c_char,
                        0,
                        std::ptr::null(),
                    )
                },
                0
            );

            {
                let mut file = File::create(format!("{}-mount/file", file_path.display()))
                    .map_err(LibcryptErr::IOError)?;
                file.write(b"I contain a test string")
                    .map_err(LibcryptErr::IOError)?;
            }

            assert_eq!(
                unsafe { libc::umount(mount_path.as_ptr() as *const libc::c_char) },
                0
            );
            assert_eq!(
                unsafe { libc::rmdir(mount_path.as_ptr() as *const libc::c_char) },
                0
            );

            let file_contents = {
                let mut file = File::open(file_path).map_err(LibcryptErr::IOError)?;
                let mut file_bytes = Vec::new();
                file.read_to_end(&mut file_bytes)
                    .map_err(LibcryptErr::IOError)?;
                let cow = String::from_utf8_lossy(file_bytes.as_slice());
                cow.into_owned()
            };
            assert!(file_contents.contains("I contain a test string"));

            Ok(())
        },
    )
    .unwrap();
}
