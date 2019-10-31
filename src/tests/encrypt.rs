use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::{
    activate::CryptDeactivateFlags, device::CryptInit, err::LibcryptErr, format::Format,
    runtime::CryptActivateFlags, tests::loopback, Either,
};

fn init_and_activate(
    dev_path: &Path,
    device_name: &'static str,
    passphrase: &'static str,
) -> Result<(), LibcryptErr> {
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
        keyslot.add_by_volume_key(None, passphrase)?
    };

    let mut dev = CryptInit::init(dev_path)?;
    {
        let mut context = dev.context_handle();
        context.load::<()>(Format::Luks2, None)?;
    }
    {
        let mut activation = dev.activate_handle(device_name);
        activation.activate_by_passphrase(keyslot, passphrase, CryptActivateFlags::empty())?;
    }
    Ok(())
}

fn mount(device: &Path, mount_point: &Path) -> Result<(), LibcryptErr> {
    assert!(device.exists());

    std::process::Command::new("/usr/sbin/mkfs.ext4")
        .arg(device)
        .output()
        .map_err(|e| LibcryptErr::Other(e.to_string()))?;

    let mkdir_res = nix::unistd::mkdir(mount_point, nix::sys::stat::Mode::empty())
        .map_err(|e| LibcryptErr::Other(e.to_string()));

    assert!(mount_point.exists() && mount_point.is_dir());

    let data: Option<&str> = None;
    let mount_res = nix::mount::mount(
        Some(device),
        mount_point,
        Some("ext4"),
        nix::mount::MsFlags::empty(),
        data,
    )
    .map_err(|e| LibcryptErr::Other(e.to_string()));

    mkdir_res.and(mount_res)
}

pub fn umount(mount_point: &Path) -> Result<(), LibcryptErr> {
    let umount_res = nix::mount::umount(mount_point).map_err(|e| LibcryptErr::Other(e.to_string()));

    let rmdir_res = std::fs::remove_dir(mount_point).map_err(LibcryptErr::IOError);
    umount_res.and(rmdir_res)
}

fn mount_write_umount(device_path: &Path, mount_path: &Path) -> Result<(), LibcryptErr> {
    let mount_result = mount(device_path, mount_path);

    if mount_result.is_ok() {
        let mut file_path = PathBuf::from(mount_path);
        file_path.push("file");
        let mut file = File::create(file_path).map_err(LibcryptErr::IOError)?;
        file.write(b"I contain a test string")
            .map_err(LibcryptErr::IOError)?;
    }

    let umount_result = if super::do_cleanup() {
        umount(mount_path)
    } else {
        Ok(())
    };
    mount_result.and(umount_result)
}

fn get_file_contents(file_path: &Path) -> Result<String, LibcryptErr> {
    let mut file = File::open(file_path).map_err(LibcryptErr::IOError)?;
    let mut file_bytes = Vec::new();
    file.read_to_end(&mut file_bytes)
        .map_err(LibcryptErr::IOError)?;
    let cow = String::from_utf8_lossy(file_bytes.as_slice());
    Ok(cow.into_owned())
}

pub fn test_encrypt() {
    loopback::use_loopback(
        1024 * 1024 * 1024,
        super::format_with_zeros(),
        super::do_cleanup(),
        |dev_path, file_path| {
            let device_name = "test-device";
            let encrypted_device = PathBuf::from(format!("/dev/mapper/{}", device_name));

            init_and_activate(dev_path, device_name, "abadpassphrase")?;

            let mount_path = PathBuf::from(format!("{}-mount", file_path.display().to_string()));

            let mount_umount_result =
                mount_write_umount(encrypted_device.as_path(), mount_path.as_path());

            if super::do_cleanup() {
                let mut dev = CryptInit::init_by_name_and_header("test-device", None)?;
                let mut activation = dev.activate_handle("test-device");
                activation.deactivate(CryptDeactivateFlags::empty())?;
            }

            let file_contents = get_file_contents(file_path)?;
            assert!(!file_contents.contains("I contain a test string"));

            mount_umount_result
        },
    )
    .expect("Should succeed");

    loopback::use_loopback(
        1024 * 1024 * 1024,
        super::format_with_zeros(),
        super::do_cleanup(),
        |dev_path, file_path| {
            let mount_path = PathBuf::from(format!("{}-mount", file_path.display().to_string()));

            let mount_umount_result = mount_write_umount(dev_path, mount_path.as_path());

            let file_contents = get_file_contents(file_path)?;
            assert!(file_contents.contains("I contain a test string"));

            mount_umount_result
        },
    )
    .unwrap();
}
