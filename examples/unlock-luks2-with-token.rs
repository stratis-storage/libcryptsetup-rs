use std::{
    env::args,
    path::{Path, PathBuf},
};

use keyutils::Keyring;
use libcryptsetup_rs::{CryptActivateFlags, CryptInit, EncryptionFormat, LibcryptErr};

fn usage() -> &'static str {
    "Usage: format-luks2-with-token <DEVICE_PATH> <KEY_DESCRIPTION>\n\
     \tDEVICE_PATH: Path to devices to unlock\n\
     \tDEVICE_NAME: Name of activated device"
}

fn parse_args() -> Result<(PathBuf, String), &'static str> {
    let args: Vec<_> = args().collect();
    if args.len() != usage().split('\n').count() {
        println!("{}", usage());
        return Err("Incorrect arguments provided");
    }

    let device_string = args
        .get(1)
        .ok_or("Could not get the device path for the device node to be encrypted")?;
    let device_path = PathBuf::from(device_string);
    if !device_path.exists() {
        return Err("Device does not exist");
    }

    let device_name = args
        .get(2)
        .ok_or("No device name was provided")?
        .to_string();

    Ok((device_path, device_name))
}

fn activate(devpath: &Path, name: &str) -> Result<(), LibcryptErr> {
    let mut device = CryptInit::init(devpath)?;
    device
        .context_handle()
        .load::<()>(EncryptionFormat::Luks2, None)?;
    device.token_handle().activate_by_token::<()>(
        Some(name),
        None,
        None,
        CryptActivateFlags::empty(),
    )?;
    Ok(())
}

fn main() -> Result<(), String> {
    let (device_path, device_name) = parse_args()?;
    let mut keyring =
        Keyring::attach(keyutils::SpecialKeyring::SessionKeyring).map_err(|e| e.to_string())?;
    keyring.attach_persistent().map_err(|e| e.to_string())?;
    activate(&device_path, &device_name).map_err(|e| e.to_string())?;
    Ok(())
}
