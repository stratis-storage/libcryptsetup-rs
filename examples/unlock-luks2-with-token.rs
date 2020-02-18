use std::{
    env::args,
    path::{Path, PathBuf},
};

use libcryptsetup_rs::{CryptActivateFlags, CryptInit, LibcryptErr};

fn usage() -> &'static str {
    "Usage: format-luks2-with-token <DEVICE_PATH> <KEY_DESCRIPTION>\n\
    \tDEVICE_PATH: Path to devices to unlock\n\
    \tDEVICE_NAME: Name of activated device"
}

fn parse_args() -> Result<(PathBuf, String), &'static str> {
    let args: Vec<_> = args().collect();
    if args.len() != usage().split('\n').collect::<Vec<_>>().len() {
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
    let mut token_handle = device.token_handle();
    token_handle.activate_by_token::<()>(name, None, None, CryptActivateFlags::empty())?;
    Ok(())
}

fn main() -> Result<(), String> {
    let (device_path, device_name) = parse_args()?;
    activate(&device_path, &device_name).map_err(|e| e.to_string())?;
    Ok(())
}
