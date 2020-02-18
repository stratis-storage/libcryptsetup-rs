use std::{
    convert::TryFrom,
    env::args,
    path::{Path, PathBuf},
};

use libcryptsetup_rs::{
    c_int, c_uint, CryptInit, CryptVolumeKeyFlags, EncryptionFormat, LibcryptErr,
};

#[macro_use]
extern crate serde_json;
use uuid::Uuid;

fn usage() -> &'static str {
    "Usage: format-luks2-with-token <DEVICE_PATH> <openable|unopenable>\n\
    \tDEVICE_PATH: Path to device to format\n\
    \topenable|unopenable: openable to write the openable LUKS2 token to the keyslot"
}

enum Openable {
    Yes,
    No,
}

impl TryFrom<&String> for Openable {
    type Error = &'static str;

    fn try_from(v: &String) -> Result<Self, &'static str> {
        match v.as_str() {
            "openable" => Ok(Openable::Yes),
            "unopenable" => Ok(Openable::No),
            _ => Err("Unrecognized option for whether device should be openable"),
        }
    }
}

fn parse_args() -> Result<(PathBuf, Openable), &'static str> {
    let args: Vec<_> = args().collect();
    if args.len() != 3 {
        return Err(usage());
    }

    let device_string = args
        .get(1)
        .ok_or("Could not get the device path for the  device node to be encrypted")?;
    let device_path = PathBuf::from(device_string);
    if !device_path.exists() {
        return Err("Device does not exist");
    }

    let openable_string = args
        .get(2)
        .ok_or("Could not determine whether device should be openable or not")?;
    let openable = Openable::try_from(openable_string)?;

    Ok((device_path, openable))
}

fn format(dev: &Path) -> Result<(), LibcryptErr> {
    let mut device = CryptInit::init(dev)?;
    let mut context_handle = device.context_handle();
    context_handle.format::<()>(
        EncryptionFormat::Luks2,
        ("aes", "xts-plain"),
        None,
        libcryptsetup_rs::Either::Right(256 / 8),
        None,
    )?;
    Ok(())
}

fn keyslot_handler(dev: &Path) -> Result<c_int, LibcryptErr> {
    let mut device = CryptInit::init(dev)?;
    let mut keyslot = device.keyslot_handle(None);
    let keyslot_num = keyslot.add_by_key(None, b"changeme", CryptVolumeKeyFlags::empty())?;
    Ok(keyslot_num)
}

fn luks2_token_handler(dev: &Path, keyslot: c_int) -> Result<(), LibcryptErr> {
    let mut device = CryptInit::init(dev)?;
    let mut token = device.token_handle();
    let token_num = token.luks2_keyring_set(None, "test-key")?;
    let _ = token.assign_keyslot(token_num as c_uint, Some(keyslot as c_uint))?;
    Ok(())
}

fn proto_token_handler(dev: &Path) -> Result<(), LibcryptErr> {
    let mut device = CryptInit::init(dev)?;
    let mut token = device.token_handle();
    let _ = token.json_set(
        None,
        &json!({
            "type": "proto",
            "keyslots": [],
            "a_uuid": Uuid::new_v4().to_simple().to_string(),
            "key_description": "test-key"
        }),
    );
    Ok(())
}

fn main() -> Result<(), String> {
    let (path, openable) = parse_args()?;
    format(&path).map_err(|e| e.to_string())?;
    let keyslot = keyslot_handler(&path).map_err(|e| e.to_string())?;
    luks2_token_handler(&path, keyslot).map_err(|e| e.to_string())?;
    if let Openable::Yes = openable {
        proto_token_handler(&path).map_err(|e| e.to_string())?;
    };
    Ok(())
}
