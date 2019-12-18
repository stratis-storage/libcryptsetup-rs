use std::{
    env::args,
    io,
    path::{Path, PathBuf},
};

use libcryptsetup_rs::{
    CryptActivateFlags, CryptInit, CryptVolumeKeyFlags, EncryptionFormat, LibcryptErr,
};

enum CryptCommand {
    Encrypt(PathBuf),
    Open(PathBuf, String),
}

fn parse_args() -> Result<CryptCommand, LibcryptErr> {
    let mut args = args();
    let _ = args.next();
    let command = args.next();
    match command.as_ref().map(|s| s.as_str()) {
        Some("encrypt") => {
            let dev = PathBuf::from(match args.next() {
                Some(p) => p,
                None => {
                    return Err(LibcryptErr::Other(
                        "Device path for device to be encrypted is required".to_string(),
                    ))
                }
            });
            if dev.exists() {
                Ok(CryptCommand::Encrypt(dev))
            } else {
                Err(LibcryptErr::IOError(io::Error::from(
                    io::ErrorKind::NotFound,
                )))
            }
        }
        Some("open") => {
            let dev = PathBuf::from(match args.next() {
                Some(p) => p,
                None => {
                    return Err(LibcryptErr::Other(
                        "Device path for device to be encrypted is required".to_string(),
                    ))
                }
            });
            if !dev.exists() {
                return Err(LibcryptErr::IOError(io::Error::from(
                    io::ErrorKind::NotFound,
                )));
            }
            let name = args.next().ok_or_else(|| {
                LibcryptErr::Other("Name for mapped device is required".to_string())
            })?;
            Ok(CryptCommand::Open(dev, name))
        }
        Some(s) => Err(LibcryptErr::Other(format!("Unrecognized command {}", s))),
        None => Err(LibcryptErr::Other("Missing command".to_string())),
    }
}

fn encrypt(path: &Path) -> Result<(), LibcryptErr> {
    let mut device = CryptInit::init(&path)?;
    device.context_handle().format::<()>(
        EncryptionFormat::Luks2,
        ("aes", "xts-plain"),
        None,
        libcryptsetup_rs::Either::Right(256 / 8),
        None,
    )?;
    device
        .keyslot_handle(None)
        .add_by_key(None, b"changeme", CryptVolumeKeyFlags::empty())?;
    Ok(())
}

fn activate(path: &Path, name: &str) -> Result<(), LibcryptErr> {
    let mut device = CryptInit::init(&path)?;
    device
        .context_handle()
        .load::<()>(EncryptionFormat::Luks2, None)?;
    device.activate_handle().activate_by_passphrase(
        Some(name),
        None,
        b"changeme",
        CryptActivateFlags::empty(),
    )?;
    Ok(())
}

fn main() -> Result<(), LibcryptErr> {
    let args = parse_args()?;
    if let CryptCommand::Encrypt(ref path) = args {
        encrypt(path)?;
    } else if let CryptCommand::Open(ref path, ref name) = args {
        activate(path, name)?;
    }
    Ok(())
}
