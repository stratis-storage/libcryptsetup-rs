use std::env::args;

use keyutils::{Keyring, SpecialKeyring};

fn usage() -> &'static str {
    "Usage: add-to-persistent-keyring <KEY_DESCRIPTION> <KEY_DATA>\n\
     \tKEY_DESCRIPTION: Kernel keyring key description\n\
     \tKEY_DATA: Secret data associated with the key description"
}

fn parse_args() -> Result<(String, String), &'static str> {
    let args: Vec<_> = args().collect();
    if args.len() != 3 {
        println!("{}", usage());
        return Err("Incorrect arguments provided");
    }

    let key_desc = args.get(1).ok_or("No key description provided")?;

    let key_data = args.get(2).ok_or("No key data provided")?;

    Ok((key_desc.to_owned(), key_data.to_owned()))
}

fn add_to_persistent_keyring(key_desc: String, key_data: String) -> Result<(), keyutils::Error> {
    let mut session_keyring = Keyring::attach(SpecialKeyring::SessionKeyring)?;
    session_keyring.attach_persistent()?;
    session_keyring.clear()?;
    session_keyring.add_key(&key_desc, key_data.as_bytes())?;
    Ok(())
}

fn main() -> Result<(), String> {
    let (key_desc, key_data) = parse_args()?;
    add_to_persistent_keyring(key_desc, key_data).map_err(|e| e.to_string())?;
    Ok(())
}
