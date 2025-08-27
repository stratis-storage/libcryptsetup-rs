// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::{
    consts::{
        flags::{CryptActivate, CryptDeactivate, CryptReencrypt, CryptVolumeKey},
        vals::{CryptReencryptDirectionInfo, CryptReencryptModeInfo, EncryptionFormat},
    },
    device::CryptInit,
    get_sector_size,
    tests::loopback,
    CryptParamsLuks2, CryptParamsReencrypt, Either,
};

pub fn test_reencrypt_by_password() {
    loopback::use_loopback(
        50 * 1024 * 1024,
        super::format_with_zeros(),
        super::do_cleanup(),
        |dev_path, _file_path| {
            let mut dev = CryptInit::init(dev_path).unwrap();
            dev.context_handle()
                .format::<()>(
                    EncryptionFormat::Luks2,
                    ("aes", "xts-plain"),
                    None,
                    Either::Right(512 / 8),
                    None,
                )
                .unwrap();

            dev.keyslot_handle()
                .add_by_key(
                    None,
                    None,
                    "thisisatest".as_bytes(),
                    CryptVolumeKey::empty(),
                )
                .unwrap();

            let new_keyslot = dev
                .keyslot_handle()
                .add_by_key(
                    None,
                    Some(Either::Right(512 / 8)),
                    "thisisatest".as_bytes(),
                    CryptVolumeKey::NO_SEGMENT,
                )
                .unwrap();

            dev.activate_handle()
                .activate_by_passphrase(
                    Some("test-device"),
                    None,
                    "thisisatest".as_bytes(),
                    CryptActivate::empty(),
                )
                .unwrap();

            let size = match get_sector_size(Some(&mut dev)) {
                i if i < 0 => panic!("Received error: {i:?}"),
                i => i as u32,
            };
            let cipher = dev.status_handle().get_cipher().unwrap();
            let cipher_mode = dev.status_handle().get_cipher_mode().unwrap();

            dev.reencrypt_handle()
                .reencrypt_init_by_passphrase(
                    Some("test-device"),
                    "thisisatest".as_bytes(),
                    None,
                    Some(new_keyslot),
                    Some((&cipher, &cipher_mode)),
                    CryptParamsReencrypt {
                        mode: CryptReencryptModeInfo::Reencrypt,
                        direction: CryptReencryptDirectionInfo::Forward,
                        resilience: "checksum".to_string(),
                        hash: "sha256".to_string(),
                        data_shift: 0,
                        max_hotzone_size: 0,
                        device_size: 0,
                        luks2: Some(CryptParamsLuks2 {
                            data_alignment: 0,
                            data_device: None,
                            integrity: None,
                            integrity_params: None,
                            pbkdf: None,
                            label: None,
                            sector_size: size,
                            subsystem: None,
                        }),
                        flags: CryptReencrypt::empty(),
                    },
                )
                .unwrap();

            dev.reencrypt_handle().reencrypt2::<()>(None, None).unwrap();

            dev.activate_handle()
                .deactivate("test-device", CryptDeactivate::empty())
                .unwrap();
        },
    )
}
