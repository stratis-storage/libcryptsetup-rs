// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use bitflags::bitflags;

bitflags! {
    /// Crypt device activation flags.
    pub struct CryptActivate: u32 {
        const READONLY = libcryptsetup_rs_sys::CRYPT_ACTIVATE_READONLY;
        const NO_UUID = libcryptsetup_rs_sys::CRYPT_ACTIVATE_NO_UUID;
        const SHARED = libcryptsetup_rs_sys::CRYPT_ACTIVATE_SHARED;
        const ALLOW_DISCARDS = libcryptsetup_rs_sys::CRYPT_ACTIVATE_ALLOW_DISCARDS;
        const PRIVATE = libcryptsetup_rs_sys::CRYPT_ACTIVATE_PRIVATE;
        const CORRUPTED = libcryptsetup_rs_sys::CRYPT_ACTIVATE_CORRUPTED;
        const SAME_CPU_CRYPT = libcryptsetup_rs_sys::CRYPT_ACTIVATE_SAME_CPU_CRYPT;
        const SUBMIT_FROM_CRYPT_CPUS = libcryptsetup_rs_sys::CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS;
        const IGNORE_CORRUPTION = libcryptsetup_rs_sys::CRYPT_ACTIVATE_IGNORE_CORRUPTION;
        const RESTART_ON_CORRUPTION = libcryptsetup_rs_sys::CRYPT_ACTIVATE_RESTART_ON_CORRUPTION;
        const IGNORE_ZERO_BLOCKS = libcryptsetup_rs_sys::CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS;
        const KEYRING_KEY = libcryptsetup_rs_sys::CRYPT_ACTIVATE_KEYRING_KEY;
        const NO_JOURNAL = libcryptsetup_rs_sys::CRYPT_ACTIVATE_NO_JOURNAL;
        const RECOVERY = libcryptsetup_rs_sys::CRYPT_ACTIVATE_RECOVERY;
        const IGNORE_PERSISTENT = libcryptsetup_rs_sys::CRYPT_ACTIVATE_IGNORE_PERSISTENT;
        const CHECK_AT_MOST_ONCE = libcryptsetup_rs_sys::CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE;
        const ALLOW_UNBOUND_KEY = libcryptsetup_rs_sys::CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY;
        const RECALCULATE = libcryptsetup_rs_sys::CRYPT_ACTIVATE_RECALCULATE;
        const REFRESH = libcryptsetup_rs_sys::CRYPT_ACTIVATE_REFRESH;
        const SERIALIZE_MEMORY_HARD_PBKDF = libcryptsetup_rs_sys::CRYPT_ACTIVATE_SERIALIZE_MEMORY_HARD_PBKDF;
        const NO_JOURNAL_BITMAP = libcryptsetup_rs_sys::CRYPT_ACTIVATE_NO_JOURNAL_BITMAP;
        #[cfg(cryptsetup23supported)]
        const SUSPENDED = libcryptsetup_rs_sys::CRYPT_ACTIVATE_SUSPENDED;
        #[cfg(cryptsetup24supported)]
        const IV_LARGE_SECTORS = libcryptsetup_rs_sys::CRYPT_ACTIVATE_IV_LARGE_SECTORS;
        #[cfg(cryptsetup24supported)]
        const PANIC_ON_CORRUPTION = libcryptsetup_rs_sys::CRYPT_ACTIVATE_PANIC_ON_CORRUPTION;
        #[cfg(cryptsetup24supported)]
        const NO_READ_WORKQUEUE = libcryptsetup_rs_sys::CRYPT_ACTIVATE_NO_READ_WORKQUEUE;
        #[cfg(cryptsetup24supported)]
        const NO_WRITE_WORKQUEUE = libcryptsetup_rs_sys::CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE;
        #[cfg(cryptsetup24supported)]
        const RECALCULATE_RESET = libcryptsetup_rs_sys::CRYPT_ACTIVATE_RECALCULATE_RESET;
    }
}

bitflags! {
    /// Flags for crypt deactivate operations
    pub struct CryptDeactivate: u32 {
        const DEFERRED = libcryptsetup_rs_sys::CRYPT_DEACTIVATE_DEFERRED;
        const FORCE = libcryptsetup_rs_sys::CRYPT_DEACTIVATE_FORCE;
    }
}

bitflags! {
    /// Verity format flags
    pub struct CryptVerity: u32 {
        const NO_HEADER = libcryptsetup_rs_sys::CRYPT_VERITY_NO_HEADER;
        const CHECK_HASH = libcryptsetup_rs_sys::CRYPT_VERITY_CHECK_HASH;
        const CREATE_HASH = libcryptsetup_rs_sys::CRYPT_VERITY_CREATE_HASH;
    }
}

bitflags! {
    /// tcrypt format flags
    pub struct CryptTcrypt: u32 {
        const LEGACY_MODES = libcryptsetup_rs_sys::CRYPT_TCRYPT_LEGACY_MODES;
        const HIDDEN_HEADER = libcryptsetup_rs_sys::CRYPT_TCRYPT_HIDDEN_HEADER;
        const BACKUP_HEADER = libcryptsetup_rs_sys::CRYPT_TCRYPT_BACKUP_HEADER;
        const SYSTEM_HEADER = libcryptsetup_rs_sys::CRYPT_TCRYPT_SYSTEM_HEADER;
        const VERA_MODES = libcryptsetup_rs_sys::CRYPT_TCRYPT_VERA_MODES;
    }
}

bitflags! {
    /// Flags for reading keyfiles
    pub struct CryptKeyfile: u32 {
        const STOP_EOL = libcryptsetup_rs_sys::CRYPT_KEYFILE_STOP_EOL;
    }
}

bitflags! {
    /// Flags for tunable options when operating with volume keys
    pub struct CryptVolumeKey: u32 {
        const NO_SEGMENT = libcryptsetup_rs_sys::CRYPT_VOLUME_KEY_NO_SEGMENT;
        const SET = libcryptsetup_rs_sys::CRYPT_VOLUME_KEY_SET;
        const DIGEST_REUSE = libcryptsetup_rs_sys::CRYPT_VOLUME_KEY_DIGEST_REUSE;
    }
}

bitflags! {
    /// Requirement flags
    pub struct CryptRequirement: u32 {
        const OFFLINE_REENCRYPT = libcryptsetup_rs_sys::CRYPT_REQUIREMENT_OFFLINE_REENCRYPT;
        const ONLINE_REENCRYPT = libcryptsetup_rs_sys::CRYPT_REQUIREMENT_ONLINE_REENCRYPT;
        const UNKNOWN = libcryptsetup_rs_sys::CRYPT_REQUIREMENT_UNKNOWN;
    }
}

bitflags! {
    /// Reencryption flags
    pub struct CryptReencrypt: u32 {
        const INITIALIZE_ONLY = libcryptsetup_rs_sys::CRYPT_REENCRYPT_INITIALIZE_ONLY;
        const MOVE_FIRST_SEGMENT = libcryptsetup_rs_sys::CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT;
        const RESUME_ONLY = libcryptsetup_rs_sys::CRYPT_REENCRYPT_RESUME_ONLY;
        const RECOVERY = libcryptsetup_rs_sys::CRYPT_REENCRYPT_RECOVERY;
    }
}

bitflags! {
    /// PBKDF flags
    pub struct CryptPbkdf: u32 {
        const ITER_TIME_SET = libcryptsetup_rs_sys::CRYPT_PBKDF_ITER_TIME_SET;
        const NO_BENCHMARK = libcryptsetup_rs_sys::CRYPT_PBKDF_NO_BENCHMARK;
    }
}

bitflags! {
    /// Flags for crypt wipe operations
    pub struct CryptWipe: u32 {
        const NO_DIRECT_IO = libcryptsetup_rs_sys::CRYPT_WIPE_NO_DIRECT_IO;
    }
}
