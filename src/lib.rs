// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#![deny(missing_docs)]

//! This is a wrapper library for libcryptsetup. The intension is to provide as much safety as
//! possible when crossing FFI boundaries to the crypsetup C library.

// Keyfile reading functions are supported through a workaround in these bindings due
// to how memory is handled in these functions - memory for keys is allocated
// and the corresponding free functions are not part of the public API.
// The function is copied and pasted from libcryptsetup and compiled into the bindings
// for now to work around this. This will be supported by libcryptsetup at a later
// time.

pub use either::Either;

#[macro_use]
mod macros;

mod activate;
pub use activate::{
    CryptActivateFlag, CryptActivateFlags, CryptActivation, CryptDeactivateFlag,
    CryptDeactivateFlags,
};

mod backup;
pub use backup::CryptBackup;

mod context;
pub use context::CryptContext;

mod debug;
pub use debug::{CryptDebug, CryptDebugLevel};

mod device;
pub use device::{CryptDevice, CryptInit};

mod err;
pub use err::LibcryptErr;

mod format;
pub use format::{
    CryptFormat, CryptParamsIntegrity, CryptParamsIntegrityRef, CryptParamsLuks2,
    CryptParamsLuks2Ref, CryptParamsVerity, CryptVerityFlag, CryptVerityFlags, EncryptionFormat,
};

mod key;
pub use key::CryptVolumeKey;

mod keyfile;
pub use keyfile::{CryptKeyfile, CryptKeyfileContents, CryptKeyfileFlag, CryptKeyfileFlags};

mod keyslot;
pub use keyslot::{
    CryptKeyslot, CryptVolumeKeyFlag, CryptVolumeKeyFlags, KeyslotInfo, KeyslotPriority,
};

mod log;
pub use log::{CryptLog, CryptLogLevel};

mod luks2_flags;
pub use luks2_flags::{CryptLuks2Flags, CryptRequirementFlag, CryptRequirementFlags};

mod luks2_reencrypt;
pub use luks2_reencrypt::{
    CryptLuks2Reencrypt, CryptParamsReencrypt, CryptParamsReencryptRef,
    CryptReencryptDirectionInfo, CryptReencryptFlag, CryptReencryptFlags, CryptReencryptInfo,
    CryptReencryptModeInfo,
};

mod luks2_token;
pub use luks2_token::{CryptLuks2Token, CryptTokenInfo};

mod mem;
pub use mem::SafeMemHandle;
#[cfg(cryptsetup23supported)]
pub use mem::{SafeBorrowedMemZero, SafeMemzero, SafeOwnedMemZero};

mod runtime;
pub use runtime::{ActiveDevice, CryptRuntime};

mod settings;
pub use settings::{
    CryptKdf, CryptPbkdfFlag, CryptPbkdfFlags, CryptPbkdfType, CryptPbkdfTypeRef, CryptRngFlag,
    CryptSettings, KeyslotsSize, LockState, LuksType, MetadataSize,
};

mod status;
pub use status::{status, CryptDeviceStatus, CryptStatusInfo};

#[cfg(test)]
mod tests;

mod wipe;
pub use wipe::{CryptWipe, CryptWipePattern};

/// Re-exports `libc` types in API
pub use libc::{c_int, c_uint, size_t};

/// Result type to be used with `libcryptsetup-rs`
pub type Result<T> = std::result::Result<T, LibcryptErr>;

/// Boolean specifying yes or no
#[derive(Debug, Eq, PartialEq)]
pub enum Bool {
    /// False
    No = 0,
    /// True
    Yes = 1,
}

impl From<c_int> for Bool {
    fn from(v: c_int) -> Self {
        match v {
            i if i == 0 => Bool::No,
            _ => Bool::Yes,
        }
    }
}

/// Boolean specifying yes or no
#[derive(Debug, Eq, PartialEq)]
pub enum Interrupt {
    /// False
    No = Bool::No as isize,
    /// True
    Yes = Bool::Yes as isize,
}

impl From<c_int> for Interrupt {
    fn from(v: c_int) -> Self {
        match v {
            i if i == 0 => Interrupt::No,
            _ => Interrupt::Yes,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::tests;

    #[ignore]
    #[test]
    fn test_encrypt_by_password() {
        tests::encrypt::test_encrypt_by_password();
    }

    #[ignore]
    #[test]
    fn test_encrypt_by_keyfile() {
        tests::encrypt::test_encrypt_by_keyfile();
    }

    #[ignore]
    #[test]
    fn test_unencrypted() {
        tests::encrypt::test_unecrypted();
    }

    #[ignore]
    #[test]
    fn test_crypt_setup_free_exists() {
        tests::keyfile::test_keyfile_cleanup();
    }
}
