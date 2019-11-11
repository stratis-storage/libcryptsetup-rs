use std::convert::TryFrom;

use crate::{device::CryptDevice, err::LibcryptErr};

consts_to_from_enum!(
    /// Enum wrapping `CRYPT_ACTIVATE_*` flags
    CryptActivateFlag,
    u32,
    Readonly => libcryptsetup_rs_sys::CRYPT_ACTIVATE_READONLY,
    NoUuid => libcryptsetup_rs_sys::CRYPT_ACTIVATE_NO_UUID,
    Shared => libcryptsetup_rs_sys::CRYPT_ACTIVATE_SHARED,
    AllowDiscards => libcryptsetup_rs_sys::CRYPT_ACTIVATE_ALLOW_DISCARDS,
    Private => libcryptsetup_rs_sys::CRYPT_ACTIVATE_PRIVATE,
    Corrupted => libcryptsetup_rs_sys::CRYPT_ACTIVATE_CORRUPTED,
    SameCpuCrypt => libcryptsetup_rs_sys::CRYPT_ACTIVATE_SAME_CPU_CRYPT,
    SubmitFromCryptCpus => libcryptsetup_rs_sys::CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS,
    IgnoreCorruption => libcryptsetup_rs_sys::CRYPT_ACTIVATE_IGNORE_CORRUPTION,
    RestartOnCorruption => libcryptsetup_rs_sys::CRYPT_ACTIVATE_RESTART_ON_CORRUPTION,
    IgnoreZeroBlocks => libcryptsetup_rs_sys::CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS,
    KeyringKey => libcryptsetup_rs_sys::CRYPT_ACTIVATE_KEYRING_KEY,
    NoJournal => libcryptsetup_rs_sys::CRYPT_ACTIVATE_NO_JOURNAL,
    Recovery => libcryptsetup_rs_sys::CRYPT_ACTIVATE_RECOVERY,
    IgnorePersistent => libcryptsetup_rs_sys::CRYPT_ACTIVATE_IGNORE_PERSISTENT,
    CheckAtMostOnce => libcryptsetup_rs_sys::CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE,
    AllowUnboundKey => libcryptsetup_rs_sys::CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY,
    Recalculate => libcryptsetup_rs_sys::CRYPT_ACTIVATE_RECALCULATE,
    Refresh => libcryptsetup_rs_sys::CRYPT_ACTIVATE_REFRESH,
    SerializeMemoryHardPbkdf => libcryptsetup_rs_sys::CRYPT_ACTIVATE_SERIALIZE_MEMORY_HARD_PBKDF,
    NoJournalBitmap => libcryptsetup_rs_sys::CRYPT_ACTIVATE_NO_JOURNAL_BITMAP
);

bitflags_to_from_struct!(
    /// Enum wrapping `CRYPT_ACTIVATE_*` flags
    CryptActivateFlags,
    CryptActivateFlag,
    u32
);

pub struct ActiveDevice {
    pub offset: u64,
    pub iv_offset: u64,
    pub size: u64,
    pub flags: CryptActivateFlags,
}

impl<'a> TryFrom<&'a libcryptsetup_rs_sys::crypt_active_device> for ActiveDevice {
    type Error = LibcryptErr;

    fn try_from(v: &'a libcryptsetup_rs_sys::crypt_active_device) -> Result<Self, Self::Error> {
        Ok(ActiveDevice {
            offset: v.offset,
            iv_offset: v.iv_offset,
            size: v.size,
            flags: CryptActivateFlags::try_from(v.flags)?,
        })
    }
}

/// Handle for runtime attribute options
pub struct CryptRuntime<'a> {
    reference: &'a mut CryptDevice,
    name: &'a str,
}

impl<'a> CryptRuntime<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice, name: &'a str) -> Self {
        CryptRuntime { reference, name }
    }

    /// Get active crypt device attributes
    pub fn get_active_device(&mut self) -> Result<ActiveDevice, LibcryptErr> {
        let mut cad = libcryptsetup_rs_sys::crypt_active_device {
            offset: 0,
            iv_offset: 0,
            size: 0,
            flags: 0,
        };
        let name_cstring = to_cstring!(self.name)?;
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_get_active_device(
                self.reference.as_ptr(),
                name_cstring.as_ptr(),
                &mut cad as *mut _,
            )
        })
        .and_then(|_| ActiveDevice::try_from(&cad))
    }

    /// Get detected number of integrity failures
    pub fn get_active_integrity_failures(&mut self) -> Result<u64, LibcryptErr> {
        let name_cstring = to_cstring!(self.name)?;
        Ok(unsafe {
            libcryptsetup_rs_sys::crypt_get_active_integrity_failures(
                self.reference.as_ptr(),
                name_cstring.as_ptr(),
            )
        } as u64)
    }
}
