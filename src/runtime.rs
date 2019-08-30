use std::convert::TryFrom;

use crate::{device::CryptDevice, err::LibcryptErr};

pub enum CryptActivate {
    Readonly = cryptsetup_sys::CRYPT_ACTIVATE_READONLY as isize,
    NoUuid = cryptsetup_sys::CRYPT_ACTIVATE_NO_UUID as isize,
    Shared = cryptsetup_sys::CRYPT_ACTIVATE_SHARED as isize,
    AllowDiscards = cryptsetup_sys::CRYPT_ACTIVATE_ALLOW_DISCARDS as isize,
    Private = cryptsetup_sys::CRYPT_ACTIVATE_PRIVATE as isize,
    Corrupted = cryptsetup_sys::CRYPT_ACTIVATE_CORRUPTED as isize,
    SameCpuCrypt = cryptsetup_sys::CRYPT_ACTIVATE_SAME_CPU_CRYPT as isize,
    SubmitFromCryptCpus = cryptsetup_sys::CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS as isize,
    IgnoreCorruption = cryptsetup_sys::CRYPT_ACTIVATE_IGNORE_CORRUPTION as isize,
    RestartOnCorruption = cryptsetup_sys::CRYPT_ACTIVATE_RESTART_ON_CORRUPTION as isize,
    IgnoreZeroBlocks = cryptsetup_sys::CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS as isize,
    KeyringKey = cryptsetup_sys::CRYPT_ACTIVATE_KEYRING_KEY as isize,
    NoJournal = cryptsetup_sys::CRYPT_ACTIVATE_NO_JOURNAL as isize,
    Recovery = cryptsetup_sys::CRYPT_ACTIVATE_RECOVERY as isize,
    IgnorePersistent = cryptsetup_sys::CRYPT_ACTIVATE_IGNORE_PERSISTENT as isize,
    CheckAtMostOnce = cryptsetup_sys::CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE as isize,
    AllowUnboundKey = cryptsetup_sys::CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY as isize,
    Recalculate = cryptsetup_sys::CRYPT_ACTIVATE_RECALCULATE as isize,
    Refresh = cryptsetup_sys::CRYPT_ACTIVATE_REFRESH as isize,
    SerializeMemoryHardPbkdf = cryptsetup_sys::CRYPT_ACTIVATE_SERIALIZE_MEMORY_HARD_PBKDF as isize,
    NoJournalBitmap = cryptsetup_sys::CRYPT_ACTIVATE_NO_JOURNAL_BITMAP as isize,
}

impl TryFrom<u32> for CryptActivate {
    type Error = LibcryptErr;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        let crypt_activate = match v {
            i if i == CryptActivate::Readonly as u32 => CryptActivate::Readonly,
            i if i == CryptActivate::NoUuid as u32 => CryptActivate::NoUuid,
            i if i == CryptActivate::Shared as u32 => CryptActivate::Shared,
            i if i == CryptActivate::AllowDiscards as u32 => CryptActivate::AllowDiscards,
            i if i == CryptActivate::Private as u32 => CryptActivate::Private,
            i if i == CryptActivate::Corrupted as u32 => CryptActivate::Corrupted,
            i if i == CryptActivate::SameCpuCrypt as u32 => CryptActivate::SameCpuCrypt,
            i if i == CryptActivate::SubmitFromCryptCpus as u32 => {
                CryptActivate::SubmitFromCryptCpus
            }
            i if i == CryptActivate::IgnoreCorruption as u32 => CryptActivate::IgnoreCorruption,
            i if i == CryptActivate::RestartOnCorruption as u32 => {
                CryptActivate::RestartOnCorruption
            }
            i if i == CryptActivate::IgnoreZeroBlocks as u32 => CryptActivate::IgnoreZeroBlocks,
            i if i == CryptActivate::KeyringKey as u32 => CryptActivate::KeyringKey,
            i if i == CryptActivate::NoJournal as u32 => CryptActivate::NoJournal,
            i if i == CryptActivate::Recovery as u32 => CryptActivate::Recovery,
            i if i == CryptActivate::IgnorePersistent as u32 => CryptActivate::IgnorePersistent,
            i if i == CryptActivate::CheckAtMostOnce as u32 => CryptActivate::CheckAtMostOnce,
            i if i == CryptActivate::AllowUnboundKey as u32 => CryptActivate::AllowUnboundKey,
            i if i == CryptActivate::Recalculate as u32 => CryptActivate::Recalculate,
            i if i == CryptActivate::Refresh as u32 => CryptActivate::Refresh,
            i if i == CryptActivate::SerializeMemoryHardPbkdf as u32 => {
                CryptActivate::SerializeMemoryHardPbkdf
            }
            i if i == CryptActivate::NoJournalBitmap as u32 => CryptActivate::NoJournalBitmap,
            _ => return Err(LibcryptErr::InvalidConversion),
        };
        Ok(crypt_activate)
    }
}

pub struct CryptActivateFlags(Vec<CryptActivate>);

bitflags_to_enum!(CryptActivateFlags, CryptActivate, u32);

impl Into<u32> for CryptActivateFlags {
    fn into(self) -> u32 {
        self.0.into_iter().fold(0, |acc, flag| acc | flag as u32)
    }
}

pub struct ActiveDevice {
    pub offset: u64,
    pub iv_offset: u64,
    pub size: u64,
    pub flags: CryptActivateFlags,
}

impl<'a> TryFrom<&'a cryptsetup_sys::crypt_active_device> for ActiveDevice {
    type Error = LibcryptErr;

    fn try_from(v: &'a cryptsetup_sys::crypt_active_device) -> Result<Self, Self::Error> {
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
        let mut cad = cryptsetup_sys::crypt_active_device {
            offset: 0,
            iv_offset: 0,
            size: 0,
            flags: 0,
        };
        errno!(unsafe {
            cryptsetup_sys::crypt_get_active_device(
                self.reference.as_ptr(),
                to_str_ptr!(self.name)?,
                &mut cad as *mut _,
            )
        })
        .and_then(|_| ActiveDevice::try_from(&cad))
    }

    /// Get detected number of integrity failures
    pub fn get_active_integrity_failures(&mut self) -> Result<u64, LibcryptErr> {
        Ok(unsafe {
            cryptsetup_sys::crypt_get_active_integrity_failures(
                self.reference.as_ptr(),
                to_str_ptr!(self.name)?,
            )
        } as u64)
    }
}
