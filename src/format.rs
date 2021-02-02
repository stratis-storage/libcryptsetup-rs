// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    convert::{TryFrom, TryInto},
    ffi::{CStr, CString},
    os::raw::{c_char, c_uint},
    path::PathBuf,
    ptr, slice,
};

use crate::{
    device::CryptDevice,
    err::LibcryptErr,
    settings::{CryptPbkdfType, CryptPbkdfTypeRef},
};

consts_to_from_enum!(
    /// Verity format flags
    CryptVerityFlag,
    u32,
    NoHeader => libcryptsetup_rs_sys::CRYPT_VERITY_NO_HEADER,
    CheckHash => libcryptsetup_rs_sys::CRYPT_VERITY_CHECK_HASH,
    CreateHash => libcryptsetup_rs_sys::CRYPT_VERITY_CREATE_HASH
);

bitflags_to_from_struct!(
    /// Set of flags for Verity format
    CryptVerityFlags,
    CryptVerityFlag,
    u32
);

struct_ref_to_bitflags!(CryptVerityFlags, CryptVerityFlag, u32);

consts_to_from_enum!(
    /// tcrypt format flags
    CryptTcryptFlag,
    u32,
    LegacyModes => libcryptsetup_rs_sys::CRYPT_TCRYPT_LEGACY_MODES,
    HiddenHeader => libcryptsetup_rs_sys::CRYPT_TCRYPT_HIDDEN_HEADER,
    BackupHeader => libcryptsetup_rs_sys::CRYPT_TCRYPT_BACKUP_HEADER,
    SystemHeader => libcryptsetup_rs_sys::CRYPT_TCRYPT_SYSTEM_HEADER,
    VeraModes => libcryptsetup_rs_sys::CRYPT_TCRYPT_VERA_MODES
);

bitflags_to_from_struct!(
    /// Set of flags for tcrypt format
    CryptTcryptFlags,
    CryptTcryptFlag,
    u32
);

struct_ref_to_bitflags!(CryptTcryptFlags, CryptTcryptFlag, u32);

/// Device formatting type options
#[derive(Debug, PartialEq)]
pub enum EncryptionFormat {
    #[allow(missing_docs)]
    Plain,
    #[allow(missing_docs)]
    Luks1,
    #[allow(missing_docs)]
    Luks2,
    #[allow(missing_docs)]
    Loopaes,
    #[allow(missing_docs)]
    Verity,
    #[allow(missing_docs)]
    Tcrypt,
    #[allow(missing_docs)]
    Integrity,
}

impl EncryptionFormat {
    /// Get `EncryptionFormat` as a char pointer
    pub(crate) fn as_ptr(&self) -> *const c_char {
        match *self {
            EncryptionFormat::Plain => libcryptsetup_rs_sys::CRYPT_PLAIN.as_ptr() as *const c_char,
            EncryptionFormat::Luks1 => libcryptsetup_rs_sys::CRYPT_LUKS1.as_ptr() as *const c_char,
            EncryptionFormat::Luks2 => libcryptsetup_rs_sys::CRYPT_LUKS2.as_ptr() as *const c_char,
            EncryptionFormat::Loopaes => {
                libcryptsetup_rs_sys::CRYPT_LOOPAES.as_ptr() as *const c_char
            }
            EncryptionFormat::Verity => {
                libcryptsetup_rs_sys::CRYPT_VERITY.as_ptr() as *const c_char
            }
            EncryptionFormat::Tcrypt => {
                libcryptsetup_rs_sys::CRYPT_TCRYPT.as_ptr() as *const c_char
            }
            EncryptionFormat::Integrity => {
                libcryptsetup_rs_sys::CRYPT_INTEGRITY.as_ptr() as *const c_char
            }
        }
    }

    /// Get `EncryptionFormat` from a char pointer
    fn from_ptr(p: *const c_char) -> Result<Self, LibcryptErr> {
        let p_bytes = unsafe { CStr::from_ptr(p) }.to_bytes_with_nul();
        if libcryptsetup_rs_sys::CRYPT_PLAIN == p_bytes {
            Ok(EncryptionFormat::Plain)
        } else if libcryptsetup_rs_sys::CRYPT_LUKS1 == p_bytes {
            Ok(EncryptionFormat::Luks1)
        } else if libcryptsetup_rs_sys::CRYPT_LUKS2 == p_bytes {
            Ok(EncryptionFormat::Luks2)
        } else if libcryptsetup_rs_sys::CRYPT_LOOPAES == p_bytes {
            Ok(EncryptionFormat::Loopaes)
        } else if libcryptsetup_rs_sys::CRYPT_VERITY == p_bytes {
            Ok(EncryptionFormat::Verity)
        } else if libcryptsetup_rs_sys::CRYPT_TCRYPT == p_bytes {
            Ok(EncryptionFormat::Tcrypt)
        } else if libcryptsetup_rs_sys::CRYPT_INTEGRITY == p_bytes {
            Ok(EncryptionFormat::Integrity)
        } else {
            Err(LibcryptErr::InvalidConversion)
        }
    }
}

/// A struct with a lifetime representing a reference to `CryptParamsLuks1`.
pub struct CryptParamsLuks1Ref<'a> {
    /// The struct containing data referenced from the corresponding
    /// `CryptParamsLuks1`.
    pub inner: libcryptsetup_rs_sys::crypt_params_luks1,
    #[allow(dead_code)]
    reference: &'a CryptParamsLuks1,
    #[allow(dead_code)]
    hash_cstring: CString,
    #[allow(dead_code)]
    data_device_cstring: Option<CString>,
}

/// A struct representing LUKS1 specific parameters.
pub struct CryptParamsLuks1 {
    #[allow(missing_docs)]
    pub hash: String,
    #[allow(missing_docs)]
    pub data_alignment: usize,
    #[allow(missing_docs)]
    pub data_device: Option<PathBuf>,
}

impl<'a> TryFrom<&'a libcryptsetup_rs_sys::crypt_params_luks1> for CryptParamsLuks1 {
    type Error = LibcryptErr;

    fn try_from(v: &'a libcryptsetup_rs_sys::crypt_params_luks1) -> Result<Self, Self::Error> {
        Ok(CryptParamsLuks1 {
            hash: from_str_ptr_to_owned!(v.hash)?,
            data_alignment: v.data_alignment,
            data_device: match ptr_to_option!(v.data_device) {
                Some(s) => Some(PathBuf::from(from_str_ptr_to_owned!(s)?)),
                None => None,
            },
        })
    }
}

impl<'a> TryInto<CryptParamsLuks1Ref<'a>> for &'a CryptParamsLuks1 {
    type Error = LibcryptErr;

    fn try_into(self) -> Result<CryptParamsLuks1Ref<'a>, Self::Error> {
        let hash_cstring = to_cstring!(self.hash)?;
        let data_device_cstring = match self.data_device {
            Some(ref dd) => Some(path_to_cstring!(dd)?),
            None => None,
        };

        let inner = libcryptsetup_rs_sys::crypt_params_luks1 {
            hash: hash_cstring.as_ptr(),
            data_alignment: self.data_alignment,
            data_device: data_device_cstring
                .as_ref()
                .map(|dd| dd.as_ptr())
                .unwrap_or(ptr::null()),
        };
        Ok(CryptParamsLuks1Ref {
            inner,
            reference: self,
            hash_cstring,
            data_device_cstring,
        })
    }
}

/// A struct representing a reference with a lifetime to a `CryptParamsLuks2`
/// struct
pub struct CryptParamsLuks2Ref<'a> {
    #[allow(missing_docs)]
    pub inner: libcryptsetup_rs_sys::crypt_params_luks2,
    #[allow(dead_code)]
    reference: &'a CryptParamsLuks2,
    #[allow(dead_code)]
    pbkdf_type: Option<CryptPbkdfTypeRef<'a>>,
    #[allow(dead_code)]
    integrity_params: Option<CryptParamsIntegrityRef<'a>>,
    #[allow(dead_code)]
    integrity_cstring_opt: Option<CString>,
    #[allow(dead_code)]
    data_device_cstring: Option<CString>,
    #[allow(dead_code)]
    label_cstring: Option<CString>,
    #[allow(dead_code)]
    subsystem_cstring: Option<CString>,
}

/// LUKS2-specific parameters
pub struct CryptParamsLuks2 {
    #[allow(missing_docs)]
    pub pbkdf: Option<CryptPbkdfType>,
    #[allow(missing_docs)]
    pub integrity: Option<String>,
    #[allow(missing_docs)]
    pub integrity_params: Option<CryptParamsIntegrity>,
    #[allow(missing_docs)]
    pub data_alignment: crate::size_t,
    #[allow(missing_docs)]
    pub data_device: Option<PathBuf>,
    #[allow(missing_docs)]
    pub sector_size: u32,
    #[allow(missing_docs)]
    pub label: Option<String>,
    #[allow(missing_docs)]
    pub subsystem: Option<String>,
}

impl<'a> TryFrom<&'a libcryptsetup_rs_sys::crypt_params_luks2> for CryptParamsLuks2 {
    type Error = LibcryptErr;

    fn try_from(v: &'a libcryptsetup_rs_sys::crypt_params_luks2) -> Result<Self, Self::Error> {
        Ok(CryptParamsLuks2 {
            pbkdf: match ptr_to_option_with_reference!(v.pbkdf) {
                Some(reference) => Some(CryptPbkdfType::try_from(reference)?),
                None => None,
            },
            integrity: match ptr_to_option!(v.integrity) {
                Some(ptr) => Some(from_str_ptr_to_owned!(ptr)?),
                None => None,
            },
            integrity_params: match ptr_to_option_with_reference!(v.integrity_params) {
                Some(ptr) => Some(CryptParamsIntegrity::try_from(ptr)?),
                None => None,
            },
            data_alignment: v.data_alignment,
            data_device: match ptr_to_option!(v.data_device) {
                Some(ptr) => Some(PathBuf::from(from_str_ptr_to_owned!(ptr)?)),
                None => None,
            },
            sector_size: v.sector_size,
            label: match ptr_to_option!(v.label) {
                Some(ptr) => Some(from_str_ptr_to_owned!(ptr)?),
                None => None,
            },
            subsystem: match ptr_to_option!(v.subsystem) {
                Some(ptr) => Some(from_str_ptr_to_owned!(ptr)?),
                None => None,
            },
        })
    }
}

impl<'a> TryInto<CryptParamsLuks2Ref<'a>> for &'a CryptParamsLuks2 {
    type Error = LibcryptErr;

    fn try_into(self) -> Result<CryptParamsLuks2Ref<'a>, Self::Error> {
        let pbkdf_type: Option<CryptPbkdfTypeRef<'a>> = match self.pbkdf {
            Some(ref pbkdf) => Some(pbkdf.try_into()?),
            None => None,
        };
        let integrity_params: Option<CryptParamsIntegrityRef<'a>> = match self.integrity_params {
            Some(ref integrity) => Some(integrity.try_into()?),
            None => None,
        };

        let integrity_cstring_opt = match self.integrity {
            Some(ref intg) => Some(to_cstring!(intg)?),
            None => None,
        };
        let data_device_cstring = match self.data_device {
            Some(ref dd) => Some(path_to_cstring!(dd)?),
            None => None,
        };
        let label_cstring = match self.label {
            Some(ref label) => Some(to_cstring!(label)?),
            None => None,
        };
        let subsystem_cstring = match self.subsystem {
            Some(ref subsystem) => Some(to_cstring!(subsystem)?),
            None => None,
        };

        let inner = libcryptsetup_rs_sys::crypt_params_luks2 {
            pbkdf: pbkdf_type
                .as_ref()
                .map(|pt| &pt.inner as *const _)
                .unwrap_or(ptr::null()),
            integrity: integrity_cstring_opt
                .as_ref()
                .map(|cs| cs.as_ptr())
                .unwrap_or(ptr::null()),
            integrity_params: integrity_params
                .as_ref()
                .map(|ip| &ip.inner as *const _)
                .unwrap_or(ptr::null()),
            data_alignment: self.data_alignment,
            data_device: data_device_cstring
                .as_ref()
                .map(|dd| dd.as_ptr())
                .unwrap_or(ptr::null()),
            sector_size: self.sector_size,
            label: label_cstring
                .as_ref()
                .map(|l| l.as_ptr())
                .unwrap_or(ptr::null()),
            subsystem: subsystem_cstring
                .as_ref()
                .map(|s| s.as_ptr())
                .unwrap_or(ptr::null()),
        };
        Ok(CryptParamsLuks2Ref {
            inner,
            reference: self,
            pbkdf_type,
            integrity_params,
            integrity_cstring_opt,
            data_device_cstring,
            label_cstring,
            subsystem_cstring,
        })
    }
}

/// Reference to parameters specific to Verity
pub struct CryptParamsVerityRef<'a> {
    /// C representation of the struct to use with FFI
    pub inner: libcryptsetup_rs_sys::crypt_params_verity,
    #[allow(dead_code)]
    reference: &'a CryptParamsVerity,
    #[allow(dead_code)]
    hash_name_cstring: CString,
    #[allow(dead_code)]
    data_device_cstring: CString,
    #[allow(dead_code)]
    hash_device_cstring: CString,
    #[allow(dead_code)]
    fec_device_cstring: CString,
}

/// Parameters specific to Verity
pub struct CryptParamsVerity {
    #[allow(missing_docs)]
    pub hash_name: String,
    #[allow(missing_docs)]
    pub data_device: PathBuf,
    #[allow(missing_docs)]
    pub hash_device: PathBuf,
    #[allow(missing_docs)]
    pub fec_device: PathBuf,
    #[allow(missing_docs)]
    pub salt: Vec<u8>,
    #[allow(missing_docs)]
    pub hash_type: u32,
    #[allow(missing_docs)]
    pub data_block_size: u32,
    #[allow(missing_docs)]
    pub hash_block_size: u32,
    #[allow(missing_docs)]
    pub data_size: u64,
    #[allow(missing_docs)]
    pub hash_area_offset: u64,
    #[allow(missing_docs)]
    pub fec_area_offset: u64,
    #[allow(missing_docs)]
    pub fec_roots: u32,
    #[allow(missing_docs)]
    pub flags: CryptVerityFlags,
}

impl<'a> TryFrom<&'a libcryptsetup_rs_sys::crypt_params_verity> for CryptParamsVerity {
    type Error = LibcryptErr;

    fn try_from(v: &'a libcryptsetup_rs_sys::crypt_params_verity) -> Result<Self, Self::Error> {
        Ok(CryptParamsVerity {
            hash_name: from_str_ptr_to_owned!(v.hash_name)?,
            data_device: PathBuf::from(from_str_ptr_to_owned!(v.data_device)?),
            hash_device: PathBuf::from(from_str_ptr_to_owned!(v.hash_device)?),
            fec_device: PathBuf::from(from_str_ptr_to_owned!(v.fec_device)?),
            salt: Vec::from(unsafe {
                std::slice::from_raw_parts(v.salt as *const u8, v.salt_size as usize)
            }),
            hash_type: v.hash_type,
            data_block_size: v.data_block_size,
            hash_block_size: v.hash_block_size,
            data_size: v.data_size,
            hash_area_offset: v.hash_area_offset,
            fec_area_offset: v.fec_area_offset,
            fec_roots: v.fec_roots,
            flags: CryptVerityFlags::try_from(v.flags)?,
        })
    }
}

impl<'a> TryInto<CryptParamsVerityRef<'a>> for &'a CryptParamsVerity {
    type Error = LibcryptErr;

    fn try_into(self) -> Result<CryptParamsVerityRef<'a>, Self::Error> {
        let hash_name_cstring = to_cstring!(self.hash_name)?;
        let data_device_cstring = path_to_cstring!(self.data_device)?;
        let hash_device_cstring = path_to_cstring!(self.hash_device)?;
        let fec_device_cstring = path_to_cstring!(self.fec_device)?;
        Ok(CryptParamsVerityRef {
            inner: libcryptsetup_rs_sys::crypt_params_verity {
                hash_name: hash_name_cstring.as_ptr(),
                data_device: data_device_cstring.as_ptr(),
                hash_device: hash_device_cstring.as_ptr(),
                fec_device: fec_device_cstring.as_ptr(),
                salt: self.salt.as_ptr() as *const libc::c_char,
                salt_size: self.salt.len() as u32,
                hash_type: self.hash_type,
                data_block_size: self.data_block_size,
                hash_block_size: self.hash_block_size,
                data_size: self.data_size,
                hash_area_offset: self.hash_area_offset,
                fec_area_offset: self.fec_area_offset,
                fec_roots: self.fec_roots,
                flags: (&self.flags).into(),
            },
            reference: self,
            hash_name_cstring,
            data_device_cstring,
            hash_device_cstring,
            fec_device_cstring,
        })
    }
}

/// C-compatible reference to a `CryptParamsLoopaes` struct
pub struct CryptParamsLoopaesRef<'a> {
    /// C representation of the struct to use with FFI
    pub inner: libcryptsetup_rs_sys::crypt_params_loopaes,
    #[allow(dead_code)]
    reference: &'a CryptParamsLoopaes,
    #[allow(dead_code)]
    hash_cstring: CString,
}

/// Parameters for formatting a loop AES device
pub struct CryptParamsLoopaes {
    #[allow(missing_docs)]
    pub hash: String,
    #[allow(missing_docs)]
    pub offset: u64,
    #[allow(missing_docs)]
    pub skip: u64,
}

impl<'a> TryFrom<&'a libcryptsetup_rs_sys::crypt_params_loopaes> for CryptParamsLoopaes {
    type Error = LibcryptErr;

    fn try_from(v: &'a libcryptsetup_rs_sys::crypt_params_loopaes) -> Result<Self, Self::Error> {
        Ok(CryptParamsLoopaes {
            hash: from_str_ptr_to_owned!(v.hash)?,
            offset: v.offset,
            skip: v.skip,
        })
    }
}

impl<'a> TryInto<CryptParamsLoopaesRef<'a>> for &'a CryptParamsLoopaes {
    type Error = LibcryptErr;

    fn try_into(self) -> Result<CryptParamsLoopaesRef<'a>, Self::Error> {
        let hash_cstring = to_cstring!(self.hash)?;
        Ok(CryptParamsLoopaesRef {
            inner: libcryptsetup_rs_sys::crypt_params_loopaes {
                hash: hash_cstring.as_ptr(),
                offset: self.offset,
                skip: self.skip,
            },
            reference: self,
            hash_cstring,
        })
    }
}

/// A struct representing a reference with a lifetime to a `CryptParamsIntegrity`
/// struct
pub struct CryptParamsIntegrityRef<'a> {
    #[allow(missing_docs)]
    pub inner: libcryptsetup_rs_sys::crypt_params_integrity,
    #[allow(dead_code)]
    reference: &'a CryptParamsIntegrity,
    #[allow(dead_code)]
    integrity_cstring: CString,
    #[allow(dead_code)]
    journal_integrity_cstring: CString,
    #[allow(dead_code)]
    journal_crypt_cstring: CString,
}

/// Parameters for integrity checking
pub struct CryptParamsIntegrity {
    #[allow(missing_docs)]
    pub journal_size: u64,
    #[allow(missing_docs)]
    pub journal_watermark: c_uint,
    #[allow(missing_docs)]
    pub journal_commit_time: c_uint,
    #[allow(missing_docs)]
    pub interleave_sectors: u32,
    #[allow(missing_docs)]
    pub tag_size: u32,
    #[allow(missing_docs)]
    pub sector_size: u32,
    #[allow(missing_docs)]
    pub buffer_sectors: u32,
    #[allow(missing_docs)]
    pub integrity: String,
    #[allow(missing_docs)]
    pub integrity_key_size: u32,
    #[allow(missing_docs)]
    pub journal_integrity: String,
    #[allow(missing_docs)]
    pub journal_integrity_key: Vec<u8>,
    #[allow(missing_docs)]
    pub journal_crypt: String,
    #[allow(missing_docs)]
    pub journal_crypt_key: Vec<u8>,
}

impl<'a> TryInto<CryptParamsIntegrityRef<'a>> for &'a CryptParamsIntegrity {
    type Error = LibcryptErr;

    fn try_into(self) -> Result<CryptParamsIntegrityRef<'a>, Self::Error> {
        let integrity_cstring = to_cstring!(self.integrity)?;
        let journal_integrity_cstring = to_cstring!(self.journal_integrity)?;
        let journal_crypt_cstring = to_cstring!(self.journal_crypt)?;
        let inner = libcryptsetup_rs_sys::crypt_params_integrity {
            journal_size: self.journal_size,
            journal_watermark: self.journal_watermark,
            journal_commit_time: self.journal_commit_time,
            interleave_sectors: self.interleave_sectors,
            tag_size: self.tag_size,
            sector_size: self.sector_size,
            buffer_sectors: self.buffer_sectors,
            integrity: integrity_cstring.as_ptr(),
            integrity_key_size: self.integrity_key_size,
            journal_integrity: journal_integrity_cstring.as_ptr(),
            journal_integrity_key: to_byte_ptr!(self.journal_integrity_key),
            journal_integrity_key_size: self.journal_integrity_key.len() as u32,
            journal_crypt: journal_crypt_cstring.as_ptr(),
            journal_crypt_key: to_byte_ptr!(self.journal_crypt_key),
            journal_crypt_key_size: self.journal_crypt_key.len() as u32,
        };
        Ok(CryptParamsIntegrityRef {
            inner,
            reference: self,
            integrity_cstring,
            journal_integrity_cstring,
            journal_crypt_cstring,
        })
    }
}

impl<'a> TryFrom<&'a libcryptsetup_rs_sys::crypt_params_integrity> for CryptParamsIntegrity {
    type Error = LibcryptErr;

    fn try_from(v: &'a libcryptsetup_rs_sys::crypt_params_integrity) -> Result<Self, Self::Error> {
        Ok(CryptParamsIntegrity {
            journal_size: v.journal_size,
            journal_watermark: v.journal_watermark,
            journal_commit_time: v.journal_commit_time,
            interleave_sectors: v.interleave_sectors,
            tag_size: v.tag_size,
            sector_size: v.sector_size,
            buffer_sectors: v.buffer_sectors,
            integrity: from_str_ptr_to_owned!(v.integrity)?,
            integrity_key_size: v.integrity_key_size,
            journal_integrity: from_str_ptr_to_owned!(v.journal_integrity)?,
            journal_integrity_key: Vec::from(unsafe {
                std::slice::from_raw_parts(
                    v.journal_integrity_key as *const u8,
                    v.journal_integrity_key_size as usize,
                )
            }),
            journal_crypt: from_str_ptr_to_owned!(v.journal_crypt)?,
            journal_crypt_key: Vec::from(unsafe {
                std::slice::from_raw_parts(
                    v.journal_crypt_key as *const u8,
                    v.journal_crypt_key_size as usize,
                )
            }),
        })
    }
}

/// Represents a reference to a `CryptParamsPlain` struct
pub struct CryptParamsPlainRef<'a> {
    /// C FFI-compatible field
    pub inner: libcryptsetup_rs_sys::crypt_params_plain,
    #[allow(dead_code)]
    reference: &'a CryptParamsPlain,
    #[allow(dead_code)]
    hash_cstring: CString,
}

/// Struct representing plain cryptsetup format parameters
pub struct CryptParamsPlain {
    /// Password hash function
    pub hash: String,
    /// Offset in sectors
    pub offset: u64,
    /// Sector size in bytes
    pub sector_size: u32,
    /// Size of mapped device
    pub size: u64,
    /// IV offset
    pub skip: u64,
}

impl<'a> TryInto<CryptParamsPlainRef<'a>> for &'a CryptParamsPlain {
    type Error = LibcryptErr;

    fn try_into(self) -> Result<CryptParamsPlainRef<'a>, Self::Error> {
        let hash_cstring = to_cstring!(self.hash)?;
        Ok(CryptParamsPlainRef {
            inner: libcryptsetup_rs_sys::crypt_params_plain {
                hash: hash_cstring.as_ptr(),
                offset: self.offset,
                sector_size: self.sector_size,
                size: self.size,
                skip: self.skip,
            },
            reference: self,
            hash_cstring,
        })
    }
}

impl<'a> TryFrom<&'a libcryptsetup_rs_sys::crypt_params_plain> for CryptParamsPlain {
    type Error = LibcryptErr;

    fn try_from(v: &'a libcryptsetup_rs_sys::crypt_params_plain) -> Result<Self, Self::Error> {
        Ok(CryptParamsPlain {
            hash: from_str_ptr_to_owned!(v.hash)?,
            offset: v.offset,
            sector_size: v.sector_size,
            size: v.size,
            skip: v.skip,
        })
    }
}

/// Reference to a `CryptParamsTcrypt` struct
pub struct CryptParamsTcryptRef<'a> {
    /// FFI compatible representation of `CryptParamsTcrypt`
    pub inner: libcryptsetup_rs_sys::crypt_params_tcrypt,
    #[allow(dead_code)]
    reference: &'a CryptParamsTcrypt,
    #[allow(dead_code)]
    keyfiles_cstrings: Vec<CString>,
    #[allow(dead_code)]
    keyfiles_ptrs: Vec<*const libc::c_char>,
    #[allow(dead_code)]
    hash_name_cstring: CString,
    #[allow(dead_code)]
    cipher_cstring: CString,
    #[allow(dead_code)]
    mode_cstring: CString,
}

/// Parameters for tcrypt operations
pub struct CryptParamsTcrypt {
    #[allow(missing_docs)]
    pub passphrase: Option<Vec<u8>>,
    #[allow(missing_docs)]
    pub keyfiles: Option<Vec<PathBuf>>,
    #[allow(missing_docs)]
    pub hash_name: String,
    #[allow(missing_docs)]
    pub cipher: String,
    #[allow(missing_docs)]
    pub mode: String,
    #[allow(missing_docs)]
    pub key_size: usize,
    #[allow(missing_docs)]
    pub flags: CryptTcryptFlags,
    #[allow(missing_docs)]
    pub veracrypt_pim: u32,
}

impl<'a> TryInto<CryptParamsTcryptRef<'a>> for &'a CryptParamsTcrypt {
    type Error = LibcryptErr;

    fn try_into(self) -> Result<CryptParamsTcryptRef<'a>, Self::Error> {
        let mut keyfiles_cstrings = Vec::new();
        if let Some(ref keyfiles) = self.keyfiles {
            for keyfile in keyfiles.iter() {
                keyfiles_cstrings.push(path_to_cstring!(keyfile)?);
            }
        }
        let mut keyfiles_ptrs: Vec<*const libc::c_char> =
            keyfiles_cstrings.iter().map(|cs| cs.as_ptr()).collect();
        let hash_name_cstring = to_cstring!(self.hash_name)?;
        let cipher_cstring = to_cstring!(self.cipher)?;
        let mode_cstring = to_cstring!(self.mode)?;
        Ok(CryptParamsTcryptRef {
            inner: libcryptsetup_rs_sys::crypt_params_tcrypt {
                passphrase: match self.passphrase {
                    Some(ref pass) => pass.as_ptr() as *const libc::c_char,
                    None => std::ptr::null(),
                },
                passphrase_size: match self.passphrase {
                    Some(ref pass) => pass.len(),
                    None => 0,
                },
                keyfiles: keyfiles_ptrs.as_mut_ptr(),
                keyfiles_count: keyfiles_cstrings.len() as u32,
                hash_name: hash_name_cstring.as_ptr(),
                cipher: cipher_cstring.as_ptr(),
                mode: mode_cstring.as_ptr(),
                flags: (&self.flags).into(),
                key_size: self.key_size,
                veracrypt_pim: self.veracrypt_pim,
            },
            reference: self,
            keyfiles_cstrings,
            keyfiles_ptrs,
            hash_name_cstring,
            cipher_cstring,
            mode_cstring,
        })
    }
}

impl<'a> TryFrom<&'a libcryptsetup_rs_sys::crypt_params_tcrypt> for CryptParamsTcrypt {
    type Error = LibcryptErr;

    fn try_from(v: &'a libcryptsetup_rs_sys::crypt_params_tcrypt) -> Result<Self, Self::Error> {
        let mut keyfiles = Vec::new();
        let keyfiles_ptrs = unsafe { slice::from_raw_parts(v.keyfiles, v.keyfiles_count as usize) };
        for keyfile_ptr in keyfiles_ptrs {
            keyfiles.push(PathBuf::from(from_str_ptr_to_owned!(*keyfile_ptr)?));
        }
        Ok(CryptParamsTcrypt {
            passphrase: ptr_to_option!(v.passphrase).map(|p| {
                unsafe { slice::from_raw_parts(p as *const u8, v.passphrase_size) }.to_vec()
            }),
            keyfiles: if keyfiles.is_empty() {
                None
            } else {
                Some(keyfiles)
            },
            hash_name: from_str_ptr_to_owned!(v.hash_name)?,
            cipher: from_str_ptr_to_owned!(v.cipher)?,
            mode: from_str_ptr_to_owned!(v.mode)?,
            flags: CryptTcryptFlags::try_from(v.flags)?,
            key_size: v.key_size,
            veracrypt_pim: v.veracrypt_pim,
        })
    }
}

/// Handle for format operations on a device
pub struct CryptFormat<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptFormat<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptFormat { reference }
    }

    /// Get the formatting type
    pub fn get_type(&mut self) -> Result<EncryptionFormat, LibcryptErr> {
        EncryptionFormat::from_ptr(ptr_to_result!(mutex!(unsafe {
            libcryptsetup_rs_sys::crypt_get_type(self.reference.as_ptr())
        }))?)
    }

    /// Get the default formatting type
    pub fn get_default_type() -> Result<EncryptionFormat, LibcryptErr> {
        EncryptionFormat::from_ptr(ptr_to_result!(mutex!(unsafe {
            libcryptsetup_rs_sys::crypt_get_default_type()
        }))?)
    }
}

#[cfg(test)]
mod test {
    use super::EncryptionFormat;

    #[test]
    fn test_encryption_format_partialeq() {
        #[allow(clippy::eq_op)]
        {
            assert_eq!(EncryptionFormat::Luks1, EncryptionFormat::Luks1);
        }
        assert_ne!(EncryptionFormat::Luks1, EncryptionFormat::Luks2);
    }

    #[test]
    fn test_encryption_format_from_ptr() {
        for format in &[
            EncryptionFormat::Integrity,
            EncryptionFormat::Tcrypt,
            EncryptionFormat::Verity,
            EncryptionFormat::Luks2,
            EncryptionFormat::Loopaes,
            EncryptionFormat::Luks1,
            EncryptionFormat::Plain,
        ] {
            assert_eq!(
                EncryptionFormat::from_ptr(format.as_ptr()).unwrap(),
                *format
            );
        }
    }
}
