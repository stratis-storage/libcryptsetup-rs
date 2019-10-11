use std::{
    convert::{TryFrom, TryInto},
    ffi::{CStr, CString},
    os::raw::{c_char, c_uint},
    path::PathBuf,
    ptr,
};

use crate::{
    device::CryptDevice,
    err::LibcryptErr,
    settings::{CryptPbkdfType, CryptPbkdfTypeRef},
};

use cryptsetup_sys::*;

consts_to_from_enum!(
    /// Verity format flags
    CryptVerityFlag,
    u32,
    NoHeader => cryptsetup_sys::CRYPT_VERITY_NO_HEADER,
    CheckHash => cryptsetup_sys::CRYPT_VERITY_CHECK_HASH,
    CreateHash => cryptsetup_sys::CRYPT_VERITY_CREATE_HASH
);

bitflags_to_from_struct!(
    /// Set of flags for Verity format
    CryptVerityFlags,
    CryptVerityFlag,
    u32
);

/// Device formatting type options
pub enum Format {
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

pub struct CryptParamsLuks2Ref<'a> {
    pub inner: cryptsetup_sys::crypt_params_luks2,
    #[allow(dead_code)]
    reference: &'a CryptParamsLuks2,
    #[allow(dead_code)]
    pbkdf_type: CryptPbkdfTypeRef<'a>,
    #[allow(dead_code)]
    integrity_params: CryptParamsIntegrityRef<'a>,
    #[allow(dead_code)]
    integrity_cstring_opt: Option<CString>,
    #[allow(dead_code)]
    data_device_cstring: CString,
    #[allow(dead_code)]
    label_cstring: CString,
    #[allow(dead_code)]
    subsystem_cstring: CString,
}

pub struct CryptParamsLuks2 {
    pub pbkdf: CryptPbkdfType,
    pub integrity: Option<String>,
    pub integrity_params: CryptParamsIntegrity,
    pub data_alignment: crate::size_t,
    pub data_device: PathBuf,
    pub sector_size: u32,
    pub label: String,
    pub subsystem: String,
}

impl<'a> TryInto<CryptParamsLuks2Ref<'a>> for &'a CryptParamsLuks2 {
    type Error = LibcryptErr;

    fn try_into(self) -> Result<CryptParamsLuks2Ref<'a>, Self::Error> {
        let pbkdf_type: CryptPbkdfTypeRef<'a> = (&self.pbkdf).try_into()?;
        let integrity_params: CryptParamsIntegrityRef<'a> = (&self.integrity_params).try_into()?;

        let integrity_cstring_opt = match self.integrity {
            Some(ref intg) => Some(to_cstring!(intg)?),
            None => None,
        };
        let data_device_cstring = path_to_cstring!(self.data_device.as_path())?;
        let label_cstring = to_cstring!(self.label)?;
        let subsystem_cstring = to_cstring!(self.subsystem)?;

        let inner = cryptsetup_sys::crypt_params_luks2 {
            pbkdf: &pbkdf_type.inner as *const _,
            integrity: integrity_cstring_opt
                .as_ref()
                .map(|cs| cs.as_ptr())
                .unwrap_or(ptr::null()),
            integrity_params: &integrity_params.inner as *const _,
            data_alignment: self.data_alignment,
            data_device: data_device_cstring.as_ptr(),
            sector_size: self.sector_size,
            label: label_cstring.as_ptr(),
            subsystem: subsystem_cstring.as_ptr(),
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

pub struct CryptParamsVerity {
    pub hash_name: String,
    pub data_device: PathBuf,
    pub hash_device: PathBuf,
    pub fec_device: PathBuf,
    pub salt: Vec<u8>,
    pub hash_type: u32,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub data_size: u64,
    pub hash_area_offset: u64,
    pub fec_area_offset: u64,
    pub fec_roots: u32,
    pub flags: CryptVerityFlags,
}

impl<'a> TryFrom<&'a cryptsetup_sys::crypt_params_verity> for CryptParamsVerity {
    type Error = LibcryptErr;

    fn try_from(v: &'a cryptsetup_sys::crypt_params_verity) -> Result<Self, Self::Error> {
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

pub struct CryptParamsIntegrityRef<'a> {
    pub inner: cryptsetup_sys::crypt_params_integrity,
    #[allow(dead_code)]
    reference: &'a CryptParamsIntegrity,
    #[allow(dead_code)]
    integrity_cstring: CString,
    #[allow(dead_code)]
    journal_integrity_cstring: CString,
    #[allow(dead_code)]
    journal_crypt_cstring: CString,
}

pub struct CryptParamsIntegrity {
    pub journal_size: u64,
    pub journal_watermark: c_uint,
    pub journal_commit_time: c_uint,
    pub interleave_sectors: u32,
    pub tag_size: u32,
    pub sector_size: u32,
    pub buffer_sectors: u32,
    pub integrity: String,
    pub integrity_key_size: u32,
    pub journal_integrity: String,
    pub journal_integrity_key: Vec<u8>,
    pub journal_crypt: String,
    pub journal_crypt_key: Vec<u8>,
}

impl<'a> TryInto<CryptParamsIntegrityRef<'a>> for &'a CryptParamsIntegrity {
    type Error = LibcryptErr;

    fn try_into(self) -> Result<CryptParamsIntegrityRef<'a>, Self::Error> {
        let integrity_cstring = to_cstring!(self.integrity)?;
        let journal_integrity_cstring = to_cstring!(self.journal_integrity)?;
        let journal_crypt_cstring = to_cstring!(self.journal_crypt)?;
        let inner = cryptsetup_sys::crypt_params_integrity {
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

impl<'a> TryFrom<&'a cryptsetup_sys::crypt_params_integrity> for CryptParamsIntegrity {
    type Error = LibcryptErr;

    fn try_from(v: &'a cryptsetup_sys::crypt_params_integrity) -> Result<Self, Self::Error> {
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

impl Format {
    /// Get `Format` as a char pointer
    pub(crate) fn as_ptr(&self) -> *const c_char {
        match *self {
            Format::Plain => cryptsetup_sys::CRYPT_PLAIN.as_ptr() as *const c_char,
            Format::Luks1 => cryptsetup_sys::CRYPT_LUKS1.as_ptr() as *const c_char,
            Format::Luks2 => cryptsetup_sys::CRYPT_LUKS2.as_ptr() as *const c_char,
            Format::Loopaes => cryptsetup_sys::CRYPT_LOOPAES.as_ptr() as *const c_char,
            Format::Verity => cryptsetup_sys::CRYPT_VERITY.as_ptr() as *const c_char,
            Format::Tcrypt => cryptsetup_sys::CRYPT_TCRYPT.as_ptr() as *const c_char,
            Format::Integrity => cryptsetup_sys::CRYPT_INTEGRITY.as_ptr() as *const c_char,
        }
    }

    /// Get `Format` from a char pointer
    fn from_ptr(p: *const c_char) -> Result<Self, LibcryptErr> {
        if cryptsetup_sys::CRYPT_PLAIN == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Plain)
        } else if cryptsetup_sys::CRYPT_LUKS1 == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Luks1)
        } else if cryptsetup_sys::CRYPT_LUKS2 == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Luks2)
        } else if cryptsetup_sys::CRYPT_LOOPAES == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Loopaes)
        } else if cryptsetup_sys::CRYPT_VERITY == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Verity)
        } else if cryptsetup_sys::CRYPT_TCRYPT == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Tcrypt)
        } else if cryptsetup_sys::CRYPT_INTEGRITY == unsafe { CStr::from_ptr(p) }.to_bytes() {
            Ok(Format::Integrity)
        } else {
            Err(LibcryptErr::InvalidConversion)
        }
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
    pub fn get_type(&mut self) -> Result<Format, LibcryptErr> {
        Format::from_ptr(unsafe { crypt_get_type(self.reference.as_ptr()) })
    }

    /// Get the default formatting type
    pub fn get_default_type() -> Result<Format, LibcryptErr> {
        Format::from_ptr(unsafe { crypt_get_default_type() })
    }
}
