// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::slice;

use libc::c_void;

#[cfg(cryptsetup23supported)]
use crate::Result;

/// Handle for zeroing memory
///
/// # SECURITY WARNING
///
/// Any pointer used with this *must point to memory allocated by* `libc::malloc`
/// or any other function compatible with `libc::free`. If it has not been,
/// you could cause memory corruption and security problems.
#[cfg(cryptsetup23supported)]
pub struct SafeMemZero(*mut c_void, usize);

#[cfg(cryptsetup23supported)]
impl SafeMemZero {
    /// Construct a safe memory handle from a pointer and a size.
    ///
    /// # Safety
    ///
    /// The pointer must point to memory allocated by `libc::malloc` or something
    /// compatible with `libc::free`. See the struct-level security warning for more
    /// information.
    pub unsafe fn from_ptr(ptr: *mut c_void, size: usize) -> Self {
        SafeMemZero(ptr, size)
    }
}

#[cfg(cryptsetup23supported)]
impl Drop for SafeMemZero {
    fn drop(&mut self) {
        unsafe {
            libcryptsetup_rs_sys::crypt_safe_memzero(self.0, self.1);
            libc::free(self.0);
        }
    }
}

/// Handle to allocated memory from libcryptsetup
pub struct SafeMemHandle(*mut c_void, usize);

impl SafeMemHandle {
    pub(crate) unsafe fn from_ptr(ptr: *mut c_void, size: usize) -> Self {
        SafeMemHandle(ptr, size)
    }

    /// Allocate a block of memory that will be safely zeroed when deallocated
    /// by the `Drop` trait.
    #[cfg(cryptsetup23supported)]
    pub fn alloc(size: usize) -> Result<Self> {
        let ptr = ptr_to_result!(unsafe { libcryptsetup_rs_sys::crypt_safe_alloc(size) })?;
        Ok(SafeMemHandle(ptr, size))
    }

    /// Zero the data in the buffer. This is not necessary in most circumstances
    /// unless the user wants to reuse the buffer and reinitialize with zeros.
    /// This method is never needed before the value is dropped as `Drop` will
    /// safely zero the memory for the user.
    #[cfg(cryptsetup23supported)]
    pub fn memzero(&mut self) {
        unsafe { libcryptsetup_rs_sys::crypt_safe_memzero(self.0, self.1) };
    }
}

impl Drop for SafeMemHandle {
    fn drop(&mut self) {
        unsafe { libcryptsetup_rs_sys::crypt_safe_free(self.0) }
    }
}

impl AsRef<[u8]> for SafeMemHandle {
    fn as_ref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.0 as *const _ as *const u8, self.1) }
    }
}

impl AsMut<[u8]> for SafeMemHandle {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.0 as *mut u8, self.1) }
    }
}

#[cfg(all(test, cryptsetup23supported))]
mod test {
    use super::*;

    use std::io::Write;

    #[test]
    fn test_memzero() {
        let mut handle = SafeMemHandle::alloc(32).unwrap();
        handle.as_mut().write_all(&[20; 32]).unwrap();
        assert_eq!(&[20; 32], handle.as_ref());
        handle.memzero();
        assert_eq!(&[0; 32], handle.as_ref());
    }
}
