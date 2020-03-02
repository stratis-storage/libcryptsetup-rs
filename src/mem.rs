// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::slice;

use libc::c_void;

#[cfg(cryptsetup23supported)]
use crate::Result;

macro_rules! memzero {
    ($(#[$docs:meta])* $name:ident, $drop:expr, $(#[$from_ptr_docs:meta])*) => {
        $(#[$docs])*
        #[cfg(cryptsetup23supported)]
        pub struct $name(*mut c_void, usize);

        #[cfg(cryptsetup23supported)]
        impl $name {
            $(#[$from_ptr_docs])*
            pub unsafe fn from_ptr(ptr: *mut c_void, size: usize) -> Self {
                $name(ptr, size)
            }
        }

        #[cfg(cryptsetup23supported)]
        impl Drop for $name {
            fn drop(&mut self) {
                unsafe { $drop(self) }
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                unsafe { slice::from_raw_parts(self.0 as *const _ as *const u8, self.1) }
            }
        }

        impl AsMut<[u8]> for $name {
            fn as_mut(&mut self) -> &mut [u8] {
                unsafe { slice::from_raw_parts_mut(self.0 as *mut u8, self.1) }
            }
        }
    };
}

memzero ! {
    /// Handle for zeroing owned memory. "Owned" in this context refers to memory
    /// that has been allocated and stored in some kind of `char **` argument
    /// in the context of C FFI. This means that the memory has been allocated
    /// by standard C allocators and needs to be cleaned up by the caller.
    /// In the context of Rust, we would consider this owned by the current scope.
    ///
    /// # SECURITY WARNING
    ///
    /// Any pointer used with this *must point to memory allocated by* `libc::malloc`
    /// or any other function compatible with `libc::free`. If it has not been,
    /// you could cause memory corruption and security problems.
    SafeOwnedMemZero,
    |self_: &mut SafeOwnedMemZero| {
        libcryptsetup_rs_sys::crypt_safe_memzero(self_.0, self_.1);
        libc::free(self_.0);
    },
    /// Construct a safe memory handle from a pointer and a size.
    ///
    /// # Safety
    ///
    /// The pointer must point to memory allocated by `libc::malloc` or something
    /// compatible with `libc::free`. See the struct-level security warning for more
    /// information. The `size` argument also must match the length of the
    /// allocated block or memory corruption could occur.
}

memzero ! {
    /// Handle for zeroing borrowed memory. "Borrowed" in this context refers to memory
    /// that will be cleaned up by some other scope and is not required to be freed
    /// by the caller. An example of this would be a `char *` pointer to kernel memory
    /// where the caller can access the memory but is not responsible for its
    /// allocation or deallocation.
    SafeBorrowedMemZero,
    |self_: &mut SafeBorrowedMemZero| {
        libcryptsetup_rs_sys::crypt_safe_memzero(self_.0, self_.1);
    },
    /// Construct a safe memory handle from a pointer and a size.
    ///
    /// # Safety
    ///
    /// The length must match the length of the exposed memory block
    /// or memory corruption could occur.
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

    #[test]
    fn test_memzero_borrowed() {
        let mut slice = [0u8; 32];
        let mut borrowed_handle = unsafe {
            SafeBorrowedMemZero::from_ptr(slice.as_mut_ptr() as *mut _, slice.len())
        };
        borrowed_handle.as_mut().write_all(&[33; 32]).unwrap();
        assert_eq!(&[33; 32], borrowed_handle.as_ref());
        std::mem::drop(borrowed_handle);
        assert_eq!(&[0u8; 32], &slice);
    }
}
