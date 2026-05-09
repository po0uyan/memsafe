use std::ops::{Deref, DerefMut};

#[cfg(unix)]
use crate::ffi::mem_noaccess;

#[cfg(target_os = "linux")]
use crate::ffi::mem_no_dump;

use crate::{
    ffi::{mem_alloc, mem_dealloc, mem_lock, mem_readonly, mem_readwrite, mem_unlock},
    ptr_ops::{ptr_deref, ptr_deref_mut, ptr_drop_in_place, ptr_fill_zero, ptr_write, secure_zero},
    MemoryError,
};

#[derive(Debug)]
pub struct Cell<T> {
    ptr: *mut T,
}

impl<T> Cell<T> {
    pub fn new(mut value: T) -> Result<Cell<T>, MemoryError> {
        // allocated memory and lock it to RAM
        let len = std::mem::size_of::<T>();
        let ptr = mem_alloc(len)?;
        mem_lock(ptr, len)?;

        // avoid memory dump in linux
        #[cfg(target_os = "linux")]
        mem_no_dump(ptr, len)?;

        // copy the value and replace it with zero
        let val_ptr = &mut value as *mut T;
        ptr_write(ptr, value);
        ptr_fill_zero(val_ptr);

        // lowest privilege on windows
        #[cfg(windows)]
        mem_readonly(ptr, len)?;

        // lowest privilege on unix
        #[cfg(unix)]
        mem_noaccess(ptr, len)?;

        Ok(Cell { ptr })
    }

    pub fn low_priv(&mut self) -> Result<(), MemoryError> {
        // lowest privilege on windows
        #[cfg(windows)]
        let ret = self.read_only();

        // lowest privilege on unix
        #[cfg(unix)]
        let ret = self.no_access();

        ret
    }

    #[cfg(unix)]
    pub fn no_access(&mut self) -> Result<(), MemoryError> {
        mem_noaccess(self.ptr, std::mem::size_of::<T>())
    }

    pub fn read_only(&mut self) -> Result<(), MemoryError> {
        mem_readonly(self.ptr, std::mem::size_of::<T>())
    }

    pub fn read_write(&mut self) -> Result<(), MemoryError> {
        mem_readwrite(self.ptr, std::mem::size_of::<T>())
    }
}

impl<const N: usize> Cell<[u8; N]> {
    /// Allocate a protected `N`-byte page and let `init` fill it in place.
    ///
    /// The page is allocated, `mlock`'d, marked `MADV_DONTDUMP` (Linux), and
    /// OS-zeroed (`mmap MAP_ANONYMOUS` / `VirtualAlloc MEM_COMMIT`) **before**
    /// `init` runs. `init` writes the secret through `&mut [u8; N]` directly
    /// into the protected region — no stack temporary, no allocator detour.
    /// After `init` returns, the page is transitioned to its lowest-privilege
    /// state (`PROT_NONE` on Unix, `PAGE_READONLY` on Windows).
    ///
    /// If `init` panics the protected page leaks (`Cell` is never constructed
    /// so its `Drop` does not run). Treat `init` as panic-free.
    pub fn new_with<F>(init: F) -> Result<Self, MemoryError>
    where
        F: FnOnce(&mut [u8; N]),
    {
        let len = std::mem::size_of::<[u8; N]>();
        let ptr: *mut [u8; N] = mem_alloc(len)?;
        mem_lock(ptr, len)?;

        #[cfg(target_os = "linux")]
        crate::ffi::mem_no_dump(ptr, len)?;

        // Page is currently RW + zero-filled. Caller writes the secret
        // straight into protected memory.
        init(unsafe { &mut *ptr });

        #[cfg(windows)]
        mem_readonly(ptr, len)?;
        #[cfg(unix)]
        mem_noaccess(ptr, len)?;

        Ok(Cell { ptr })
    }

    /// Encapsulate an owned byte source into a fresh protected page,
    /// volatile-zeroing the source after the copy.
    ///
    /// On error the source is returned alongside the failure reason:
    /// - On length mismatch (`source.len() > N`): source is returned untouched.
    /// - On memory-protection failure: source has already been zeroed.
    pub fn from_bytes<T: AsMut<[u8]>>(mut bytes: T) -> Result<Self, (T, MemoryError)> {
        let len = bytes.as_mut().len();
        if len > N {
            return Err((
                bytes,
                MemoryError::from(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "byte slice exceeds buffer size",
                )),
            ));
        }
        Self::new_with(|page| {
            let slice = bytes.as_mut();
            unsafe {
                std::ptr::copy_nonoverlapping(slice.as_ptr(), page.as_mut_ptr(), len);
            }
            secure_zero(slice);
        })
        .map_err(|e| (bytes, e))
    }
}

impl<T> Deref for Cell<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        ptr_deref(self.ptr)
    }
}

impl<T> DerefMut for Cell<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        ptr_deref_mut(self.ptr)
    }
}

impl<T> Drop for Cell<T> {
    fn drop(&mut self) {
        mem_readwrite(self.ptr, std::mem::size_of::<T>()).unwrap();
        ptr_drop_in_place(self.ptr);
        ptr_fill_zero(self.ptr);
        mem_unlock(self.ptr, std::mem::size_of::<T>()).unwrap();
        mem_dealloc(self.ptr, std::mem::size_of::<T>()).unwrap();
    }
}
