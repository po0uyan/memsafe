// src/lib.rs
mod ffi;
mod raw_ptr;

use std::cell::UnsafeCell;
use std::io;
use std::ops::{Deref, DerefMut};

use raw_ptr::{ptr_deref, ptr_deref_mut, ptr_drop_in_place, ptr_write, ptr_write_bytes};
#[cfg(windows)]
use winapi::um::
    winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, MEM_DECOMMIT} // Added MEM_RELEASE
;

#[derive(Debug)]
pub struct MemoryError(io::Error);

impl From<io::Error> for MemoryError {
    fn from(err: io::Error) -> Self {
        MemoryError(err)
    }
}

impl MemoryError {
    pub fn inner(&self) -> &io::Error {
        &self.0
    }
}

pub struct MemSafe<T> {
    ptr: *mut T,
    len: usize,
    is_writable: UnsafeCell<bool>,
}

impl<T> MemSafe<T> {
    pub fn new(value: T) -> Result<Self, MemoryError> {
        let len = std::mem::size_of::<T>();

        #[cfg(unix)]
        {
            let ptr = ffi::unix::mmap(
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )?;
            let mem_safe = MemSafe {
                ptr,
                len,
                is_writable: UnsafeCell::new(true),
            };
            ptr_write(ptr, value);
            mem_safe.lock_memory()?;
            mem_safe.set_memory_advice()?;
            mem_safe.make_noaccess()?;
            Ok(mem_safe)
        }

        #[cfg(windows)]
        {
            let ptr = ffi::win::virtual_alloc(
                std::ptr::null_mut(),
                len,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )?;
            let mem_safe = MemSafe {
                ptr,
                len,
                is_writable: UnsafeCell::new(true),
            };
            ptr_write(ptr, value);
            mem_safe.lock_memory()?;
            mem_safe.make_readonly()?;
            Ok(mem_safe)
        }
    }

    fn make_noaccess(&self) -> Result<(), MemoryError> {
        #[cfg(unix)]
        {
            ffi::unix::mprotect(self.ptr, self.len, libc::PROT_NONE)?;
            unsafe {
                *self.is_writable.get() = false;
                Ok(())
            }
        }

        #[cfg(windows)]
        {
            ffi::win::virtual_protect(self.ptr, self.len, PAGE_NOACCESS, &mut 0)?;
            unsafe {
                *self.is_writable.get() = false;
                Ok(())
            }
        }
    }

    fn make_writable(&self) -> Result<(), MemoryError> {
        #[cfg(unix)]
        {
            ffi::unix::mprotect(self.ptr, self.len, libc::PROT_READ | libc::PROT_WRITE)?;
            unsafe {
                *self.is_writable.get() = true;
                Ok(())
            }
        }

        #[cfg(windows)]
        {
            ffi::win::virtual_protect(self.ptr, self.len, PAGE_READWRITE, &mut 0)?;
            unsafe {
                *self.is_writable.get() = true;
                Ok(())
            }
        }
    }

    fn make_readonly(&self) -> Result<(), MemoryError> {
        #[cfg(unix)]
        {
            ffi::unix::mprotect(self.ptr, self.len, libc::PROT_READ)?;
            unsafe {
                *self.is_writable.get() = false;
                Ok(())
            }
        }

        #[cfg(windows)]
        {
            ffi::win::virtual_protect(self.ptr, self.len, PAGE_READONLY, &mut 0)?;
            unsafe {
                *self.is_writable.get() = false;
                Ok(())
            }
        }
    }

    fn lock_memory(&self) -> Result<(), MemoryError> {
        #[cfg(unix)]
        {
            ffi::unix::mlock(self.ptr, self.len)
        }

        #[cfg(windows)]
        {
            ffi::win::virtual_lock(self.ptr, self.len)
        }
    }

    #[cfg(target_os = "linux")]
    fn set_memory_advice(&self) -> Result<(), MemoryError> {
        ffi::unix::madvice(self.ptr as *mut c_void, self.len, libc::MADV_DONTDUMP)
    }

    #[cfg(not(target_os = "linux"))]
    fn set_memory_advice(&self) -> Result<(), MemoryError> {
        Ok(())
    }
}

impl<T> Deref for MemSafe<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe {
            if !*self.is_writable.get() {
                self.make_readonly().expect("Failed to make readable");
            }
        }
        ptr_deref(self.ptr)
    }
}

impl<T> DerefMut for MemSafe<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.make_writable().expect("Failed to make writable");
        ptr_deref_mut(self.ptr)
    }
}

impl<T> Drop for MemSafe<T> {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            self.make_writable().ok();
            ptr_drop_in_place(self.ptr);
            ptr_write_bytes(self.ptr, 0, self.len);
            ffi::unix::munlock(self.ptr, self.len).unwrap();
            ffi::unix::munmap(self.ptr, self.len).unwrap();
        }

        #[cfg(windows)]
        {
            self.make_writable().ok();
            ptr_drop_in_place(self.ptr);
            ptr_write_bytes(self.ptr, 0, self.len);
            ffi::win::virtual_unlock(self.ptr, self.len).unwrap();
            ffi::win::virtual_free(self.ptr, self.len, MEM_DECOMMIT).unwrap();
        }
    }
}
