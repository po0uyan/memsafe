// src/lib.rs
mod ffi;
mod raw_ptr;

use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::io;
use std::ops::{Deref, DerefMut};

use ffi::{
    mem_alloc, mem_dealloc, mem_lock, mem_noaccess, mem_readonly, mem_readwrite, mem_unlock,
};
use raw_ptr::{ptr_deref, ptr_deref_mut, ptr_drop_in_place, ptr_write, ptr_write_bytes};

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
        let ptr = mem_alloc(len)?;
        ptr_write(ptr, value);
        let mem_safe = MemSafe {
            ptr,
            len,
            is_writable: UnsafeCell::new(true),
        };
        mem_safe.lock_memory()?;
        mem_safe.set_memory_advice()?;
        #[cfg(unix)]
        {
            mem_safe.make_noaccess()?;
        }
        // Windows doesn't allow for no access locked memory. So, the memory is kept readonly
        // in Windows. See more in following link:
        // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock#remarks
        #[cfg(windows)]
        {
            mem_safe.make_readonly()?;
        }
        Ok(mem_safe)
    }

    fn make_noaccess(&self) -> Result<(), MemoryError> {
        mem_noaccess(self.ptr, self.len)?;
        unsafe {
            *self.is_writable.get() = false;
            Ok(())
        }
    }

    fn make_writable(&self) -> Result<(), MemoryError> {
        mem_readwrite(self.ptr, self.len)?;
        unsafe {
            *self.is_writable.get() = true;
            Ok(())
        }
    }

    fn make_readonly(&self) -> Result<(), MemoryError> {
        mem_readonly(self.ptr, self.len)?;
        unsafe {
            *self.is_writable.get() = false;
            Ok(())
        }
    }

    fn lock_memory(&self) -> Result<(), MemoryError> {
        mem_lock(self.ptr, self.len)
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
        self.make_writable().unwrap();
        ptr_drop_in_place(self.ptr);
        ptr_write_bytes(self.ptr, 0, self.len);
        mem_unlock(self.ptr, self.len).unwrap();
        mem_dealloc(self.ptr, self.len).unwrap();
    }
}
