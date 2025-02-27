// src/lib.rs
mod ffi;
mod raw_ptr;

use std::convert::Infallible;
use std::io;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

#[cfg(target_os = "linux")]
use ffi::mem_no_dump;
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

#[cfg(unix)]
pub struct NoAccess;
pub struct ReadOnly;
pub struct ReadWrite;

pub struct MemSafe<T, State> {
    ptr: *mut T,
    len: usize,
    _state: PhantomData<State>,
}

#[cfg(unix)]
impl<T> MemSafe<T, NoAccess> {
    pub fn new(value: T) -> Result<Self, MemoryError> {
        let len = std::mem::size_of::<T>();
        let ptr = mem_alloc(len)?;
        mem_lock(ptr, len)?;
        #[cfg(target_os = "linux")]
        mem_no_dump()?;
        ptr_write(ptr, value);
        mem_noaccess(ptr, len)?;
        Ok(MemSafe {
            ptr,
            len,
            _state: Default::default(),
        })
    }

    pub fn no_access(self) -> Result<MemSafe<T, NoAccess>, Infallible> {
        Ok(self)
    }

    pub fn read_only(self) -> Result<MemSafe<T, ReadOnly>, MemoryError> {
        mem_readonly(self.ptr, self.len)?;
        Ok(MemSafe {
            ptr: self.ptr,
            len: self.len,
            _state: Default::default(),
        })
    }

    pub fn read_write(self) -> Result<MemSafe<T, ReadWrite>, MemoryError> {
        mem_readwrite(self.ptr, self.len)?;
        Ok(MemSafe {
            ptr: self.ptr,
            len: self.len,
            _state: Default::default(),
        })
    }
}

impl<T> MemSafe<T, ReadOnly> {
    #[cfg(windows)]
    pub fn new(value: T) -> Result<Self, MemoryError> {
        // Windows doesn't allow for no access locked memory. So, the memory is kept readonly
        // in Windows. See more in following link:
        // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock#remarks
        let len = std::mem::size_of::<T>();
        let ptr = mem_alloc(len)?;
        mem_lock(ptr, len)?;
        ptr_write(ptr, value);
        mem_readonly(ptr, len)?;
        Ok(MemSafe {
            ptr,
            len,
            _state: Default::default(),
        })
    }

    #[cfg(unix)]
    pub fn no_access(self) -> Result<MemSafe<T, NoAccess>, MemoryError> {
        mem_noaccess(self.ptr, self.len)?;
        Ok(MemSafe {
            ptr: self.ptr,
            len: self.len,
            _state: Default::default(),
        })
    }

    pub fn read_only(self) -> Result<Self, Infallible> {
        Ok(self)
    }

    pub fn read_write(self) -> Result<MemSafe<T, ReadWrite>, MemoryError> {
        mem_readwrite(self.ptr, self.len)?;
        Ok(MemSafe {
            ptr: self.ptr,
            len: self.len,
            _state: Default::default(),
        })
    }
}

impl<T> MemSafe<T, ReadWrite> {
    #[cfg(unix)]
    pub fn no_access(self) -> Result<MemSafe<T, NoAccess>, MemoryError> {
        mem_noaccess(self.ptr, self.len)?;
        Ok(MemSafe {
            ptr: self.ptr,
            len: self.len,
            _state: Default::default(),
        })
    }

    pub fn read_only(self) -> Result<Self, MemoryError> {
        mem_readonly(self.ptr, self.len)?;
        Ok(MemSafe {
            ptr: self.ptr,
            len: self.len,
            _state: Default::default(),
        })
    }

    pub fn read_write(self) -> Result<MemSafe<T, ReadWrite>, Infallible> {
        Ok(self)
    }
}

impl<T> Deref for MemSafe<T, ReadOnly> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        ptr_deref(self.ptr)
    }
}

impl<T> Deref for MemSafe<T, ReadWrite> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        ptr_deref(self.ptr)
    }
}

impl<T> DerefMut for MemSafe<T, ReadWrite> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        ptr_deref_mut(self.ptr)
    }
}

impl<T, State> Drop for MemSafe<T, State> {
    fn drop(&mut self) {
        mem_readwrite(self.ptr, self.len).unwrap();
        ptr_drop_in_place(self.ptr);
        ptr_write_bytes(self.ptr, 0, self.len);
        mem_unlock(self.ptr, self.len).unwrap();
        mem_dealloc(self.ptr, self.len).unwrap();
    }
}
