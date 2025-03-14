// src/lib.rs
mod ffi;
pub mod gaurd;
mod raw_ptr;

use std::convert::Infallible;
use std::io;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

#[cfg(target_os = "linux")]
use ffi::mem_no_dump;
#[cfg(unix)]
use ffi::mem_noaccess;
use ffi::{mem_alloc, mem_dealloc, mem_lock, mem_readonly, mem_readwrite, mem_unlock};
use raw_ptr::{ptr_deref, ptr_deref_mut, ptr_drop_in_place, ptr_fill_zero, ptr_write};

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
/// Represents a memory state with no access permissions.
#[cfg(unix)]
pub struct NoAccess;

/// Represents a memory state with read-only permissions.
pub struct ReadOnly;

/// Represents a memory state with read-write permissions.
pub struct ReadWrite;

/// A memory-safe wrapper around raw pointers that ensures proper memory management.
///
/// The memory can have different states:
/// - `NoAccess`: Memory cannot be read or written (Unix only).
/// - `ReadOnly`: Memory is read-only.
/// - `ReadWrite`: Memory is readable and writable.
///
/// The transitions between states ensure security and prevent unintended modifications.
#[cfg(unix)]
pub struct MemSafe<T, State = NoAccess> {
    ptr: *mut T,
    _state: PhantomData<State>,
}

/// A memory-safe wrapper around raw pointers that ensures proper memory management.
///
/// The memory can have different states:
/// - `NoAccess`: Memory cannot be read or written (Unix only).
/// - `ReadOnly`: Memory is read-only.
/// - `ReadWrite`: Memory is readable and writable.
///
/// The transitions between states ensure security and prevent unintended modifications.
#[cfg(windows)]
pub struct MemSafe<T, State = ReadOnly> {
    ptr: *mut T,
    _state: PhantomData<State>,
}

#[cfg(unix)]
unsafe impl<T> Sync for MemSafe<T, NoAccess> where T: Sync {}
unsafe impl<T> Sync for MemSafe<T, ReadOnly> where T: Sync {}
#[cfg(unix)]
unsafe impl<T> Send for MemSafe<T, NoAccess> where T: Send {}
unsafe impl<T> Send for MemSafe<T, ReadOnly> where T: Send {}
unsafe impl<T> Send for MemSafe<T, ReadWrite> where T: Send {}

#[cfg(unix)]
impl<T> MemSafe<T, NoAccess> {
    /// Allocates a new instance of `T` in locked memory with no access permissions.
    pub fn new(mut value: T) -> Result<Self, MemoryError> {
        let len = std::mem::size_of::<T>();
        let ptr = mem_alloc(len)?;
        mem_lock(ptr, len)?;
        #[cfg(target_os = "linux")]
        mem_no_dump(ptr, len)?;
        let val_ptr = &mut value as *mut T;
        ptr_write(ptr, value);
        ptr_fill_zero(val_ptr);
        mem_noaccess(ptr, len)?;
        Ok(MemSafe {
            ptr,
            _state: Default::default(),
        })
    }

    /// Does nothing and return the object itself.
    pub fn no_access(self) -> Result<Self, Infallible> {
        Ok(self)
    }

    // Changes the memory state from `NoAccess` to `ReadOnly`.
    pub fn read_only(self) -> Result<MemSafe<T, ReadOnly>, MemoryError> {
        mem_readonly(self.ptr, Self::len())?;
        let new_self = MemSafe {
            ptr: self.ptr,
            _state: Default::default(),
        };
        std::mem::forget(self);
        Ok(new_self)
    }

    /// Changes the memory state from `NoAccess` to `ReadWrite`.
    pub fn read_write(self) -> Result<MemSafe<T, ReadWrite>, MemoryError> {
        mem_readwrite(self.ptr, Self::len())?;
        let new_self = MemSafe {
            ptr: self.ptr,
            _state: Default::default(),
        };
        std::mem::forget(self);
        Ok(new_self)
    }
}

impl<T> MemSafe<T, ReadOnly> {
    /// Allocates a new instance of `T` in locked memory with read-only permissions (only available in Windows).
    #[cfg(windows)]
    pub fn new(mut value: T) -> Result<Self, MemoryError> {
        // Windows doesn't allow for no access locked memory. So, the memory is kept readonly
        // in Windows. See more in following link:
        // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock#remarks
        let len = std::mem::size_of::<T>();
        let ptr = mem_alloc(len)?;
        mem_lock(ptr, len)?;
        let val_ptr = &mut value as *mut T;
        ptr_write(ptr, value);
        ptr_fill_zero(val_ptr);
        mem_readonly(ptr, len)?;
        Ok(MemSafe {
            ptr,
            _state: Default::default(),
        })
    }
    /// Changes the memory state from `ReadOnly` to `NoAccess`.
    #[cfg(unix)]
    pub fn no_access(self) -> Result<MemSafe<T, NoAccess>, MemoryError> {
        mem_noaccess(self.ptr, Self::len())?;
        let new_self = MemSafe {
            ptr: self.ptr,
            _state: Default::default(),
        };
        std::mem::forget(self);
        Ok(new_self)
    }

    /// Does nothing and return the object itself.
    pub fn read_only(self) -> Result<Self, Infallible> {
        Ok(self)
    }

    /// Changes the memory state from `ReadOnly` to `ReadWrite`.
    pub fn read_write(self) -> Result<MemSafe<T, ReadWrite>, MemoryError> {
        mem_readwrite(self.ptr, Self::len())?;
        let new_self = MemSafe {
            ptr: self.ptr,
            _state: Default::default(),
        };
        std::mem::forget(self);
        Ok(new_self)
    }
}

impl<T> MemSafe<T, ReadWrite> {
    /// Changes the memory state from `ReadWrite` to `NoAccess`.
    #[cfg(unix)]
    pub fn no_access(self) -> Result<MemSafe<T, NoAccess>, MemoryError> {
        mem_noaccess(self.ptr, Self::len())?;
        let new_self = MemSafe {
            ptr: self.ptr,
            _state: Default::default(),
        };
        std::mem::forget(self);
        Ok(new_self)
    }

    /// Changes the memory state from `ReadWrite` to `ReadOnly`.
    pub fn read_only(self) -> Result<MemSafe<T, ReadOnly>, MemoryError> {
        mem_readonly(self.ptr, Self::len())?;
        let new_self = MemSafe {
            ptr: self.ptr,
            _state: Default::default(),
        };
        std::mem::forget(self);
        Ok(new_self)
    }

    /// Does nothing and return the object itself.
    pub fn read_write(self) -> Result<Self, Infallible> {
        Ok(self)
    }
}

impl<T, S> MemSafe<T, S> {
    const fn len() -> usize {
        std::mem::size_of::<T>()
    }
}

impl<T> Deref for MemSafe<T, ReadOnly> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        ptr_deref(self.ptr)
    }
}

impl<T> AsRef<T> for MemSafe<T, ReadOnly> {
    fn as_ref(&self) -> &T {
        ptr_deref(self.ptr)
    }
}

impl<T> Deref for MemSafe<T, ReadWrite> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        ptr_deref(self.ptr)
    }
}

impl<T> AsRef<T> for MemSafe<T, ReadWrite> {
    fn as_ref(&self) -> &T {
        ptr_deref(self.ptr)
    }
}

impl<T> DerefMut for MemSafe<T, ReadWrite> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        ptr_deref_mut(self.ptr)
    }
}

impl<T> AsMut<T> for MemSafe<T, ReadWrite> {
    fn as_mut(&mut self) -> &mut T {
        ptr_deref_mut(self.ptr)
    }
}

impl<T, State> Drop for MemSafe<T, State> {
    fn drop(&mut self) {
        mem_readwrite(self.ptr, Self::len()).unwrap();
        ptr_drop_in_place(self.ptr);
        ptr_fill_zero(self.ptr);
        mem_unlock(self.ptr, Self::len()).unwrap();
        mem_dealloc(self.ptr, Self::len()).unwrap();
    }
}
