use std::ops::{Deref, DerefMut};

#[cfg(unix)]
use crate::ffi::mem_noaccess;

#[cfg(target_os = "linux")]
use crate::ffi::mem_no_dump;

use crate::{
    ffi::{mem_alloc, mem_dealloc, mem_lock, mem_readonly, mem_readwrite, mem_unlock},
    ptr_ops::{ptr_deref, ptr_deref_mut, ptr_drop_in_place, ptr_fill_zero, ptr_write},
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
        let ret = self.readonly();

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
