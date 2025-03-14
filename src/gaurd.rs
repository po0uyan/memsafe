use std::ops::{Deref, DerefMut};

use crate::{
    ffi::{
        mem_alloc, mem_dealloc, mem_lock, mem_noaccess, mem_readonly, mem_readwrite, mem_unlock,
    },
    raw_ptr::{ptr_deref, ptr_deref_mut, ptr_drop_in_place, ptr_fill_zero, ptr_write},
    MemoryError,
};

#[derive(Debug)]
pub struct MemSafe<T> {
    data: MemSafePtr<T>,
}

impl<T> MemSafe<T> {
    pub fn new(value: T) -> Result<MemSafe<T>, MemoryError> {
        Ok(Self {
            data: MemSafePtr::new(value)?,
        })
    }

    pub fn read(&mut self) -> MemSafeRead<'_, T> {
        self.data.readonly();
        MemSafeRead { mem_safe: self }
    }

    pub fn write(&mut self) -> MemSafeWrite<'_, T> {
        self.data.readwrite();
        MemSafeWrite { mem_safe: self }
    }
}

pub struct MemSafeRead<'a, T> {
    mem_safe: &'a mut MemSafe<T>,
}

impl<T> Deref for MemSafeRead<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.mem_safe.data.deref()
    }
}

impl<T> Drop for MemSafeRead<'_, T> {
    fn drop(&mut self) {
        self.mem_safe.data.low_priv();
    }
}

pub struct MemSafeWrite<'a, T> {
    mem_safe: &'a mut MemSafe<T>,
}

impl<T> Deref for MemSafeWrite<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.mem_safe.data.deref()
    }
}

impl<T> DerefMut for MemSafeWrite<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.mem_safe.data.deref_mut()
    }
}

impl<T> Drop for MemSafeWrite<'_, T> {
    fn drop(&mut self) {
        self.mem_safe.data.low_priv();
    }
}

#[derive(Debug)]
struct MemSafePtr<T> {
    ptr: *mut T,
}

impl<T> MemSafePtr<T> {
    pub fn new(mut value: T) -> Result<MemSafePtr<T>, MemoryError> {
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

        Ok(MemSafePtr { ptr })
    }

    fn low_priv(&mut self) {
        // lowest privilege on windows
        #[cfg(windows)]
        mem_readonly(self.ptr, std::mem::size_of::<T>()).unwrap();

        // lowest privilege on unix
        #[cfg(unix)]
        mem_noaccess(self.ptr, std::mem::size_of::<T>()).unwrap();
    }

    fn readonly(&mut self) {
        mem_readonly(self.ptr, std::mem::size_of::<T>()).unwrap();
    }

    fn readwrite(&mut self) {
        mem_readwrite(self.ptr, std::mem::size_of::<T>()).unwrap();
    }
}

impl<T> Deref for MemSafePtr<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        ptr_deref(self.ptr)
    }
}

impl<T> DerefMut for MemSafePtr<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        ptr_deref_mut(self.ptr)
    }
}

impl<T> Drop for MemSafePtr<T> {
    fn drop(&mut self) {
        mem_readwrite(self.ptr, std::mem::size_of::<T>()).unwrap();
        ptr_drop_in_place(self.ptr);
        ptr_fill_zero(self.ptr);
        mem_unlock(self.ptr, std::mem::size_of::<T>()).unwrap();
        mem_dealloc(self.ptr, std::mem::size_of::<T>()).unwrap();
    }
}
