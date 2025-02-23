// src/lib.rs
use std::cell::UnsafeCell;
use std::ops::{Deref, DerefMut};
use std::ptr;
use std::io;

#[cfg(unix)]
use libc::{self, c_void};
#[cfg(windows)]
use winapi::um::{
    memoryapi::{VirtualAlloc, VirtualFree, VirtualLock, VirtualProtect, VirtualUnlock},
    winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE},
};

#[derive(Debug)]
pub struct MemoryError(io::Error);

impl From<io::Error> for MemoryError {
    fn from(err: io::Error) -> Self {
        MemoryError(err)
    }
}

impl MemoryError {
    // Add a method to access the inner error, silencing the dead_code warning
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
        let size = std::mem::size_of::<T>();

        #[cfg(unix)]
        {
            let ptr = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if ptr == libc::MAP_FAILED {
                return Err(MemoryError(io::Error::last_os_error()));
            }
            let mem_safe = MemSafe {
                ptr: ptr as *mut T,
                len: size,
                is_writable: UnsafeCell::new(true),
            };
            unsafe { ptr::write(mem_safe.ptr, value); }
            mem_safe.lock_memory()?;
            mem_safe.set_memory_advice()?;
            mem_safe.make_noaccess()?;
            Ok(mem_safe)
        }

        #[cfg(windows)]
        {
            let ptr = unsafe {
                VirtualAlloc(
                    ptr::null_mut(),
                    size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                )
            };
            if ptr.is_null() {
                return Err(MemoryError(io::Error::last_os_error()));
            }
            let mut memsafe = MemSafe {
                ptr: ptr as *mut T,
                len: size,
                is_writable: UnsafeCell::new(true),
            };
            unsafe { ptr::write(memsafe.ptr, value); }
            memsafe.lock_memory()?;
            memsafe.make_noaccess()?;
            Ok(memsafe)
        }
    }

    fn make_noaccess(&self) -> Result<(), MemoryError> {
        #[cfg(unix)]
        unsafe {
            if libc::mprotect(self.ptr as *mut c_void, self.len, libc::PROT_NONE) != 0 {
                return Err(MemoryError(io::Error::last_os_error()));
            }
            *self.is_writable.get() = false;
            Ok(())
        }

        #[cfg(windows)]
        unsafe {
            let mut old_protect = 0;
            if VirtualProtect(self.ptr as *mut _, self.len, PAGE_NOACCESS, &mut old_protect) == 0 {
                return Err(MemoryError(io::Error::last_os_error()));
            }
            *self.is_writable.get() = false;
            Ok(())
        }
    }

    fn make_writable(&self) -> Result<(), MemoryError> {
        #[cfg(unix)]
        unsafe {
            if libc::mprotect(self.ptr as *mut c_void, self.len, libc::PROT_READ | libc::PROT_WRITE) != 0 {
                return Err(MemoryError(io::Error::last_os_error()));
            }
            *self.is_writable.get() = true;
            Ok(())
        }

        #[cfg(windows)]
        unsafe {
            let mut old_protect = 0;
            if VirtualProtect(self.ptr as *mut _, self.len, PAGE_READWRITE, &mut old_protect) == 0 {
                return Err(MemoryError(io::Error::last_os_error()));
            }
            *self.is_writable.get() = true;
            Ok(())
        }
    }

    fn make_readonly(&self) -> Result<(), MemoryError> {
        #[cfg(unix)]
        unsafe {
            if libc::mprotect(self.ptr as *mut c_void, self.len, libc::PROT_READ) != 0 {
                return Err(MemoryError(io::Error::last_os_error()));
            }
            *self.is_writable.get() = false;
            Ok(())
        }

        #[cfg(windows)]
        unsafe {
            let mut old_protect = 0;
            if VirtualProtect(self.ptr as *mut _, self.len, PAGE_READONLY, &mut old_protect) == 0 {
                return Err(MemoryError(io::Error::last_os_error()));
            }
            *self.is_writable.get() = false;
            Ok(())
        }
    }

    fn lock_memory(&self) -> Result<(), MemoryError> {
        #[cfg(unix)]
        unsafe {
            if libc::mlock(self.ptr as *const c_void, self.len) != 0 {
                return Err(MemoryError(io::Error::last_os_error()));
            }
            Ok(())
        }

        #[cfg(windows)]
        unsafe {
            if VirtualLock(self.ptr as *mut _, self.len) == 0 {
                return Err(MemoryError(io::Error::last_os_error()));
            }
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    fn set_memory_advice(&self) -> Result<(), MemoryError> {
        unsafe {
            if libc::madvise(self.ptr as *mut c_void, self.len, libc::MADV_DONTDUMP) != 0 {
                return Err(MemoryError(io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn set_memory_advice(&self) -> Result<(), MemoryError> {
        Ok(())
    }
}

impl<T> Deref for MemSafe<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        if !unsafe { *self.is_writable.get() } {
            self.make_readonly().expect("Failed to make readable");
            let result = unsafe { &*self.ptr };
            self.make_noaccess().expect("Failed to make noaccess");
            result
        } else {
            unsafe { &*self.ptr }
        }
    }
}

impl<T> DerefMut for MemSafe<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.make_writable().expect("Failed to make writable");
        unsafe {
            let result = &mut *self.ptr;
            self.make_noaccess().expect("Failed to make noaccess");
            result
        }
    }
}

impl<T> Drop for MemSafe<T> {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            self.make_writable().ok();
            ptr::drop_in_place(self.ptr);
            ptr::write_bytes(self.ptr as *mut u8, 0, self.len);
            libc::munlock(self.ptr as *const c_void, self.len);
            libc::munmap(self.ptr as *mut c_void, self.len);
        }

        #[cfg(windows)]
        unsafe {
            self.make_writable().ok();
            ptr::drop_in_place(self.ptr);
            ptr::write_bytes(self.ptr as *mut u8, 0, self.len);
            VirtualUnlock(self.ptr as *mut _, self.len);
            VirtualFree(self.ptr as *mut _, 0, MEM_RELEASE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memsafe_string() {
        let mut secret = MemSafe::new(String::from("secret")).unwrap();
        assert_eq!(*secret, "secret");
        secret.push_str(" data");
        assert_eq!(*secret, "secret data");
    }
}