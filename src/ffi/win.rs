use winapi::{
    ctypes::c_void,
    um::memoryapi::{VirtualAlloc, VirtualFree, VirtualLock, VirtualProtect, VirtualUnlock},
};

use crate::MemoryError;

/// Wrapper over `VirtualAlloc`. Full documentation here:
/// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
pub fn virtual_alloc<T>(
    ptr: *mut c_void,
    len: usize,
    allocation_type: u32,
    protect: u32,
) -> Result<*mut T, MemoryError> {
    let ptr = unsafe { VirtualAlloc(ptr, len, allocation_type, protect) };
    if ptr.is_null() {
        Err(MemoryError(std::io::Error::last_os_error()))
    } else {
        Ok(ptr as *mut T)
    }
}

/// Wrapper over `VirtualFree`. Full documentation here:
/// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree
pub fn virtual_free<T>(ptr: *mut T, len: usize, free_type: u32) -> Result<(), MemoryError> {
    if unsafe { VirtualFree(ptr as *mut _, len, free_type) } == 0 {
        Err(MemoryError(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

/// Wrapper over `VirtualProtect`. Full documentation here:
/// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
pub fn virtual_protect<T>(
    ptr: *mut T,
    len: usize,
    new_protect: u32,
    old_protect: &mut u32,
) -> Result<(), MemoryError> {
    if unsafe { VirtualProtect(ptr as *mut c_void, len, new_protect, old_protect) } == 0 {
        Err(MemoryError(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

/// Wrapper over `VirtualLock`. Full documentation here:
/// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock
pub fn virtual_lock<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    if unsafe { VirtualLock(ptr as *mut _, len) } == 0 {
        Err(MemoryError(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

/// Wrapper over `VirtualUnlock`. Full documentation here:
/// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualunlock
pub fn virtual_unlock<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    if unsafe { VirtualUnlock(ptr as *mut _, len) } == 0 {
        Err(MemoryError(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}
