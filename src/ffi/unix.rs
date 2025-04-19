use crate::error::MemoryError;

/// Wrapper over `mmap`. Full documentation with `man mmap`.
pub fn mmap<T>(
    len: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: isize,
) -> Result<*mut T, MemoryError> {
    let mmap_offset = if cfg!(target_pointer_width = "32") {
        offset as i32 as libc::off_t
    } else {
        offset as libc::off_t // Default to i64 for other architectures
    };
    let ptr = unsafe { libc::mmap(std::ptr::null_mut(), len, prot, flags, fd, mmap_offset) };
    if ptr == libc::MAP_FAILED {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(ptr as *mut T)
    }
}

/// Wrapper over `mprotect`. Full documentation with `man mprotect`.
pub fn mprotect<T>(ptr: *mut T, len: usize, prot: i32) -> Result<(), MemoryError> {
    if unsafe { libc::mprotect(ptr as *mut libc::c_void, len, prot) } != 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

/// Wrapper over `mlock`. Full documentation with `man mlock`.
pub fn mlock<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    if unsafe { libc::mlock(ptr as *const libc::c_void, len) } != 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

/// Wrapper over `madvice`. Full documentation here:
/// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualunlock
#[cfg(target_os = "linux")]
pub fn madvice<T>(ptr: *mut T, len: usize, advice: i32) -> Result<(), MemoryError> {
    if unsafe { libc::madvise(ptr as *mut libc::c_void, len, advice) } != 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

/// Wrapper over `munlock`. Full documentation with `man munlock`.
pub fn munlock<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    if unsafe { libc::munlock(ptr as *mut libc::c_void, len) } != 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

/// Wrapper over `munmap`. Full documentation with `man munmap`.
pub fn munmap<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    //
    if unsafe { libc::munmap(ptr as *mut libc::c_void, len) } != 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}
