use crate::MemoryError;

pub fn mmap<T>(
    len: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> Result<*mut T, MemoryError> {
    let ptr = unsafe { libc::mmap(std::ptr::null_mut(), len, prot, flags, fd, offset) };
    if ptr == libc::MAP_FAILED {
        Err(MemoryError(std::io::Error::last_os_error()))
    } else {
        Ok(ptr as *mut T)
    }
}

pub fn mprotect<T>(ptr: *mut T, len: usize, prot: i32) -> Result<(), MemoryError> {
    if unsafe { libc::mprotect(ptr as *mut libc::c_void, len, prot) } != 0 {
        Err(MemoryError(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

pub fn mlock<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    if unsafe { libc::mlock(ptr as *const libc::c_void, len) } != 0 {
        Err(MemoryError(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

pub fn madvice<T>(ptr: *mut T, len: usize, advice: i32) -> Result<(), MemoryError> {
    if unsafe { libc::madvise(ptr as *mut libc::c_void, len, advice) } != 0 {
        Err(MemoryError(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

pub fn munlock<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    if unsafe { libc::munlock(ptr as *mut libc::c_void, len) } != 0 {
        Err(MemoryError(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

pub fn munmap<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    //
    if unsafe { libc::munmap(ptr as *mut libc::c_void, len) } != 0 {
        Err(MemoryError(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}
