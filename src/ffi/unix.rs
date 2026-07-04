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

/// Error-branch tests: every wrapper must translate a failing syscall into
/// `Err(MemoryError)` instead of silently returning `Ok`. Each test feeds the
/// syscall an argument POSIX defines as invalid (unmapped address, overflowing
/// range, unaligned pointer), so the failures are deterministic across the
/// Unix platforms in CI.
#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = 4096;

    #[test]
    fn mmap_error_on_absurd_length() {
        // A mapping the size of the whole address space can never succeed.
        let result = mmap::<u8>(
            usize::MAX,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn mprotect_error_on_unmapped_address() {
        // The zero page is never mapped in a hosted process.
        let result = mprotect(std::ptr::null_mut::<u8>(), PAGE, libc::PROT_READ);
        assert!(result.is_err());
    }

    #[test]
    fn mlock_error_on_out_of_range_address() {
        // The top page of the address space is never mappable; locking it
        // must fail. (NULL is not used here: on macOS the reserved
        // __PAGEZERO region makes mlock(NULL) succeed.)
        let ptr = (usize::MAX & !(PAGE - 1)) as *mut u8;
        let result = mlock(ptr, PAGE);
        assert!(result.is_err());
    }

    #[test]
    fn munlock_error_on_overflowing_range() {
        // Page-aligned start address + a length that overflows the address
        // space is invalid on every POSIX platform.
        let ptr = (usize::MAX & !(PAGE - 1)) as *mut u8;
        let result = munlock(ptr, usize::MAX);
        assert!(result.is_err());
    }

    #[test]
    fn munmap_error_on_unaligned_pointer() {
        // POSIX requires the munmap address to be page-aligned.
        let result = munmap(std::ptr::dangling_mut::<u8>(), PAGE);
        assert!(result.is_err());
    }
}
