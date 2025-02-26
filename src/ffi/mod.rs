use crate::MemoryError;

#[cfg(unix)]
pub mod unix;

#[cfg(windows)]
pub mod win;
#[cfg(windows)]
use winapi::um::winnt::{
    MEM_COMMIT, MEM_DECOMMIT, MEM_RESERVE, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
};

pub fn mem_alloc<T>(len: usize) -> Result<*mut T, MemoryError> {
    #[cfg(unix)]
    {
        unix::mmap(
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    }

    #[cfg(windows)]
    {
        win::virtual_alloc(
            std::ptr::null_mut(),
            len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    }
}

pub fn mem_dealloc<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    #[cfg(unix)]
    {
        unix::munmap(ptr, len)
    }

    #[cfg(windows)]
    {
        win::virtual_free(ptr, len, MEM_DECOMMIT)
    }
}

pub fn mem_noaccess<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    #[cfg(unix)]
    {
        unix::mprotect(ptr, len, libc::PROT_NONE)
    }

    #[cfg(windows)]
    {
        win::virtual_protect(ptr, len, PAGE_NOACCESS, &mut 0)
    }
}

pub fn mem_readonly<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    #[cfg(unix)]
    {
        unix::mprotect(ptr, len, libc::PROT_READ)
    }

    #[cfg(windows)]
    {
        win::virtual_protect(ptr, len, PAGE_READONLY, &mut 0)
    }
}

pub fn mem_readwrite<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    #[cfg(unix)]
    {
        unix::mprotect(ptr, len, libc::PROT_READ | libc::PROT_WRITE)
    }

    #[cfg(windows)]
    {
        win::virtual_protect(ptr, len, PAGE_READWRITE, &mut 0)
    }
}

pub fn mem_lock<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    #[cfg(unix)]
    {
        unix::mlock(ptr, len)
    }

    #[cfg(windows)]
    {
        win::virtual_lock(ptr, len)
    }
}

pub fn mem_unlock<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    #[cfg(unix)]
    {
        unix::munlock(ptr, len)
    }

    #[cfg(windows)]
    {
        win::virtual_unlock(ptr, len)
    }
}
