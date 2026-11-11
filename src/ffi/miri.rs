//! Miri-compatible stand-ins for the libc syscalls in `unix.rs`.
//!
//! Miri models no foreign functions, so `mlock`/`mprotect` abort the
//! interpreter before any of this crate's own code runs. These replacements
//! back the "page" with the Rust allocator and make every permission change a
//! no-op, which is enough to check the crate for UB: the value handling in
//! `Cell`, `MemSafe` and `Secret` is ordinary Rust and runs unmodified.
//!
//! This module is only compiled under `cfg(miri)`, so it never ships and never
//! affects a real build. It deliberately does not model the OS guarantees
//! (sealing, locking, dump exclusion) — those stay covered by the tests in
//! `tests/security.rs`, which require a real kernel.

use crate::error::MemoryError;

/// Page-sized alignment, matching what `mmap` gives the real backend.
const ALIGN: usize = 4096;

fn layout(len: usize) -> std::alloc::Layout {
    std::alloc::Layout::from_size_align(len.max(1), ALIGN).expect("valid layout")
}

pub fn mmap<T>(
    len: usize,
    _prot: i32,
    _flags: i32,
    _fd: i32,
    _offset: isize,
) -> Result<*mut T, MemoryError> {
    let ptr = unsafe { std::alloc::alloc_zeroed(layout(len)) };
    if ptr.is_null() {
        Err(std::io::Error::from(std::io::ErrorKind::OutOfMemory).into())
    } else {
        Ok(ptr as *mut T)
    }
}

/// Performs the same pointer cast as `unix::mprotect`, but no permission change.
pub fn mprotect<T>(ptr: *mut T, len: usize, _prot: i32) -> Result<(), MemoryError> {
    // Sanity-check the call shape only. An over-long `len` cannot be caught
    // here: every page is a separate allocation, so there is no neighbouring
    // mapping for an out-of-range access to land in.
    debug_assert!(!ptr.is_null() && len > 0);
    Ok(())
}

pub fn mlock<T>(_ptr: *mut T, _len: usize) -> Result<(), MemoryError> {
    Ok(())
}

pub fn munlock<T>(_ptr: *mut T, _len: usize) -> Result<(), MemoryError> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn madvice<T>(_ptr: *mut T, _len: usize, _advice: i32) -> Result<(), MemoryError> {
    Ok(())
}

pub fn munmap<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    unsafe { std::alloc::dealloc(ptr as *mut u8, layout(len)) };
    Ok(())
}
