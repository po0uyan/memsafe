use crate::MemoryError;

#[cfg(unix)]
mod unix;

#[cfg(unix)]
use libc::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_NONE, PROT_READ, PROT_WRITE};

#[cfg(target_os = "linux")]
use libc::{c_void, MADV_DONTDUMP};

#[cfg(windows)]
mod win;
#[cfg(windows)]
use winapi::um::winnt::{MEM_COMMIT, MEM_DECOMMIT, MEM_RESERVE, PAGE_READONLY, PAGE_READWRITE};

/// Allocates page-alined memory dynamically.
///
/// This function provides a cross-platform abstraction for memory allocation,
/// using `mmap` on Unix-like systems and `VirtualAlloc` on Windows. The allocated
/// memory is anonymous, meaning it is not backed by a file and is zero-initialized
/// by the OS.
///
/// # Arguments
///
/// * `len` - The size of the memory allocation in bytes.
///
/// # Returns
///
/// * `Ok(*mut T)` - A pointer to the allocated memory if the allocation succeeds.
/// * `Err(MemoryError)` - A memory allocation error if the operation fails.
///
/// # Platform-specific Behavior
///
/// * **Unix**: Uses `mmap` with `PROT_READ | PROT_WRITE` and `MAP_PRIVATE | MAP_ANONYMOUS`.
/// * **Windows**: Uses `VirtualAlloc` with `MEM_COMMIT | MEM_RESERVE` and `PAGE_READWRITE`.
///
/// # Safety
///
/// The returned pointer is uninitialized and must be properly managed by the caller.
/// Ensure that the allocated memory is deallocated appropriately to prevent memory leaks.
pub fn mem_alloc<T>(len: usize) -> Result<*mut T, MemoryError> {
    #[cfg(unix)]
    {
        unix::mmap(
            len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
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

/// Deallocates previously allocated page-aligned memory.
///
/// This function provides a cross-platform abstraction for memory deallocation,
/// using `munmap` on Unix-like systems and `VirtualFree` on Windows. It ensures that
/// memory is properly released and can be reclaimed by the operating system.
///
/// # Arguments
///
/// * `ptr` - A pointer to the memory that was previously allocated.
/// * `len` - The size of the allocated memory in bytes. This must match the size
///   originally passed to [`mem_alloc`](fn.mem_alloc.html).
///
/// # Returns
///
/// * `Ok(())` - If the deallocation succeeds.
/// * `Err(MemoryError)` - If the operation fails.
///
/// # Platform-specific Behavior
///
/// * **Unix**: Uses `munmap` to release the memory.
/// * **Windows**: Uses `VirtualFree` with `MEM_DECOMMIT` to deallocate the memory.
///
/// # Safety
///
/// * The `ptr` must be a valid, non-null pointer returned by [`mem_alloc`](fn.mem_alloc.html).
/// * The `len` must be correct, as passing an incorrect size may cause undefined behavior.
/// * After deallocation, the pointer must not be accessed again.
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

/// Marks a memory region as inaccessible.
///
/// This function changes the protection settings of a previously allocated memory region
/// to prevent any read, write, or execute access.
///
/// # Arguments
///
/// * `ptr` - A pointer to the memory region.
/// * `len` - The size of the memory region in bytes.
///
/// # Returns
///
/// * `Ok(())` - If the operation succeeds.
/// * `Err(MemoryError)` - If the operation fails.
///
/// # Platform-specific Behavior
///
/// * **Unix**: Uses `mprotect` with `PROT_NONE`, making the memory completely inaccessible.
/// * **Windows**: Uses `VirtualProtect` with `PAGE_NOACCESS`, denying all access.
///
/// # Safety
///
/// * `ptr` must be a valid, non-null pointer to an allocated memory region.
/// * `len` must be correct, matching the size of the allocated region.
/// * Accessing the memory after calling this function will trigger a segmentation fault (Unix) or
///   access violation (Windows).
#[cfg(unix)]
pub fn mem_noaccess<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {

    unix::mprotect(ptr, len, PROT_NONE)
}

/// Marks a memory region as read-only.
///
/// This function modifies the protection settings of a previously allocated memory region
/// to allow read access while preventing writes.
///
/// # Arguments
///
/// * `ptr` - A pointer to the memory region.
/// * `len` - The size of the memory region in bytes.
///
/// # Returns
///
/// * `Ok(())` - If the operation succeeds.
/// * `Err(MemoryError)` - If the operation fails.
///
/// # Platform-specific Behavior
///
/// * **Unix**: Uses `mprotect` with `PROT_READ`, making the memory readable but not writable or executable.
/// * **Windows**: Uses `VirtualProtect` with `PAGE_READONLY`, allowing only read access.
///
/// # Safety
///
/// * `ptr` must be a valid, non-null pointer to an allocated memory region.
/// * `len` must be correct, matching the size of the allocated region.
/// * Writing to the memory after calling this function will trigger a segmentation fault
///   (Unix) or an access violation (Windows).
pub fn mem_readonly<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    #[cfg(unix)]
    {
        unix::mprotect(ptr, len, PROT_READ)
    }

    #[cfg(windows)]
    {
        win::virtual_protect(ptr, len, PAGE_READONLY, &mut 0)
    }
}

/// Marks a memory region as readable and writable.
///
/// This function modifies the protection settings of a previously allocated memory region
/// to allow both read and write access.
///
/// # Arguments
///
/// * `ptr` - A pointer to the memory region.
/// * `len` - The size of the memory region in bytes.
///
/// # Returns
///
/// * `Ok(())` - If the operation succeeds.
/// * `Err(MemoryError)` - If the operation fails.
///
/// # Platform-specific Behavior
///
/// * **Unix**: Uses `mprotect` with `PROT_READ | PROT_WRITE`, enabling both read and write access.
/// * **Windows**: Uses `VirtualProtect` with `PAGE_READWRITE`, allowing both read and write operations.
///
/// # Safety
///
/// * `ptr` must be a valid, non-null pointer to an allocated memory region.
/// * `len` must be correct, matching the size of the allocated region.
pub fn mem_readwrite<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    #[cfg(unix)]
    {
        unix::mprotect(ptr, len, PROT_READ | PROT_WRITE)
    }

    #[cfg(windows)]
    {
        win::virtual_protect(ptr, len, PAGE_READWRITE, &mut 0)
    }
}

/// Locks a memory region to prevent it from being paged out into swap memory.
///
/// This function ensures that the specified memory region remains in physical
/// Random Access Memory (RAM) and is not swapped to disk by the operating system.
///
/// # Arguments
///
/// * `ptr` - A pointer to the memory region.
/// * `len` - The size of the memory region in bytes.
///
/// # Returns
///
/// * `Ok(())` - If the operation succeeds.
/// * `Err(MemoryError)` - If the operation fails.
///
/// # Platform-specific Behavior
///
/// * **Unix**: Uses `mlock`, which prevents the specified memory range from being swapped out.
/// * **Windows**: Uses `VirtualLock`, which locks the memory in RAM and prevents paging.
///   - **Windows Limitation**:
///     - All pages in the specified region must be committed.
///     - Memory protected with `PAGE_NOACCESS` cannot be locked.
///
/// # Safety
///
/// * `ptr` must be a valid, non-null pointer to an allocated memory region.
/// * `len` must be correct, matching the size of the allocated region.
/// * Excessive use of locked memory may cause system-wide performance degradation.
/// * On some systems, locking memory may require elevated privileges.
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

/// Unlocks a previously locked memory region, allowing it to be paged out.
///
/// This function reverses the effect of [`mem_lock`](fn.mem_lock.html), allowing the operating system
/// to move the specified memory region back into the page file or swap space if necessary.
///
/// # Arguments
///
/// * `ptr` - A pointer to the memory region.
/// * `len` - The size of the memory region in bytes.
///
/// # Returns
///
/// * `Ok(())` - If the operation succeeds.
/// * `Err(MemoryError)` - If the operation fails.
///
/// # Platform-specific Behavior
///
/// * **Unix**: Uses `munlock`, allowing the specified memory range to be swapped out.
/// * **Windows**: Uses `VirtualUnlock`, allowing the memory to be paged.
///
/// # Safety
///
/// * `ptr` must be a valid, non-null pointer to an allocated memory region.
/// * `len` must be correct, matching the size of the locked region.
/// * Unlocking memory that was never locked may result in undefined behavior on some platforms.
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

#[cfg(target_os = "linux")]
pub fn mem_no_dump<T>(ptr: *mut T, len: usize) -> Result<(), MemoryError> {
    unix::madvice(ptr as *mut c_void, len, MADV_DONTDUMP)
}
