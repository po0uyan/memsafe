use std::ops::{Deref, DerefMut};

#[cfg(unix)]
use crate::ffi::mem_noaccess;

#[cfg(target_os = "linux")]
use crate::ffi::{mem_no_dump, mem_wipe_on_fork};

use crate::{
    ffi::{mem_alloc, mem_dealloc, mem_lock, mem_readonly, mem_readwrite, mem_unlock},
    ptr_ops::{ptr_deref, ptr_deref_mut, ptr_drop_in_place, ptr_fill_zero, secure_zero},
    MemoryError,
};

// No `Debug`: this crate withholds `Debug` from every type that participates
// in handling secret memory, so nothing about the page (not even its address)
// can leak through a formatting macro.
pub struct Cell<T> {
    ptr: *mut T,
}

/// Tracks how far `Cell` construction has progressed. Construction is strictly
/// linear:
///
/// 1. `mem_alloc` succeeds          → `Allocated`
/// 2. `mem_lock`  succeeds          → `Locked`
/// 3. value is written to the page  → `Written` (page must be wiped on rollback)
// `PartialState` deliberately does not derive `Debug`: this crate withholds
// `Debug` from any type that participates in handling secret memory, so that
// a stray `dbg!` or `{:?}` cannot leak state information to logs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PartialState {
    Allocated,
    Locked,
    Written,
}

/// RAII guard for a partially-constructed protected page.
///
/// While `Cell::new` / `Cell::new_with` walk through their fallible setup
/// steps, this guard owns the page. If any step returns `Err`, or if a
/// caller-provided `init` closure panics, the guard's `Drop` rolls back
/// exactly the partial state that was reached — including wiping the page
/// when a secret has already been written into it.
///
/// On a successful build, [`PartialCell::disarm`] uses `mem::forget` to
/// suppress cleanup so the live `Cell` takes ownership of the page.
///
/// Rollback is intentionally best-effort: each syscall is invoked through
/// `let _ = ...` rather than `?` or `.unwrap()`. Construction has already
/// failed by the time we get here, and amplifying that failure into a
/// panic-during-drop (which aborts the process if a panic is already
/// unwinding) serves no one.
struct PartialCell<T> {
    ptr: *mut T,
    len: usize,
    state: PartialState,
}

impl<T> PartialCell<T> {
    fn new(ptr: *mut T, len: usize) -> Self {
        Self {
            ptr,
            len,
            state: PartialState::Allocated,
        }
    }

    fn mark_locked(&mut self) {
        debug_assert!(self.state == PartialState::Allocated);
        self.state = PartialState::Locked;
    }

    fn mark_written(&mut self) {
        debug_assert!(self.state == PartialState::Locked);
        self.state = PartialState::Written;
    }

    /// Suppress cleanup and return the raw pointer. Call exactly once after
    /// every fallible setup step has succeeded.
    fn disarm(self) -> *mut T {
        let ptr = self.ptr;
        std::mem::forget(self);
        ptr
    }
}

impl<T> Drop for PartialCell<T> {
    fn drop(&mut self) {
        // If a `T` has been written into the page, drop it and zero the
        // bytes before unmapping. The page is RW at this point in the
        // construction sequence (we haven't yet called the final mprotect
        // that lowers privilege); a defensive `mem_readwrite` covers the
        // pathological case where some intermediate step left the page
        // in a non-RW state.
        if self.state == PartialState::Written {
            let _ = mem_readwrite(self.ptr, self.len);
            // `*self.ptr` holds a valid `T` written by `Cell::new`'s
            // byte copy or `Cell::new_with`'s `init` closure. The page
            // is RW (or has just been re-set RW above).
            ptr_drop_in_place(self.ptr);
            ptr_fill_zero(self.ptr);
        }
        // Only `munlock` if we successfully locked — `munlock` on
        // never-locked memory is documented as UB on some platforms.
        if matches!(self.state, PartialState::Locked | PartialState::Written) {
            let _ = mem_unlock(self.ptr, self.len);
        }
        // The mapping always exists in this state — `Allocated` is the
        // entry condition for constructing a `PartialCell`.
        let _ = mem_dealloc(self.ptr, self.len);
    }
}

impl<T> Cell<T> {
    pub fn new(mut value: T) -> Result<Cell<T>, MemoryError> {
        let len = std::mem::size_of::<T>();
        if len == 0 {
            return Err(MemoryError::from(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "zero-sized values cannot be placed in protected memory",
            )));
        }
        let ptr = mem_alloc(len)?;
        // From here on the page is owned by `guard`. Any `?` failure or
        // panic will roll back through `PartialCell::drop`.
        let mut guard = PartialCell::new(ptr, len);

        mem_lock(ptr, len)?;
        guard.mark_locked();

        #[cfg(target_os = "linux")]
        mem_no_dump(ptr, len)?;
        #[cfg(target_os = "linux")]
        mem_wipe_on_fork(ptr, len)?;

        // Copy `value`'s bytes into the protected page, wipe the original
        // through the same borrow, then `forget` it. Ordering constraints:
        // the bytes must not move through another function's stack frame
        // (a copy there could never be wiped), the wipe must happen while
        // `value` is still live, and `forget` must come last so the wiped
        // value is never dropped. `Written` is marked between copy and
        // wipe so a panic in between still wipes the page on rollback.
        let val_ptr = &mut value as *mut T;
        unsafe {
            std::ptr::copy_nonoverlapping(val_ptr as *const u8, ptr as *mut u8, len);
        }
        guard.mark_written();
        ptr_fill_zero(val_ptr);
        std::mem::forget(value);

        #[cfg(windows)]
        mem_readonly(ptr, len)?;
        #[cfg(unix)]
        mem_noaccess(ptr, len)?;

        Ok(Cell {
            ptr: guard.disarm(),
        })
    }

    pub fn low_priv(&mut self) -> Result<(), MemoryError> {
        // lowest privilege on windows
        #[cfg(windows)]
        let ret = self.read_only();

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

impl<const N: usize> Cell<[u8; N]> {
    /// Allocate a protected `N`-byte page and let `init` fill it in place.
    ///
    /// The page is allocated, `mlock`'d, marked `MADV_DONTDUMP` (Linux), and
    /// OS-zeroed (`mmap MAP_ANONYMOUS` / `VirtualAlloc MEM_COMMIT`) **before**
    /// `init` runs. `init` writes the secret through `&mut [u8; N]` directly
    /// into the protected region — no stack temporary, no allocator detour.
    /// After `init` returns, the page is transitioned to its lowest-privilege
    /// state (`PROT_NONE` on Unix, `PAGE_READONLY` on Windows).
    ///
    /// If `init` panics, the unwinding runs the construction guard's `Drop`
    /// which volatile-zeros the page and releases all OS resources. The
    /// panic is then re-propagated unchanged.
    pub fn new_with<F>(init: F) -> Result<Self, MemoryError>
    where
        F: FnOnce(&mut [u8; N]),
    {
        let len = std::mem::size_of::<[u8; N]>();
        if len == 0 {
            return Err(MemoryError::from(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "zero-sized values cannot be placed in protected memory",
            )));
        }
        let ptr: *mut [u8; N] = mem_alloc(len)?;
        // From here on the page is owned by `guard`. Any `?` failure, or
        // a panic from `init`, will roll back through `PartialCell::drop`.
        let mut guard = PartialCell::new(ptr, len);

        mem_lock(ptr, len)?;
        guard.mark_locked();

        #[cfg(target_os = "linux")]
        mem_no_dump(ptr, len)?;
        #[cfg(target_os = "linux")]
        mem_wipe_on_fork(ptr, len)?;

        // Mark `Written` *before* invoking `init`: the closure may write
        // partial secret bytes and then panic. `[u8; N]` has trivial
        // `Drop`, so the guard's `drop_in_place` is a no-op; the
        // important effect is the volatile page-wipe on rollback.
        guard.mark_written();
        init(unsafe { &mut *ptr });

        #[cfg(windows)]
        mem_readonly(ptr, len)?;
        #[cfg(unix)]
        mem_noaccess(ptr, len)?;

        Ok(Cell {
            ptr: guard.disarm(),
        })
    }

    /// Encapsulate an owned byte source into a fresh protected page,
    /// volatile-zeroing the source after the copy.
    ///
    /// On error the source is returned alongside the failure reason:
    /// - On length mismatch (`source.len() > N`): source is returned untouched.
    /// - On memory-protection failure: source has already been zeroed.
    pub fn from_bytes<T: AsMut<[u8]>>(mut bytes: T) -> Result<Self, (T, MemoryError)> {
        let len = bytes.as_mut().len();
        if len > N {
            return Err((
                bytes,
                MemoryError::from(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "byte slice exceeds buffer size",
                )),
            ));
        }
        Self::new_with(|page| {
            let slice = bytes.as_mut();
            unsafe {
                std::ptr::copy_nonoverlapping(slice.as_ptr(), page.as_mut_ptr(), len);
            }
            secure_zero(slice);
        })
        .map_err(|e| (bytes, e))
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
        let len = std::mem::size_of::<T>();
        // Fail secure: if the page can't be made writable it can't be wiped,
        // so leak it — still mapped, locked, and sealed — rather than return
        // a dirty page to the OS for reuse by the next allocation. This also
        // keeps drop from panicking, which would abort the process when a
        // panic is already unwinding.
        if mem_readwrite(self.ptr, len).is_err() {
            return;
        }
        ptr_drop_in_place(self.ptr);
        ptr_fill_zero(self.ptr);
        let _ = mem_unlock(self.ptr, len);
        let _ = mem_dealloc(self.ptr, len);
    }
}
