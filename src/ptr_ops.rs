use std::sync::atomic::{Ordering, compiler_fence};

/// Volatile, compiler-fenced zeroization of `*ptr`.
///
/// Writes `size_of::<T>()` zero bytes through `ptr` using `write_volatile`,
/// followed by a `SeqCst` compiler fence. The optimizer is forbidden from
/// eliding volatile stores even when no observable read follows — the
/// language-level guarantee we need for any byte that just held a secret.
///
/// **Important:** `size_of::<T>()` is the *inline* size of `T`. For owned-pointer
/// types (`String`, `Vec<U>`, `Box<U>`) this is the header size only — the
/// heap payload they point to is **not** wiped by this function. The
/// inline-data invariant is enforced upstream by restricting the public
/// secret-handling API to `[u8; N]`.
pub fn ptr_fill_zero<T>(ptr: *mut T) {
    let len = std::mem::size_of::<T>();
    let bytes = ptr as *mut u8;
    for i in 0..len {
        unsafe { std::ptr::write_volatile(bytes.add(i), 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Volatile, compiler-fenced zeroization of a byte slice.
///
/// Use for sources that must be wiped before they are dropped — e.g. a
/// caller-supplied `Vec<u8>` whose contents have just been copied into a
/// protected page.
pub fn secure_zero(slice: &mut [u8]) {
    let ptr = slice.as_mut_ptr();
    for i in 0..slice.len() {
        unsafe { std::ptr::write_volatile(ptr.add(i), 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// True if all `len` bytes at `ptr` are zero.
///
/// Used before a protected page is released, to check that it really was
/// wiped. Volatile reads, so the check looks at memory and not at what the
/// optimizer believes was written there.
pub fn is_zeroed(ptr: *const u8, len: usize) -> bool {
    (0..len).all(|i| unsafe { std::ptr::read_volatile(ptr.add(i)) } == 0)
}

pub fn ptr_deref<'a, T>(ptr: *const T) -> &'a T {
    unsafe { &*ptr }
}

pub fn ptr_deref_mut<'a, T>(ptr: *mut T) -> &'a mut T {
    unsafe { &mut *ptr }
}

pub fn ptr_drop_in_place<T>(ptr: *mut T) {
    unsafe { ptr.drop_in_place() };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_zeroed_spots_a_single_nonzero_byte() {
        let mut buf = [0u8; 64];
        assert!(is_zeroed(buf.as_ptr(), buf.len()));
        buf[63] = 1;
        assert!(!is_zeroed(buf.as_ptr(), buf.len()));
        secure_zero(&mut buf);
        assert!(is_zeroed(buf.as_ptr(), buf.len()));
    }
}
