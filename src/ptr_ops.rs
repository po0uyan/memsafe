pub fn ptr_write<T>(ptr: *mut T, val: T) {
    unsafe { ptr.write(val) };
}

pub fn ptr_fill_zero<T>(ptr: *mut T) {
    unsafe { ptr.write_bytes(0, 1) };
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

/// Overwrites a `String`'s heap allocation with zero bytes across its full
/// capacity. The `String` itself remains valid (zero bytes are valid UTF-8),
/// so the subsequent drop will deallocate normally.
pub fn zeroize_string_heap(s: &mut String) {
    if s.capacity() == 0 {
        return;
    }
    unsafe {
        std::ptr::write_bytes(s.as_mut_ptr(), 0, s.capacity());
    }
}
