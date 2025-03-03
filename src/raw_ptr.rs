
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
