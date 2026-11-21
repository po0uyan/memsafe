//! Regression tests for `MemSafe<T>` edge cases that used to break the
//! crate's guarantees: over-aligned types and panicking destructors.

use memsafe::MemSafe;

/// Stricter than any page size or Windows allocation granularity in use.
#[repr(C, align(131072))]
struct OverAligned([u8; 131072]);

/// Within every supported page size.
#[repr(C, align(4096))]
struct PageAligned([u8; 4096]);

/// Run `f` on a thread with a large stack: these values are passed by value.
fn with_big_stack<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> R {
    std::thread::Builder::new()
        .stack_size(16 << 20)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

/// `mem_alloc` only guarantees page alignment. Storing a more strictly
/// aligned `T` would hand out misaligned references (UB; debug builds abort
/// with "misaligned pointer dereference"), so it must be rejected up front.
#[test]
fn over_aligned_type_is_rejected() {
    let kind = with_big_stack(|| match MemSafe::new(OverAligned([0; 131072])) {
        Ok(_) => None,
        Err(e) => Some(e.inner().kind()),
    });
    assert_eq!(kind, Some(std::io::ErrorKind::InvalidInput));
}

#[test]
fn page_aligned_type_is_accepted_and_aligned() {
    let addr = with_big_stack(|| {
        let mut ms = MemSafe::new(PageAligned([7; 4096])).unwrap();
        let view = ms.read().unwrap();
        assert_eq!(view.0[4095], 7);
        &*view as *const PageAligned as usize
    });
    assert_eq!(addr % std::mem::align_of::<PageAligned>(), 0);
}
