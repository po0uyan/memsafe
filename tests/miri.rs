//! Regression test for UB in `Cell::new` with niche-optimized `T`.
//!
//! `Cell::new` copies the value's bytes into the protected page, volatile-zeros
//! the caller's copy, and then has to stop that copy from being dropped twice.
//! It used to do that with `std::mem::forget(value)`.
//!
//! Zero every byte of a `Vec` and its pointer becomes null while its length and
//! capacity stay non-zero: not a valid `Vec`. `forget` takes `value` *by value*,
//! so the call moves an invalid `Vec` — immediate UB, regardless of what
//! `forget` then does with it. Same for `String`, `Box`, `Rc`, `Arc`, `&T` and
//! `NonZero*`, i.e. anything where all-bits-zero is not a valid value.
//!
//! This is invisible to a normal test run (the move is a no-op at codegen, and
//! the value is never read afterwards), so the gate is `cargo miri test`. Run:
//!
//! ```text
//! cargo +nightly miri test --test miri
//! ```
//!
//! `src/ffi/miri.rs` stands in for the syscall backend under `cfg(miri)`;
//! everything else here is the crate's real code.
//!
//! The tests themselves do not check `cfg(miri)`: they run in the normal
//! `cargo test` pass too, where they pass without detecting anything. That
//! is expected — the assertions are about values, and the UB is invisible
//! until an interpreter looks for it.

use memsafe::MemSafe;

/// Every type below has a niche, so zeroing it produces an invalid value.
/// `Cell::new` must never move the value after the wipe.
#[test]
fn mem_safe_new_accepts_types_with_niches() {
    let ms = MemSafe::new(String::from("secret-value")).unwrap();
    drop(ms);

    let ms = MemSafe::new(vec![1u8, 2, 3, 4]).unwrap();
    drop(ms);

    let ms = MemSafe::new(Box::new(7u64)).unwrap();
    drop(ms);

    let ms = MemSafe::new(std::rc::Rc::new(1u8)).unwrap();
    drop(ms);

    let ms = MemSafe::new(std::sync::Arc::new(1u8)).unwrap();
    drop(ms);

    let value = 5u8;
    let ms = MemSafe::new(&value).unwrap();
    drop(ms);

    let ms = MemSafe::new(std::num::NonZeroU8::new(5).unwrap()).unwrap();
    drop(ms);
}

/// The stored bytes must still be the original value: the fix must not have
/// turned the "wipe the caller's copy" step into "wipe the page".
#[test]
fn mem_safe_new_preserves_the_value() {
    let mut ms = MemSafe::new(String::from("hello")).unwrap();
    assert_eq!(&*ms.read().unwrap(), "hello");
}

/// Types without a niche read back correctly too (this path was never buggy,
/// but it shares the code that changed).
#[test]
fn mem_safe_new_preserves_plain_values() {
    let mut ms = MemSafe::new([0u8; 32]).unwrap();
    {
        let mut writer = ms.write().unwrap();
        writer[..4].copy_from_slice(b"data");
    }
    assert_eq!(&ms.read().unwrap()[..4], b"data");

    let mut n = MemSafe::new(1234u64).unwrap();
    assert_eq!(*n.read().unwrap(), 1234);
    *n.write().unwrap() = 99;
    assert_eq!(*n.read().unwrap(), 99);
}
