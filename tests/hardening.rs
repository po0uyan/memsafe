//! Regression tests for `MemSafe<T>` edge cases that used to break the
//! crate's guarantees: over-aligned types and panicking destructors.
//!
//! Unix-only: on Windows, building the over-aligned test values on the stack
//! crashed the test binary (STATUS_ACCESS_VIOLATION) before reaching the
//! code under test, and the drop/re-seal tests already need Unix signals.
#![cfg(unix)]

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

/// A value whose destructor panics.
#[cfg(unix)]
struct PanicOnDrop([u8; 32]);

#[cfg(unix)]
impl Drop for PanicOnDrop {
    fn drop(&mut self) {
        panic!("PanicOnDrop::drop");
    }
}

#[cfg(unix)]
const SECRET: &[u8; 32] = b"TOP-SECRET-TOP-SECRET-TOP-SECRET";

/// If `T::drop` panics, the secret must still be wiped and the page
/// released. Before the fix the panic skipped the teardown, and the page
/// stayed mapped, writable and full of the secret after the drop.
///
/// The child drops the value, catches the panic, and reads the old address:
/// it must fault (page unmapped) or at least not see the secret. It exits 42
/// if the secret is still there.
#[cfg(unix)]
#[test]
fn panicking_drop_still_wipes_and_releases_the_page() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    if std::env::var_os("MEMSAFE_PANIC_DROP_CHILD").is_some() {
        let mut ms = MemSafe::new(PanicOnDrop(*SECRET)).unwrap();
        let addr = { ms.read().unwrap().0.as_ptr() as usize };
        let caught = catch_unwind(AssertUnwindSafe(|| drop(ms)));
        assert!(caught.is_err(), "the panic must still propagate");
        let mut seen = [0u8; 32];
        for (i, b) in seen.iter_mut().enumerate() {
            *b = unsafe { std::ptr::read_volatile((addr as *const u8).add(i)) };
        }
        std::process::exit(if &seen == SECRET { 42 } else { 0 });
    }

    let exe = std::env::current_exe().unwrap();
    let status = std::process::Command::new(exe)
        .args([
            "panicking_drop_still_wipes_and_releases_the_page",
            "--exact",
            "--test-threads=1",
        ])
        .env("MEMSAFE_PANIC_DROP_CHILD", "1")
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();

    // Same escape hatch as tests/security.rs: under cross + qemu the test
    // binary cannot re-exec itself.
    if status.code() == Some(127) {
        eprintln!("skipping: this environment cannot respawn the test binary");
        return;
    }

    use std::os::unix::process::ExitStatusExt;
    assert!(
        status.signal().is_some() || status.code() == Some(0),
        "secret must be wiped and the page released after a panicking drop, got {status:?}"
    );
}

/// If a guard cannot re-seal the page on drop, the process must abort.
/// Before, `low_priv().unwrap()` panicked, which a caller could catch and
/// carry on with the secret still readable.
///
/// The child makes the re-seal fail by unmapping the page under a live read
/// guard (the `mprotect` in the guard's drop then fails with ENOMEM).
#[cfg(unix)]
#[test]
fn failed_reseal_aborts_instead_of_panicking() {
    if std::env::var_os("MEMSAFE_RESEAL_CHILD").is_some() {
        let mut ms = MemSafe::new([1u8; 32]).unwrap();
        let guard = ms.read().unwrap();
        let page = guard.as_ptr() as *mut libc::c_void;
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        assert_eq!(unsafe { libc::munmap(page, page_size) }, 0);
        let survived = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(guard)));
        // Reaching this line means the failure was a catchable panic.
        std::process::exit(if survived.is_err() { 3 } else { 4 });
    }

    let exe = std::env::current_exe().unwrap();
    let status = std::process::Command::new(exe)
        .args([
            "failed_reseal_aborts_instead_of_panicking",
            "--exact",
            "--test-threads=1",
        ])
        .env("MEMSAFE_RESEAL_CHILD", "1")
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();

    if status.code() == Some(127) {
        eprintln!("skipping: this environment cannot respawn the test binary");
        return;
    }

    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        status.signal(),
        Some(libc::SIGABRT),
        "a failed re-seal must abort the process, got {status:?}"
    );
}
