//! Security-enforcement tests.
//!
//! These don't test that the API produces the right *values* — `secret.rs`
//! does that. They test that the *protections* actually hold at runtime:
//! that a sealed page is truly inaccessible, that sources are really wiped,
//! and that failures roll back without leaking a live page.

use memsafe::Secret;

/// A byte source that records, at drop time, whether its buffer had been
/// zeroized. `Secret::from_bytes` consumes the source and drops it after the
/// copy, so this observes exactly the moment the crate promises the wipe has
/// already happened.
struct SpySource {
    data: Vec<u8>,
    zeroed_at_drop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl AsMut<[u8]> for SpySource {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Drop for SpySource {
    fn drop(&mut self) {
        let all_zero = self.data.iter().all(|&b| b == 0);
        self.zeroed_at_drop
            .store(all_zero, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn from_bytes_zeroizes_source_before_drop() {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let source = SpySource {
        data: b"super-secret-material".to_vec(),
        zeroed_at_drop: flag.clone(),
    };
    assert!(
        source.data.iter().any(|&b| b != 0),
        "precondition: source is non-zero"
    );

    // No `.unwrap()`: the error type carries `SpySource`, which (like every
    // secret-holding type here) does not implement `Debug`.
    let mut secret = match Secret::<32>::from_bytes(source) {
        Ok(s) => s,
        Err(_) => panic!("from_bytes must succeed for a fitting source"),
    };

    // The source has been dropped inside `from_bytes`; its Drop recorded
    // whether the buffer was zero at that point.
    assert!(
        flag.load(Ordering::SeqCst),
        "source bytes must be zeroized before the source is dropped"
    );

    // And the secret still holds the payload.
    let view = secret.read().unwrap();
    assert_eq!(&view[..21], b"super-secret-material");
}

#[test]
fn from_bytes_length_error_does_not_zeroize_source() {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    let flag = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let source = SpySource {
        data: b"way-too-long-for-a-4-byte-secret".to_vec(),
        zeroed_at_drop: flag.clone(),
    };

    let (returned, _err) = match Secret::<4>::from_bytes(source) {
        Ok(_) => panic!("expected length-mismatch error"),
        Err(e) => e,
    };
    // Documented contract: on length mismatch the source comes back untouched
    // so the caller can decide what to do with it.
    assert_eq!(returned.data, b"way-too-long-for-a-4-byte-secret");
    drop(returned);
    assert!(
        !flag.load(Ordering::SeqCst),
        "length-error path must return the source untouched, not zeroized"
    );
}

/// The core page-sealing guarantee on Unix: once the read guard drops, the
/// page returns to `PROT_NONE` and *any* access — even from this very
/// process — is fatal. We verify by re-running this test binary as a child
/// process that dereferences a stale pointer to the sealed page, and
/// asserting the child dies by signal (SIGSEGV/SIGBUS) instead of exiting.
///
/// Unix-only by design: on Windows the lowest-privilege state is
/// `PAGE_READONLY`, so reads through a stale pointer do not fault there.
#[cfg(unix)]
#[test]
fn sealed_page_read_is_fatal() {
    if std::env::var_os("MEMSAFE_SEALED_READ_CHILD").is_some() {
        // Child role: obtain a pointer while readable, let the guard drop,
        // then read the sealed page. The read below must kill the process.
        let mut secret = Secret::<32>::new_with(|buf| buf[0] = 0xAA).unwrap();
        let ptr_addr = {
            let view = secret.read().unwrap();
            view.as_ptr() as usize
        }; // guard dropped here -> page resealed to PROT_NONE

        let leaked = unsafe { std::ptr::read_volatile(ptr_addr as *const u8) };
        // Reaching this line means the page was readable while sealed.
        // Exit cleanly so the parent’s "died by signal" assertion fails loudly.
        eprintln!("SECURITY FAILURE: sealed page was readable, got {leaked:#x}");
        std::process::exit(0);
    }

    let exe = std::env::current_exe().unwrap();
    let status = std::process::Command::new(exe)
        .args([
            "sealed_page_read_is_fatal",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("MEMSAFE_SEALED_READ_CHILD", "1")
        .status()
        .unwrap();

    use std::os::unix::process::ExitStatusExt;
    assert!(
        status.signal().is_some(),
        "child must die by SIGSEGV/SIGBUS when reading a sealed page, got: {status:?}"
    );
}

/// Same enforcement for writes: after the write guard drops, storing through
/// a stale pointer must be fatal. Writes are blocked in the lowest-privilege
/// state on Unix (`PROT_NONE`) — this is the strongest cross-check that the
/// guard’s Drop really lowered the privilege again.
#[cfg(unix)]
#[test]
fn sealed_page_write_is_fatal() {
    if std::env::var_os("MEMSAFE_SEALED_WRITE_CHILD").is_some() {
        let mut secret = Secret::<32>::new_with(|_| {}).unwrap();
        let ptr_addr = {
            let mut guard = secret.write().unwrap();
            guard.as_mut_ptr() as usize
        }; // guard dropped here -> page resealed

        unsafe { std::ptr::write_volatile(ptr_addr as *mut u8, 0xFF) };
        eprintln!("SECURITY FAILURE: sealed page was writable");
        std::process::exit(0);
    }

    let exe = std::env::current_exe().unwrap();
    let status = std::process::Command::new(exe)
        .args([
            "sealed_page_write_is_fatal",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("MEMSAFE_SEALED_WRITE_CHILD", "1")
        .status()
        .unwrap();

    use std::os::unix::process::ExitStatusExt;
    assert!(
        status.signal().is_some(),
        "child must die by signal when writing a sealed page, got: {status:?}"
    );
}

/// A locked-memory request no machine can satisfy must surface as a clean
/// `Err` — exercising the construction rollback path (page unmapped, nothing
/// leaked, no panic) rather than aborting or returning a half-built secret.
#[cfg(target_pointer_width = "64")]
#[test]
fn mlock_failure_rolls_back_cleanly() {
    // 4 TiB: mmap may lazily accept it, but mlock cannot pin it in RAM.
    const HUGE: usize = 1 << 42;
    let result = Secret::<HUGE>::new_with(|_| {
        panic!("init must never run when construction fails before the page is ready");
    });
    assert!(
        result.is_err(),
        "locking 4 TiB must fail with a MemoryError"
    );
}
