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
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

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
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

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

/// `as_mut` flips between two equal-length windows of one allocation.
/// Both are in bounds; `from_bytes` must still copy and wipe the first.
struct SplitSource {
    data: Vec<u8>,
    calls: usize,
    left: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl AsMut<[u8]> for SplitSource {
    fn as_mut(&mut self) -> &mut [u8] {
        let call = self.calls;
        self.calls += 1;
        let mid = self.data.len() / 2;
        if call == 0 {
            &mut self.data[..mid]
        } else {
            &mut self.data[mid..]
        }
    }
}

impl Drop for SplitSource {
    fn drop(&mut self) {
        if let Ok(mut left) = self.left.lock() {
            *left = std::mem::take(&mut self.data);
        }
    }
}

#[test]
fn from_bytes_copies_the_first_as_mut_slice() {
    use std::sync::{Arc, Mutex};

    let data = b"validated-sourcealternate-buffer".to_vec();
    assert_eq!(data.len(), 32);

    let left = Arc::new(Mutex::new(Vec::new()));
    let source = SplitSource {
        data,
        calls: 0,
        left: Arc::clone(&left),
    };

    let mut secret = match Secret::<32>::from_bytes(source) {
        Ok(s) => s,
        Err(_) => panic!("from_bytes must succeed for a fitting source"),
    };

    let view = secret.read().unwrap();
    assert_eq!(&view[..16], b"validated-source");
    assert!(view[16..].iter().all(|&b| b == 0));

    let data = left.lock().unwrap();
    assert_eq!(&data[..16], &[0u8; 16]);
    assert_eq!(&data[16..], b"alternate-buffer");
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

    // Under emulated CI (cross + qemu), the test binary cannot re-exec
    // itself; the spawn fails with shell exit code 127. Skip the enforcement
    // assertion there — every native target in the CI matrix still runs it.
    if status.code() == Some(127) {
        eprintln!("skipping: this environment cannot respawn the test binary");
        return;
    }

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

    // Under emulated CI (cross + qemu), the test binary cannot re-exec
    // itself; the spawn fails with shell exit code 127. Skip the enforcement
    // assertion there — every native target in the CI matrix still runs it.
    if status.code() == Some(127) {
        eprintln!("skipping: this environment cannot respawn the test binary");
        return;
    }

    use std::os::unix::process::ExitStatusExt;
    assert!(
        status.signal().is_some(),
        "child must die by signal when writing a sealed page, got: {status:?}"
    );
}

/// Child exit codes for the release tests below: the old address was still
/// readable, and held only zeros / still held secret bytes.
#[cfg(unix)]
const READABLE_BUT_WIPED: i32 = 7;
#[cfg(unix)]
const READABLE_AND_LEAKED: i32 = 8;

/// True for an x86_64 binary translated by Rosetta 2 on Apple Silicon (the
/// `macos-latest, x86_64` CI job). Rosetta shows 4 KiB pages on 16 KiB
/// hardware, so unmapping one does not make its address fault: a released
/// page stays readable there, and only the wipe can be checked.
#[cfg(target_os = "macos")]
fn under_rosetta() -> bool {
    let mut translated: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    let rc = unsafe {
        libc::sysctlbyname(
            c"sysctl.proc_translated".as_ptr(),
            (&mut translated as *mut libc::c_int).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    rc == 0 && translated == 1
}

#[cfg(all(unix, not(target_os = "macos")))]
fn under_rosetta() -> bool {
    false
}

/// The released page must be gone: reading it faults. Under Rosetta it may
/// stay readable, but must then hold only zeros.
#[cfg(unix)]
fn assert_released(status: std::process::ExitStatus, what: &str) {
    use std::os::unix::process::ExitStatusExt;
    // Not SIGABRT: that would mean the wipe check in `mem_unlock` failed.
    let faulted = matches!(status.signal(), Some(libc::SIGSEGV | libc::SIGBUS));
    let wiped_under_rosetta = under_rosetta() && status.code() == Some(READABLE_BUT_WIPED);
    assert!(
        faulted || wiped_under_rosetta,
        "reading {what} must fault (exit {READABLE_BUT_WIPED}: readable but wiped, \
         {READABLE_AND_LEAKED}: secret still there), got: {status:?}"
    );
}

/// Re-run this test binary with `env_var` set, running only `test_name`, and
/// report how that child ended. `None` when the binary cannot re-exec itself
/// (cross + qemu, shell exit code 127).
#[cfg(unix)]
fn run_child(test_name: &str, env_var: &str) -> Option<std::process::ExitStatus> {
    let exe = std::env::current_exe().unwrap();
    let status = std::process::Command::new(exe)
        .args([test_name, "--exact", "--nocapture", "--test-threads=1"])
        .env(env_var, "1")
        .status()
        .unwrap();
    if status.code() == Some(127) {
        eprintln!("skipping: this environment cannot respawn the test binary");
        return None;
    }
    Some(status)
}

/// Dropping a secret must release its page, not just wipe it: a read through
/// a pointer kept from before the drop must kill the process. If the drop
/// were skipped, or left the page mapped, the read would succeed.
#[cfg(unix)]
#[test]
fn read_after_drop_is_fatal() {
    if std::env::var_os("MEMSAFE_READ_AFTER_DROP_CHILD").is_some() {
        let mut secret = Secret::<32>::new_with(|buf| buf[0] = 0xAA).unwrap();
        let ptr_addr = {
            let view = secret.read().unwrap();
            view.as_ptr() as usize
        };
        drop(secret); // wiped, unlocked and unmapped here

        let byte = unsafe { std::ptr::read_volatile(ptr_addr as *const u8) };
        std::process::exit(if byte == 0 {
            READABLE_BUT_WIPED
        } else {
            READABLE_AND_LEAKED
        });
    }

    if let Some(status) = run_child("read_after_drop_is_fatal", "MEMSAFE_READ_AFTER_DROP_CHILD") {
        assert_released(status, "a dropped page");
    }
}

/// A construction that fails after `init` has written part of the secret
/// must wipe and release the page before the panic reaches the caller. The
/// child keeps the page's address from inside `init`, catches the panic and
/// reads it: the page must be gone. (The wipe itself is checked by the
/// debug assertion in `mem_unlock`, which aborts the child if it was
/// skipped.)
#[cfg(unix)]
#[test]
fn failed_construction_releases_the_page() {
    if std::env::var_os("MEMSAFE_FAILED_INIT_CHILD").is_some() {
        let addr = std::cell::Cell::new(0usize);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Secret::<32>::new_with(|buf| {
                buf[..3].copy_from_slice(b"abc");
                addr.set(buf.as_ptr() as usize);
                panic!("simulated init failure");
            })
        }));
        assert!(result.is_err(), "the panic must reach the caller");

        let byte = unsafe { std::ptr::read_volatile(addr.get() as *const u8) };
        std::process::exit(if byte == 0 {
            READABLE_BUT_WIPED
        } else {
            READABLE_AND_LEAKED
        });
    }

    if let Some(status) = run_child(
        "failed_construction_releases_the_page",
        "MEMSAFE_FAILED_INIT_CHILD",
    ) {
        assert_released(status, "the page of a failed construction");
    }
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

/// True when the tests run under a user-mode emulator (the cross/qemu CI
/// targets), where fork+madvise semantics don't match a real kernel.
#[cfg(target_os = "linux")]
fn emulated_kernel() -> bool {
    std::env::vars().any(|(k, _)| {
        k == "QEMU_LD_PREFIX"
            || k == "CROSS_RUNNER"
            || (k.starts_with("CARGO_TARGET_") && k.ends_with("_RUNNER"))
    })
}

/// `MADV_WIPEONFORK` enforcement: a forked child must see a zeroed page, not
/// a copy of the secret. Without it, fork() hands the child an *unlocked*
/// copy-on-write copy of the secret that can be swapped or dumped.
///
/// The parent holds a read guard across the fork so the page is readable in
/// both processes; the child inspects its copy and reports through its exit
/// code. The child only calls async-signal-safe things (volatile reads,
/// `_exit`) because forking a threaded test runner allows nothing more.
#[cfg(target_os = "linux")]
#[test]
fn forked_child_sees_wiped_secret() {
    if emulated_kernel() {
        eprintln!("skipping: qemu user-mode emulation does not reproduce fork/madvise semantics");
        return;
    }

    let mut secret = Secret::<32>::new_with(|buf| buf.fill(0xAB)).unwrap();
    let view = secret.read().unwrap(); // page readable across the fork
    let ptr = view.as_ptr();

    match unsafe { libc::fork() } {
        0 => {
            // Child: every byte must be zero. Exit 0 on success, 42 if any
            // secret byte survived the fork.
            for i in 0..32 {
                if unsafe { std::ptr::read_volatile(ptr.add(i)) } != 0 {
                    unsafe { libc::_exit(42) };
                }
            }
            unsafe { libc::_exit(0) };
        }
        pid if pid > 0 => {
            let mut status = 0;
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            assert_eq!(waited, pid, "waitpid failed");
            assert!(
                libc::WIFEXITED(status),
                "child did not exit normally: {status}"
            );
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "forked child must see a kernel-zeroed page, not the secret"
            );
            // Parent's own copy is untouched.
            drop(view);
            assert_eq!(secret.read().unwrap()[0], 0xAB);
        }
        _ => panic!("fork failed"),
    }
}

/// Zero-sized secrets are rejected up front with a clear error instead of a
/// raw EINVAL surfacing from mmap.
#[test]
fn zero_sized_secret_is_rejected() {
    let result = Secret::<0>::new_with(|_| {});
    let err = result.err().expect("Secret::<0> must be rejected");
    assert_eq!(err.inner().kind(), std::io::ErrorKind::InvalidInput);
}

/// Ask the kernel, not the crate: /proc/self/smaps reports per-mapping
/// VmFlags, so we can verify the secret's page really carries the
/// protections we claim to configure — `lo` (mlocked), `dd` (excluded from
/// core dumps), `wf` (wiped on fork). If a refactor ever drops one of the
/// madvise/mlock calls, this fails even though every functional test passes.
#[cfg(target_os = "linux")]
#[test]
fn kernel_reports_locked_nodump_wipeonfork_flags() {
    if emulated_kernel() {
        eprintln!("skipping: /proc maps under qemu describe the emulator, not the guest");
        return;
    }

    let mut secret = Secret::<32>::new_with(|b| b.fill(1)).unwrap();
    let view = secret.read().unwrap();
    let addr = view.as_ptr() as usize;

    let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let flags = vm_flags_for(&smaps, addr).expect("secret page not found in smaps");

    for (flag, meaning) in [
        ("lo", "mlock (never swapped)"),
        ("dd", "MADV_DONTDUMP (excluded from core dumps)"),
        ("wf", "MADV_WIPEONFORK (zeroed in forked children)"),
    ] {
        assert!(
            flags.contains(&flag.to_string()),
            "kernel does not report `{flag}` ({meaning}) on the secret page; VmFlags = {flags:?}"
        );
    }
}

/// Watch the guard state machine through the kernel's eyes: the mapping's
/// permission bits in /proc/self/maps must read `---p` while sealed, `r--p`
/// under a read guard, `rw-p` under a write guard, and return to `---p`
/// after every guard drops.
#[cfg(target_os = "linux")]
#[test]
fn kernel_reports_permission_transitions() {
    if emulated_kernel() {
        eprintln!("skipping: /proc maps under qemu describe the emulator, not the guest");
        return;
    }

    let mut secret = Secret::<32>::new_with(|b| b.fill(1)).unwrap();

    let addr = {
        let view = secret.read().unwrap();
        let addr = view.as_ptr() as usize;
        assert_eq!(perms_for(addr).as_deref(), Some("r--p"), "read guard open");
        addr
    };
    assert_eq!(
        perms_for(addr).as_deref(),
        Some("---p"),
        "after read guard drop"
    );

    {
        let _w = secret.write().unwrap();
        assert_eq!(perms_for(addr).as_deref(), Some("rw-p"), "write guard open");
    }
    assert_eq!(
        perms_for(addr).as_deref(),
        Some("---p"),
        "after write guard drop"
    );

    // Opening a guard on one secret must not unseal another.
    let mut other = Secret::<32>::new_with(|b| b.fill(2)).unwrap();
    let other_addr = {
        let v = other.read().unwrap();
        v.as_ptr() as usize
    };
    let _view = secret.read().unwrap();
    assert_eq!(
        perms_for(other_addr).as_deref(),
        Some("---p"),
        "unrelated secret must stay sealed while another is read"
    );
}

/// Concurrency stress: many threads creating, writing, reading, and dropping
/// their own secrets at once. Every thread must always observe exactly its
/// own bytes — no cross-page interference, no protection-state races.
#[test]
fn concurrent_secrets_never_interfere() {
    let handles: Vec<_> = (0u8..8)
        .map(|t| {
            std::thread::spawn(move || {
                for round in 0u8..50 {
                    let marker = t.wrapping_mul(31).wrapping_add(round);
                    let mut secret = Secret::<128>::new_with(|b| b.fill(marker)).unwrap();
                    {
                        let v = secret.read().unwrap();
                        assert!(v.iter().all(|&b| b == marker), "thread {t} round {round}");
                    }
                    {
                        let mut w = secret.write().unwrap();
                        w.fill(marker.wrapping_add(1));
                    }
                    let v = secret.read().unwrap();
                    assert!(v.iter().all(|&b| b == marker.wrapping_add(1)));
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

/// Find the VmFlags line of the smaps block covering `addr`.
#[cfg(target_os = "linux")]
fn vm_flags_for(smaps: &str, addr: usize) -> Option<Vec<String>> {
    let mut in_target_block = false;
    for line in smaps.lines() {
        if let Some((range, _)) = line.split_once(' ') {
            if let Some((start, end)) = range.split_once('-') {
                if let (Ok(s), Ok(e)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(end, 16),
                ) {
                    in_target_block = s <= addr && addr < e;
                }
            }
        }
        if in_target_block && line.starts_with("VmFlags:") {
            return Some(
                line.trim_start_matches("VmFlags:")
                    .split_whitespace()
                    .map(str::to_string)
                    .collect(),
            );
        }
    }
    None
}

/// Permission string (`r--p`, `---p`, ...) of the mapping covering `addr`.
#[cfg(target_os = "linux")]
fn perms_for(addr: usize) -> Option<String> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let range = fields.next()?;
        let perms = fields.next()?;
        if let Some((start, end)) = range.split_once('-') {
            if let (Ok(s), Ok(e)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            ) {
                if s <= addr && addr < e {
                    return Some(perms.to_string());
                }
            }
        }
    }
    None
}
