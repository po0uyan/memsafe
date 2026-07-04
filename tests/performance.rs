//! Performance smoke tests.
//!
//! These are not benchmarks — `benches/` has criterion for real numbers.
//! The bounds here are set an order of magnitude above what commodity
//! hardware does, so they stay quiet through normal variance and only fail
//! on pathological regressions: an accidental allocation per read, a leaked
//! page per construction, a syscall storm.

use memsafe::Secret;
use std::time::Instant;

/// True under the cross/qemu CI targets, where syscall overhead is not
/// representative of any real deployment.
fn emulated_kernel() -> bool {
    std::env::vars().any(|(k, _)| {
        k == "QEMU_LD_PREFIX"
            || k == "CROSS_RUNNER"
            || (k.starts_with("CARGO_TARGET_") && k.ends_with("_RUNNER"))
    })
}

#[test]
fn construction_throughput_smoke() {
    const OPS: u32 = 500;
    let start = Instant::now();
    for _ in 0..OPS {
        let secret = Secret::<256>::new_with(|b| b[..5].copy_from_slice(b"perf!")).unwrap();
        drop(secret);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "construction: {OPS} create+drop cycles in {elapsed:?} ({:?}/op)",
        elapsed / OPS
    );
    if emulated_kernel() {
        return;
    }
    // Typical: well under 50ms total. Budget: 15s.
    assert!(
        elapsed.as_secs() < 15,
        "construction throughput collapsed: {OPS} ops took {elapsed:?}"
    );
}

#[test]
fn read_guard_cycle_smoke() {
    const OPS: u32 = 10_000;
    let mut secret = Secret::<64>::new_with(|b| b.fill(7)).unwrap();
    let start = Instant::now();
    for _ in 0..OPS {
        let view = secret.read().unwrap();
        assert_eq!(view[0], 7);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "read guard: {OPS} unseal+read+reseal cycles in {elapsed:?} ({:?}/op)",
        elapsed / OPS
    );
    if emulated_kernel() {
        return;
    }
    // Two mprotect calls per cycle; typically tens of ms total. Budget: 15s.
    assert!(
        elapsed.as_secs() < 15,
        "read-guard cycle collapsed: {OPS} ops took {elapsed:?}"
    );
}

#[test]
fn write_guard_cycle_smoke() {
    const OPS: u32 = 10_000;
    let mut secret = Secret::<64>::new_with(|_| {}).unwrap();
    let start = Instant::now();
    for i in 0..OPS {
        let mut w = secret.write().unwrap();
        w[0] = i as u8;
    }
    let elapsed = start.elapsed();
    eprintln!(
        "write guard: {OPS} unseal+write+reseal cycles in {elapsed:?} ({:?}/op)",
        elapsed / OPS
    );
    if emulated_kernel() {
        return;
    }
    assert!(
        elapsed.as_secs() < 15,
        "write-guard cycle collapsed: {OPS} ops took {elapsed:?}"
    );
}

#[test]
fn from_bytes_throughput_smoke() {
    const OPS: u32 = 500;
    let start = Instant::now();
    for _ in 0..OPS {
        let secret = Secret::<64>::from_bytes(b"0123456789abcdef".to_vec()).unwrap();
        drop(secret);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "from_bytes: {OPS} ingest+drop cycles in {elapsed:?} ({:?}/op)",
        elapsed / OPS
    );
    if emulated_kernel() {
        return;
    }
    assert!(
        elapsed.as_secs() < 15,
        "from_bytes throughput collapsed: {OPS} ops took {elapsed:?}"
    );
}
