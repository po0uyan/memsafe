//! Criterion benchmarks. Run with `cargo bench`.
//!
//! Every memsafe operation costs syscalls by design (mmap/mlock/madvise on
//! construction, two mprotect per guard cycle), so the interesting numbers
//! are the per-operation overhead and how it compares to an unprotected
//! heap buffer. The `baseline_*` benches exist for that comparison.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use memsafe::Secret;

fn construction(c: &mut Criterion) {
    let mut g = c.benchmark_group("construction");
    g.bench_function("secret_new_with_64B", |b| {
        b.iter(|| Secret::<64>::new_with(|buf| buf[..10].copy_from_slice(b"my-api-key")).unwrap())
    });
    g.bench_function("secret_new_with_4KiB", |b| {
        b.iter(|| Secret::<4096>::new_with(|buf| buf.fill(0xAB)).unwrap())
    });
    g.bench_function("secret_from_bytes_64B", |b| {
        b.iter(|| Secret::<64>::from_bytes(black_box(b"my-api-key".to_vec())).unwrap())
    });
    // Unprotected equivalent, for scale: how much does the protection cost?
    g.bench_function("baseline_vec_64B", |b| {
        b.iter(|| {
            let mut v = vec![0u8; 64];
            v[..10].copy_from_slice(black_box(b"my-api-key"));
            v
        })
    });
    g.finish();
}

fn access(c: &mut Criterion) {
    let mut g = c.benchmark_group("access");

    let mut secret = Secret::<64>::new_with(|b| b.fill(7)).unwrap();
    g.bench_function("read_guard_cycle", |b| {
        b.iter(|| {
            let view = secret.read().unwrap();
            black_box(view[0])
        })
    });

    let mut secret_w = Secret::<64>::new_with(|_| {}).unwrap();
    g.bench_function("write_guard_cycle", |b| {
        b.iter(|| {
            let mut w = secret_w.write().unwrap();
            w[0] = black_box(1);
        })
    });

    // Unprotected equivalent, for scale.
    let plain = [7u8; 64];
    g.bench_function("baseline_vec_read", |b| b.iter(|| black_box(plain[0])));
    g.finish();
}

criterion_group!(benches, construction, access);
criterion_main!(benches);
