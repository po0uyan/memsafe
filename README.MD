<div align="center">

# 🔐 memsafe

### Locked, sealed, zero-on-drop memory for secrets.

Secrets live in a locked memory page: kept out of swap, excluded from core dumps (Linux),
inaccessible between uses (on Unix even your own process can't read it), never on the regular
heap, and volatile-wiped on drop. All behind one safe Rust type.

[![Crates.io](https://img.shields.io/crates/v/memsafe.svg)](https://crates.io/crates/memsafe)
[![docs.rs](https://img.shields.io/docsrs/memsafe)](https://docs.rs/memsafe)
[![CI](https://github.com/po0uyan/memsafe/actions/workflows/CI-CD.yml/badge.svg)](https://github.com/po0uyan/memsafe/actions/workflows/CI-CD.yml)
[![Downloads](https://img.shields.io/crates/d/memsafe.svg)](https://crates.io/crates/memsafe)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

🐧 **Linux** &nbsp;·&nbsp; 🍎 **macOS** &nbsp;·&nbsp; 🪟 **Windows** &nbsp;·&nbsp; ⚙️ **other Unixes**
<br/><sub>CI-tested on **10 OS/architecture targets** — x86_64 · aarch64 · ARM · i686 · RISC-V · PowerPC</sub>

</div>

---

Dropping a `String` doesn't erase it. The bytes stay in the freed heap block, can get paged out to swap, and show up in core dumps. memsafe exists to close those paths:

```rust
use memsafe::Secret;

let mut api_key = Secret::<64>::new_with(|buf| {
    buf[..10].copy_from_slice(b"my-api-key");
}).unwrap();
```

```text
mmap ──▶ mlock ──▶ MADV_DONTDUMP ──▶ write in place ──▶ PROT_NONE
 page      pinned     excluded from      secret never       locked down
 alloc     in RAM     core dumps¹        touches the        until *you*
                                         heap or stack      read() it
```
<sub>¹ Linux only. See [platform notes](#platform-specific-notes) for what each OS actually provides.</sub>

| | plain `String` | `memsafe::Secret` |
|---|---|---|
| Swap under memory pressure | may be paged to disk | stays in RAM — page is `mlock`'d |
| Core dumps | included | excluded on Linux (`MADV_DONTDUMP`) |
| Inherited by `fork()` children | as-is | kernel-zeroed on Linux (`MADV_WIPEONFORK`) |
| While your code isn't using it | readable through any stray pointer | `PROT_NONE` on Unix — even your own process faults (`PAGE_READONLY` on Windows) |
| Bytes after drop | linger on the freed heap | volatile-zeroed + compiler-fenced |
| A stray `{:?}` in a log line | leaks it | does not compile |

A few facts for evaluating the crate: the public API needs no `unsafe` on your side, there are two platform-gated dependencies (`libc` / `winapi`), the test suite includes tests where the kernel itself verifies the sealing (a child process must die by SIGSEGV), and the [threat model](#threat-model) states what this crate does *not* protect against. In the wild: [spg](https://github.com/po0uyan/rust-secure-pass-gen), a CLI password generator, keeps every generated password in memsafe-protected pages.

**Contents** — [Quick start](#quick-start) · [Going deeper](#going-deeper) · [How it compares](#how-it-compares) · [Performance](#performance) · [Threat model](#threat-model) · [Platform notes](#platform-specific-notes) · [Under the hood](#under-the-hood) · [Roadmap](#roadmap)

---

## Quick start

```shell
cargo add memsafe
```

Store an API key, password, or token in a `Secret<N>`. `N` is the buffer size; unused bytes stay zero. The closure writes straight into protected memory — the same pattern reads directly from stdin or any `Read` source, so the secret never has to exist anywhere else:

```rust
use memsafe::Secret;

let mut secret = Secret::<64>::new_with(|buf| {
    buf[..10].copy_from_slice(b"my-api-key");
}).unwrap();

// The page is unlocked only while `view` is alive, re-sealed when it drops.
let view = secret.read().unwrap();
assert_eq!(&view[..10], b"my-api-key");
```

If the secret already sits in a `String` or `Vec<u8>`, hand it over — the source gets volatile-zeroed after the copy:

```rust
let key = b"my-api-key".to_vec();
let mut secret = Secret::<64>::from_bytes(key).unwrap();

// Or: let mut secret: Secret<64> = String::from("my-api-key").try_into().unwrap();
```

Construction can fail (buffer too small, `mlock` limit hit). The owned-input constructors give you the source back along with the error instead of eating it:

```rust
match Secret::<4>::try_from(String::from("way-too-long")) {
    Ok(_) => unreachable!(),
    Err((source, err)) => eprintln!("failed ({err}); got back {} bytes", source.len()),
}
```

If all you need is a secret guard, that's the whole API. The rest is detail.

---

## Going deeper

The crate exports two types:

| Type | Use it for |
|------|------------|
| **`Secret<N>`** | **Secrets.** Every constructor keeps all `N` bytes inline inside the protected page; the heap-pointer pitfall is unrepresentable. |
| **`MemSafe<T>`** | **Non-secret protected memory.** Any `T` that wants `mlock` + `mprotect` semantics. |

### `Secret<N>` constructors

| Constructor | Input | Source returned on error | Source zeroized |
|-------------|-------|--------------------------|-----------------|
| `new_with(F)` (`F: FnOnce(&mut [u8; N])`) | closure writes in place | N/A | N/A |
| `from_bytes(T)` (`T: AsMut<[u8]>`) | owned bytes | **yes**, with the error | **yes**, before drop |
| `TryFrom<String>` | owned `String` | **yes**, with the error | **yes** |
| `TryFrom<&str>` | borrowed | N/A — borrow stays yours | no (caller-managed) |

> `from_bytes` zeroes what `AsMut::as_mut` exposes — `len`, not `capacity`. Call `shrink_to_fit()` first if trailing capacity may hold earlier secret content, and prefer `new_with` over containers that ever grew while holding the secret (old reallocations are out of reach).

### `MemSafe<T>`

The lower-level building block: a protected region holding any `T`, accessed through `read()` / `write()` guards. No secret-handling machinery.

> **Why not `MemSafe<String>` for a password?** A `String` keeps its bytes on the regular heap; wrapping it protects only the 24-byte header. The secret stays swappable, dumpable, and unwiped. `Secret<N>` exists to make that mistake unrepresentable — it can only wrap `[u8; N]`.

### Type-state API

With the `type-state` feature (`cargo add memsafe --features type-state`), the buffer's access state lives in the type, so reading a no-access buffer is a *compile-time* error:

```rust
use memsafe::type_state::MemSafe;

let secret = MemSafe::new([0_u8; 32]).unwrap(); // no-access
let mut secret = secret.read_write().unwrap();  // now writable
secret[..4].copy_from_slice(b"data");
let secret = secret.read_only().unwrap();       // now read-only
```

`Secret<N>` doesn't have a type-state variant yet; issues and PRs welcome.

## How it compares

| Capability | [`zeroize`](https://crates.io/crates/zeroize) | [`secrecy`](https://crates.io/crates/secrecy) | [`memsec`](https://crates.io/crates/memsec) | [`region`](https://crates.io/crates/region) | `memsafe` |
|---|---|---|---|---|---|
| Elision-resistant zero-on-drop | ✅ | ✅ (via zeroize) | manual | — | ✅ automatic |
| Locked out of swap (`mlock`) | — | — | manual | manual | ✅ automatic |
| Page sealed between uses (`mprotect`) | — | — | manual | manual | ✅ automatic |
| Core-dump exclusion | — | — | via its `mlock` (Linux) | — | ✅ automatic (Linux) |
| Secret bytes kept off the global heap | — | — | your responsibility | your responsibility | ✅ by construction |
| Safe API (no `unsafe` for the caller) | ✅ | ✅ | ❌ | ✅ | ✅ |
| Source returned on constructor failure | — | — | — | — | ✅ |

These combine well rather than compete: `zeroize`/`secrecy` for secrets in ordinary structs, `memsec`/`region` for building your own container, memsafe when you want the container already built.

## Performance

Construction is about five syscalls; every guard cycle is two `mprotect` calls. Measured with the criterion benches in [`benches/`](benches/memsafe_bench.rs) (Apple Silicon, release build) — `cargo bench` reproduces this table on your machine:

| Operation | with memsafe | plain heap (`Vec<u8>`) |
|---|---|---|
| Create + drop a 64 B secret | ~2.8 µs | ~9.5 ns |
| Create + drop a 4 KiB secret | ~3.8 µs | — |
| Ingest a `Vec` (`from_bytes`, 64 B) | ~2.9 µs | — |
| Read access (unseal, read, reseal) | ~1.1 µs | ~0.35 ns |
| Write access (unseal, write, reseal) | ~1.1 µs | — |

For credentials and keys this is noise. For a hot loop it isn't: take one guard and do the batch inside it rather than opening a guard per operation. Each secret also occupies a full page (typically 4 KiB) and counts against `RLIMIT_MEMLOCK`, so the number of live secrets is bounded, not their size.

## Threat model

We list this explicitly because vague "secure" claims are how secrets get leaked.

**Designed to defend against:**

- Secrets reaching disk via swap (`mlock` / `VirtualLock`).
- Secrets in Linux core dumps (`MADV_DONTDUMP`).
- A forked child inheriting an unlocked copy of the secret — **Linux only**, via `MADV_WIPEONFORK`.
- The allocator handing freed-but-unwiped bytes to a later caller (zero-on-drop; the secret never routes through the global allocator).
- Reads or writes while the buffer is logically inactive (`mprotect` between operations).
- Owned sources silently left on the heap after ingestion (`from_bytes` volatile-zeroizes them).
- The wrong-wrapper mistake — `MemSafe<String>` protecting only a header (`Secret<N>` makes it unrepresentable).

**NOT defended against:**

- Anything with your privileges or more: `ptrace`, a debugger, root. OS protection ends at the process boundary.
- **Hibernation.** The suspend-to-disk image contains all of RAM, `mlock`'d pages included. Pair with encrypted swap or full-disk encryption.
- **`fork()` on non-Linux Unixes** — the child gets an unlocked copy-on-write copy; construct secrets after forking there.
- Side channels (cache timing, speculation, power analysis) and bytes left in registers or spill slots — protection is page-level, not microarchitectural.
- Physical attackers: cold boot, DMA, RowHammer.

If your threat model includes the second list, memsafe is defense in depth, not sufficient on its own.

## Platform-specific notes

- **`mlock` limits.** Unprivileged Linux processes get `RLIMIT_MEMLOCK` (often 64 KiB). Each allocation rounds up to a page, so a handful of secrets fit; thousands need a raised limit.
- **Linux-only protections.** Dump exclusion and fork-wiping are Linux-only; macOS, the BSDs, and Windows have no equivalent here yet.
- **Windows floor is `PAGE_READONLY`.** Reads through a stale pointer are always possible on Windows; only writes are guarded. Unix uses `PROT_NONE`, blocking both.
- **No feature flags to pick.** `libc` on `cfg(unix)`, `winapi` on `cfg(windows)`; the right backend is selected automatically.

## Under the hood

- **Allocate and lock.** `mmap(MAP_PRIVATE | MAP_ANONYMOUS)` / `VirtualAlloc`, pinned with `mlock` / `VirtualLock`; on Linux additionally `MADV_DONTDUMP` and `MADV_WIPEONFORK`. (`mlock` prevents swapping, not hibernation — see the threat model.)
- **Access transitions.** Every `read()` / `write()` elevates the page with `mprotect` / `VirtualProtect` and re-seals it when the guard drops. The `type-state` feature lifts this into the type system.
- **In-place initialization.** `new_with` hands the closure a `&mut [u8; N]` pointing inside the locked region, so the secret never exists in a stack temporary or on the heap.
- **Panic-safe construction.** An internal rollback guard volatile-zeroes, unlocks, and unmaps the page if setup fails or the `init` closure panics.
- **Wipes that can't be optimized out.** Source zeroization and drop-time wiping are byte-wise `write_volatile` plus `compiler_fence(SeqCst)` — a language-level guarantee, independent of the syscalls around it.

## Roadmap

- **`fork()` hygiene beyond Linux.** `minherit(INHERIT_ZERO)` on the BSDs where available.
- **Closure-based access API**, so the page provably re-seals when the closure returns.
- **Guard pages** around the region to turn overruns into immediate faults.
- **Windows core-dump exclusion** (minidumps).
- **In-memory encryption at rest**, decrypting only inside `read()` / `write()`.
- **Anti-debugging hooks**, **constant-time access paths**, **custom allocator** with randomized placement.

See the [Milestones](https://github.com/po0uyan/memsafe/milestones) for live status.

## Security notice

memsafe is designed against the threat model above and has not undergone a formal third-party security audit. Review the threat model against your own requirements before relying on it. Bug reports and security findings are very welcome.

## Contributing

Issues and pull requests are welcome at [github.com/po0uyan/memsafe](https://github.com/po0uyan/memsafe).

```shell
cargo test                              # default features
cargo test --features type-state       # compile-time state machine
cargo clippy --all-targets             # lints (includes benches)
```

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.
