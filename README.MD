# memsafe

A small, OS-level container for secrets that should never touch the disk, the regular heap, or a core dump.

[![Crates.io](https://img.shields.io/crates/v/memsafe.svg)](https://crates.io/crates/memsafe)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This is the official `memsafe` crate, hosted on [GitHub](https://github.com/po0uyan/memsafe) and published on [crates.io](https://crates.io/crates/memsafe).

`memsafe` is a thin, deliberately-minimal abstraction over the OS primitives that production secret-handling code already reaches for: `mmap` + `mprotect` + `mlock` + `madvise(MADV_DONTDUMP)` on Unix, and `VirtualAlloc` + `VirtualProtect` + `VirtualLock` on Windows. You get a typed handle that returns the backing page to its lowest-privilege state between every operation, never lets secret bytes pass through the global allocator, and overwrites the bytes with zeros before the page is unmapped.

## At a glance

| Property | How it's enforced |
|----------|-------------------|
| Not paged to disk | `mlock` (Unix) / `VirtualLock` (Windows) on the backing page |
| Not in core dumps | `madvise(MADV_DONTDUMP)` — **Linux only** |
| Inaccessible between operations | `mprotect(PROT_NONE)` on Unix; `PAGE_READONLY` on Windows (the strictest level Windows offers in this model) |
| Zero-on-drop | `ptr::write_bytes` over the page immediately before `munmap` / `VirtualFree` |
| No allocator round-trip | Bytes are copied straight from the source into the protected page; they never reach the regular `malloc` heap |
| Source zeroization | `Secret::from_bytes(T)` volatile-overwrites the source byte slice before drop, for any `T: AsMut<[u8]>` |
| Recoverable on error | `Secret` constructors return the original source alongside the error so the caller can retry, inspect, or further zeroize it |
| Elision-resistant wipes | All zeroization is `write_volatile` + `compiler_fence(SeqCst)` — the optimizer cannot remove the wipe |
| In-place initialization | `Secret::new_with` lets a closure write straight into the protected page — the secret never visits a stack temporary or the regular heap |
| Heap-pointer pitfall unrepresentable | `Secret<N>` only ever wraps `[u8; N]` — by construction it is impossible to accidentally protect a header while leaving the payload on the unprotected heap |
| Compile-time access enforcement | Optional, behind the `type-state` feature |

## Usage

> **For secrets, use `Secret<N>`.** It is a thin newtype around `MemSafe<[u8; N]>` whose API is *only reachable* via constructors that keep every byte of the secret inside the protected page. By construction it is impossible to wrap a `String` or `Vec<u8>` and accidentally leave the payload on the regular heap — the wrapped type is `[u8; N]`, full stop. Use `MemSafe<T>` directly only for non-secret memory protection (e.g. guard pages around an allocation).

### Recommended: `Secret<N>` (compile-time-enforced inline storage)

```rust
use memsafe::Secret;

// In-place initialization — the secret never visits a stack temporary or the regular heap.
// The protected page is allocated, locked, dump-excluded, and OS-zeroed *before* the
// closure runs.
let mut secret = Secret::<256>::new_with(|buf| {
    // `buf` points directly into the protected page.
    buf[..10].copy_from_slice(b"my-api-key");
}).unwrap();

// Reading: returns a guard that derefs to `&[u8; N]` and drops back to lowest priv.
let view = secret.read().unwrap();
assert_eq!(&view[..10], b"my-api-key");
```

A common beginner pattern — read straight from a `Read` source into protected memory, with no `String` or `Vec` ever holding the secret:

```rust
use memsafe::Secret;
use std::io::Read;

let mut secret = Secret::<256>::new_with(|buf| {
    let _ = std::io::stdin().read(&mut buf[..]).unwrap();
}).unwrap();
```

From an owned byte source — the source is volatile-zeroed after the copy:

```rust
use memsafe::Secret;

let key = b"my-api-key".to_vec();
let mut secret = Secret::<64>::from_bytes(key).unwrap();

// Or via TryFrom — same recoverable error shape:
let mut secret: Secret<64> = String::from("my-api-key").try_into().unwrap();
```

When a constructor fails, the original source is handed back so the caller can recover, retry with a larger buffer, or apply their own zeroization:

```rust
use memsafe::Secret;

let too_long = String::from("way-too-long-to-fit-in-this-buffer");
match Secret::<4>::try_from(too_long) {
    Ok(_) => unreachable!(),
    Err((source, err)) => {
        eprintln!("could not encapsulate ({err}); got back {} bytes", source.len());
    }
}
```

| Constructor | Input | Source returned on error | Source zeroized |
|-------------|-------|--------------------------|-----------------|
| `Secret::<N>::new_with(F)` (`F: FnOnce(&mut [u8; N])`) | (closure writes in place) | N/A — no source | N/A — no source |
| `Secret::<N>::from_bytes(T)` (`T: AsMut<[u8]>`) | Owned bytes | **Yes**, with the error | **Yes** — `len` bytes overwritten before drop |
| `<Secret<N> as TryFrom<String>>::try_from` | Owned `String` | **Yes**, with the error | **Yes** — via `from_bytes` on `into_bytes()` |
| `<Secret<N> as TryFrom<&str>>::try_from` | Borrowed | N/A — borrow returned to caller | No (caller-managed) |

> **Capacity vs. length on `Vec` / `String`.** `from_bytes` only zeroes the bytes exposed by `AsMut::as_mut`, which is `len`, not `capacity`. If your `Vec` or `String` has unused trailing capacity that may have held earlier secret content, call `shrink_to_fit()` before passing it in.

### `MemSafe<T>` — the general-purpose protected container

`MemSafe<T>` is the lower-level building block: a protected memory region holding any `T`. It does **not** carry the secret-handling machinery — no `from_bytes`, no `TryFrom`, no source zeroization. Use it for non-secret protected memory (FFI scratch buffers, guard pages, anything where you want `mlock` + `mprotect` semantics on a non-secret value).

```rust
use memsafe::MemSafe;

// allocate protected memory holding any value
let mut buffer = MemSafe::new([0_u8; 32]).unwrap();

{
    let mut write = buffer.write().unwrap();
    write[..14].copy_from_slice(b"working-buffer");
}
{
    let read = buffer.read().unwrap();
    println!("data: {:02X?}", *read);
}
```

> **Why not just use `MemSafe<String>` for a password?** A `String` keeps its bytes on the regular `malloc` heap. Wrapping it in `MemSafe` only places the 24-byte header (pointer + length + capacity) inside the protected page; the actual secret bytes still live on the unprotected heap — swappable, dump-able, and not zeroed when the allocation is freed. **`Secret<N>` exists precisely to make that misuse impossible** — it can only ever wrap `[u8; N]`, which has no indirection.

### Type-state API (compile-time enforced access)

If you'd like the buffer's access state to be enforced by the type system rather than at runtime, enable the `type-state` feature:

```bash
cargo add memsafe --features type-state
```

```rust
use memsafe::type_state::MemSafe;

// initialize a 32-byte buffer in no-access state
let secret = MemSafe::new([0_u8; 32]).unwrap();

// transition to read-write and write into it
let info = "my-secret-info";
let mut secret = secret.read_write().unwrap();
secret[..info.len()].copy_from_slice(info.as_bytes());

// transition to read-only and read from it
let secret = secret.read_only().unwrap();
println!("Secure data: {:02X?}", *secret);
```

> `Secret<N>` does not yet have a type-state variant — secret bytes go through the runtime-state `Secret` API regardless of the `type-state` feature. If you want compile-time-enforced access state on a secret, open an issue or PR; the building blocks (`Cell` + `type_state::MemSafe`) are already in place.

## Threat model

We list this explicitly because vague "secure" claims are how secrets get leaked.

**memsafe is designed to defend against:**

- Secrets being written to disk via swap or hibernation (mitigated by `mlock` / `VirtualLock`).
- Secrets appearing in a Linux core dump (mitigated by `madvise(MADV_DONTDUMP)`).
- The Rust / system allocator handing freed-but-not-zeroed bytes to a later caller (mitigated by zero-on-drop and by never routing the secret through the global allocator).
- Accidental reads or writes while the buffer is logically inactive (mitigated by `mprotect` / `VirtualProtect` between operations and, optionally, by the type-state API).
- The "owned bytes" case: the secret being silently left on the regular heap after the source is dropped (mitigated by `Secret::from_bytes`'s explicit volatile zeroization of the source slice before drop).
- The "wrong wrapper" case: a developer wrapping a `String` or `Vec<u8>` in `MemSafe` and unknowingly leaving the payload on the unprotected heap (mitigated structurally by `Secret<N>` — by construction it can only wrap `[u8; N]`, where the secret lives inline).

**memsafe does NOT defend against:**

- A process running with privilege equivalent to or greater than your own — for example, a debugger attached via `ptrace`, or root on the same machine. OS protection ends at the process boundary.
- Side-channel attacks (cache timing, Spectre/Meltdown-class speculation, power analysis, etc.).
- Bytes left behind in CPU registers, vector lanes, or temporary spill slots after a `copy_from_slice`. The protection is at the memory-page level, not the microarchitectural level.
- Hardware attackers with physical bus access, cold-boot capability, or DMA to the host.
- Hardware/microarchitectural attacks against zeroization itself: bytes evicted into cache lines that get speculatively read out, RowHammer, and similar. The crate's wipes are language-level (volatile + fence); the silicon is not in scope.

If your threat model includes any of the items in the second list, `memsafe` is a useful layer of defense in depth but is not sufficient on its own.

## Platform-specific notes

- **`mlock` limits.** On Linux, unprivileged processes are subject to `RLIMIT_MEMLOCK` (commonly 64 KiB by default). Each `MemSafe` allocation is rounded up to a full page (typically 4 KiB), so a handful of secrets fit easily inside the default limit; allocating thousands may require raising the limit. macOS has its own per-process locked-memory caps.
- **Page rounding.** `mmap` and `VirtualAlloc` allocate in page-sized units (typically 4 KiB). A `MemSafe<[u8; 32]>` therefore consumes a full page; the trailing bytes of the page are part of the same locked, access-controlled, zero-on-drop region.
- **Linux-only protections.** `madvise(MADV_DONTDUMP)` is Linux-only. macOS, the BSDs, and Windows do not currently have an equivalent in this crate; on those systems, the page may still appear in process dumps. Windows core-dump exclusion is on the [Roadmap](#roadmap).
- **Windows access model.** Windows lacks an exact `PROT_NONE` analogue in this crate's model — the lowest-privilege state is `PAGE_READONLY`. This means reads through the protected handle are *always* possible on Windows; only writes are guarded behind `write()` / `read_write()`. Unix systems use `PROT_NONE` between operations, blocking both reads and writes.
- **Windows core dumps.** Pages are not currently excluded from minidumps on Windows.

## Features

These are the runtime guarantees the crate ships today (the table at the top has the implementation hooks):

- **In-RAM lock** — backing page pinned with `mlock` (Unix) or `VirtualLock` (Windows), so it can't be paged to disk or written to a hibernation file.
- **Default-deny access** — `PROT_NONE` on Unix, `PAGE_READONLY` on Windows, between every read and write.
- **Volatile, fenced zero-on-drop** — `write_volatile` + `compiler_fence(SeqCst)` over the full page before it's released to the OS. Optimizer cannot elide.
- **Core-dump exclusion (Linux)** — `madvise(MADV_DONTDUMP)`.
- **Dedicated `Secret<N>` type** — by construction it only wraps `[u8; N]`, so the heap-pointer pitfall (`MemSafe<String>`, `MemSafe<Vec<u8>>`) is unrepresentable. Carries `new_with` (in-place init, no stack temporary), `from_bytes` (volatile-zeros the owned source), and `TryFrom<&str>` / `TryFrom<String>`.
- **Recoverable construction errors** — `Secret`'s owned-input constructors return the source alongside the error so the caller can retry, inspect, or apply their own zeroization.
- **Optional compile-time access state machine** — `NoAccess` / `ReadOnly` / `ReadWrite` markers on `MemSafe<T>`, enabled by the `type-state` feature.
- **Cross-platform** — `libc` on `cfg(unix)`, `winapi` on `cfg(windows)`. The right backend is selected automatically; consumers do not pick a feature flag.

## Installation

```shell
cargo add memsafe
```

For the optional compile-time state machine:

```bash
cargo add memsafe --features type-state
```

## Security Mechanisms: A Deep Dive for Technical Enthusiasts

The following points describe the implementation behind each guarantee.

- **Allocation and locking.** Each `MemSafe<T>` instance allocates one or more pages via `mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)` on Unix or `VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)` on Windows. The page is then pinned with `mlock` / `VirtualLock` so the kernel cannot page it out to swap or include it in a hibernation file. On Linux, `madvise(MADV_DONTDUMP)` additionally tells the kernel to omit the page from any core dump produced for the process.

- **Access transitions.** All access to the backing page goes through the `Cell` abstraction, which calls `mprotect` (Unix) or `VirtualProtect` (Windows) to elevate the page to `PROT_READ` / `PAGE_READONLY` for reads and `PROT_READ | PROT_WRITE` / `PAGE_READWRITE` for writes. As soon as the temporary access guard is dropped, the page is restored to its lowest-privilege state (`PROT_NONE` on Unix, `PAGE_READONLY` on Windows). The `type-state` feature lifts this state machine into the type system, so an attempt to read a buffer that is currently in a writeable state — or to write through a read-only handle — is a compile-time error.

- **In-place initialization avoids a stack copy.** `Secret::<N>::new_with(|buf| ...)` allocates the protected page first, then hands the closure a `&mut [u8; N]` that points *inside* the locked region. The secret bytes are written directly into protected memory; they never live in a stack-allocated `[u8; N]` that the compiler would otherwise leave behind in the calling frame. This is the recommended path for "secure-from-the-start" initialization (e.g. reading a password straight out of a `Read` source).

- **Source zeroization for `Secret::from_bytes`.** After copying the source bytes into the protected page, `from_bytes` walks the source slice (everything `AsMut::as_mut` exposes) and overwrites every byte with `ptr::write_volatile(0)`, followed by a `compiler_fence(Ordering::SeqCst)`. The compiler is forbidden from eliding volatile stores, and the fence prevents the wipe from being sunk past later code. On a memory-protection error the zeroization has already run; on a length-mismatch error the source is returned untouched so the caller can decide what to do with it.

- **Drop-time zeroization is volatile and fenced.** The `Drop` implementation re-elevates the page to read/write, runs `drop_in_place` on the contents, overwrites the page byte-by-byte with `write_volatile`, emits a `compiler_fence(SeqCst)`, releases the lock with `munlock` / `VirtualUnlock`, and finally returns the page to the OS with `munmap` / `VirtualFree`. The volatile + fence guarantee is language-level — independent of whether the following syscall acts as an opaque barrier. The same primitive is used to wipe `Cell::new`'s moved-in value on the caller's stack slot.

- **Heap-pointer footgun is structurally prevented.** `Secret<N>` is a newtype over `MemSafe<[u8; N]>`. Its `new_with`, `from_bytes`, `TryFrom<&str>`, and `TryFrom<String>` constructors all produce inline byte storage; there is no way to instantiate a `Secret` whose payload lives behind an indirection. `MemSafe<T>` itself remains generic (you can still `MemSafe::new(some_struct)` for non-secret protected memory), but secret handling is gated through `Secret<N>` exclusively.

- **Cross-platform compatibility.** Conditional compilation via `#[cfg(unix)]` and `#[cfg(windows)]` isolates platform-specific code. `libc` is pulled in only on `cfg(unix)` and `winapi` only on `cfg(windows)` via `[target.'cfg(...)'.dependencies]` in `Cargo.toml`, so consumers do not pick a feature flag — the correct backend is selected automatically. CI runs the test suite on a matrix that includes Linux (x86_64, aarch64, i686, armv7, ppc64le, riscv64), macOS (x86_64, aarch64), and Windows (x86_64, i686), with both default and `type-state` feature variants.

## Roadmap

Planned hardening work, roughly in priority order:

- **Closure-based access API.** Replace `read()` / `write()` guards with `read(|r| ...)` / `write(|w| ...)` closures, so the page is provably returned to its lowest-privilege state when the closure returns.
- **Guard pages.** Allocate adjacent inaccessible pages around the protected region to turn over- and under-runs into immediate faults.
- **Pre-allocation zeroing.** Zero the freshly-`mmap`'d page before writing the secret into it, defending against any kernel-supplied non-zero contents in edge cases.
- **Windows core-dump exclusion.** Mark protected pages so they are omitted from minidumps.
- **In-memory encryption at rest.** Encrypt the page contents while the buffer is in its lowest-privilege state, decrypting only inside `read()` / `write()`. Defense in depth against attackers who can read the process's memory.
- **Anti-debugging hooks.** Detect or refuse `ptrace` / debugger attachment.
- **Side-channel mitigation.** Constant-time read/write paths to resist timing and speculative-execution attacks.
- **Custom allocator.** Randomized placement and integrity checks to obscure memory locations.

See the [Milestones](https://github.com/po0uyan/memsafe/milestones) for live status.

## Repository

- **Source:** [https://github.com/po0uyan/memsafe](https://github.com/po0uyan/memsafe)

## Security Notice

`memsafe` is designed against the threat model documented above and has not undergone a formal third-party security audit. We recommend reviewing the [Threat model](#threat-model) section against your own requirements before relying on this crate for sensitive data. Bug reports and security findings are very welcome — please open an issue or a PR.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Issues and pull requests are welcome at [https://github.com/po0uyan/memsafe](https://github.com/po0uyan/memsafe). I'm happy to merge enhancements, security fixes, and any work that pushes the crate closer to the items on the [Roadmap](#roadmap).