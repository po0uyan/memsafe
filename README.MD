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
| Source zeroization | `MemSafe::<[u8; N]>::from_string(String)` overwrites the source `String`'s full heap capacity before drop |
| Compile-time access enforcement | Optional, behind the `type-state` feature |

## Usage

### A raw byte buffer

```rust
use memsafe::MemSafe;

// allocate protected memory
let mut secret = MemSafe::new([0_u8; 32]).unwrap();

// write into protected memory
{
    let mut write = secret.write().unwrap();
    write[..14].copy_from_slice("my-secret-info".as_bytes());
}

// read from protected memory
{
    let read = secret.read().unwrap();
    println!("Secure data: {:02X?}", *read);
}
```

### A string-shaped secret (API key, password, token)

The string constructors copy bytes directly into a fixed-size buffer that lives entirely inside the protected page. No `String`, no heap detour.

```rust
use memsafe::MemSafe;
use std::str::FromStr;

// from a borrowed slice (e.g. a literal)
let mut secret: MemSafe<[u8; 64]> = MemSafe::from_str("my-api-key").unwrap();

// or via .parse()
let mut secret: MemSafe<[u8; 64]> = "my-api-key".parse().unwrap();

// or via TryFrom
let mut secret: MemSafe<[u8; 64]> = "my-api-key".try_into().unwrap();

// from an owned String — the source's heap is zeroized before drop
let api_key = std::env::var("API_KEY").unwrap();
let mut secret: MemSafe<[u8; 128]> = MemSafe::from_string(api_key).unwrap();
```

> **Why a fixed-size `[u8; N]` and not `MemSafe<String>`?** A `String` keeps its bytes on the regular `malloc` heap. Wrapping it in `MemSafe` only places the 24-byte header (pointer + length + capacity) inside the protected page; the actual secret bytes still live on the unprotected heap — swappable, dump-able, and not zeroed when the allocation is freed. Copying into `[u8; N]` keeps every byte of the secret inside the locked, protected page.

| Constructor | Source | Source zeroized |
|-------------|--------|-----------------|
| `MemSafe::<[u8; N]>::from_str(&str)` / `.parse()` / `TryFrom<&str>` | Borrowed | No (caller-managed) |
| `MemSafe::<[u8; N]>::from_string(String)` / `TryFrom<String>` | Owned `String` | **Yes** — full capacity overwritten with zeros before drop |

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

The same string constructors are available on the type-state API:

```rust
use memsafe::type_state::MemSafe;

let secret = MemSafe::<[u8; 64]>::from_string(String::from("my-api-key"))
    .unwrap()
    .read_only()
    .unwrap();
```

## Threat model

We list this explicitly because vague "secure" claims are how secrets get leaked.

**memsafe is designed to defend against:**

- Secrets being written to disk via swap or hibernation (mitigated by `mlock` / `VirtualLock`).
- Secrets appearing in a Linux core dump (mitigated by `madvise(MADV_DONTDUMP)`).
- The Rust / system allocator handing freed-but-not-zeroed bytes to a later caller (mitigated by zero-on-drop and by never routing the secret through the global allocator).
- Accidental reads or writes while the buffer is logically inactive (mitigated by `mprotect` / `VirtualProtect` between operations and, optionally, by the type-state API).
- The "owned `String`" case: the secret being silently left in the regular heap after the source is dropped (mitigated by `from_string`'s explicit pre-drop zeroization of the full source capacity).

**memsafe does NOT defend against:**

- A process running with privilege equivalent to or greater than your own — for example, a debugger attached via `ptrace`, or root on the same machine. OS protection ends at the process boundary.
- Side-channel attacks (cache timing, Spectre/Meltdown-class speculation, power analysis, etc.).
- Bytes left behind in CPU registers, vector lanes, or temporary spill slots after a `copy_from_slice`. The protection is at the memory-page level, not the microarchitectural level.
- Hardware attackers with physical bus access, cold-boot capability, or DMA to the host.
- Pathological compiler elision of the zeroization. The current implementation uses `ptr::write_bytes` followed immediately by a `munmap` / `VirtualFree` syscall; in practice no production compiler elides a write that is followed by an opaque syscall on the same address, but this is not a language-level guarantee. A future release will move to a volatile-write / compiler-fence pattern (see [Roadmap](#roadmap)).

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
- **Zero-on-drop** — `ptr::write_bytes` over the full page before it's released to the OS.
- **Core-dump exclusion (Linux)** — `madvise(MADV_DONTDUMP)`.
- **Source-aware string constructors** — `FromStr`, `from_string`, and `TryFrom` for `MemSafe<[u8; N]>`. The `from_string` variant zeroizes the source `String`'s full heap capacity before drop.
- **Optional compile-time access state machine** — `NoAccess` / `ReadOnly` / `ReadWrite` markers, enabled by the `type-state` feature.
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

- **No allocator round-trip for `[u8; N]`.** `Cell::new(value)` writes the value directly into the `mmap`'d page using a raw `ptr::write`, then zero-fills the original stack slot. Storing your secret as `MemSafe<[u8; N]>` (rather than `MemSafe<String>` or `MemSafe<Vec<u8>>`) therefore guarantees the bytes never visit the regular `malloc` heap. `from_string` honors this by copying the bytes from the source `String` into a stack-allocated `[u8; N]` and then handing that array to `Cell::new`.

- **Source zeroization for `from_string`.** Before the source `String` is dropped, `from_string` writes zeros across the full `capacity()` of the `String`'s heap allocation via `ptr::write_bytes`. This closes the gap that would otherwise exist: a freshly-freed-but-still-populated heap region holding the secret, sitting in the allocator's free list waiting to be handed back out. The zeroization runs on both the success path and the "input too long" error path.

- **Drop-time zeroization.** The `Drop` implementation re-elevates the page to read/write, runs `drop_in_place` on the contents, overwrites the page with zeros via `ptr::write_bytes`, releases the lock with `munlock` / `VirtualUnlock`, and finally returns the page to the OS with `munmap` / `VirtualFree`. The `munmap` / `VirtualFree` call is an opaque syscall on the same address the compiler just wrote zeros to, which in current compilers is sufficient to prevent dead-store elimination of the zeroization. A volatile-write / compiler-fence pattern is on the [Roadmap](#roadmap) to make this guarantee language-level rather than compiler-incidental.

- **Cross-platform compatibility.** Conditional compilation via `#[cfg(unix)]` and `#[cfg(windows)]` isolates platform-specific code. `libc` is pulled in only on `cfg(unix)` and `winapi` only on `cfg(windows)` via `[target.'cfg(...)'.dependencies]` in `Cargo.toml`, so consumers do not pick a feature flag — the correct backend is selected automatically. CI runs the test suite on a matrix that includes Linux (x86_64, aarch64, i686, armv7, ppc64le, riscv64), macOS (x86_64, aarch64), and Windows (x86_64, i686), with both default and `type-state` feature variants.

## Roadmap

Planned hardening work, roughly in priority order:

- **Volatile / fenced zeroization.** Replace `ptr::write_bytes` in `Drop` and `from_string` with `ptr::write_volatile` plus `compiler_fence(Ordering::SeqCst)`, so zeroization is guaranteed against compiler elision rather than relying on the following syscall as a barrier.
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