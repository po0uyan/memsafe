<div align="center">

# 🔐 memsafe

## One of the most hardened memory guards in the Rust ecosystem.

**Five layers of OS-level armor around every secret byte** — locked in RAM, kept out of swap
and core dumps, sealed against reads *even from your own process*, never touching the heap,
and provably wiped on drop.

**One safe type. Zero configuration. Almost every platform Rust runs on.**

[![Crates.io](https://img.shields.io/crates/v/memsafe.svg)](https://crates.io/crates/memsafe)
[![docs.rs](https://img.shields.io/docsrs/memsafe)](https://docs.rs/memsafe)
[![CI](https://github.com/po0uyan/memsafe/actions/workflows/CI-CD.yml/badge.svg)](https://github.com/po0uyan/memsafe/actions/workflows/CI-CD.yml)
[![Downloads](https://img.shields.io/crates/d/memsafe.svg)](https://crates.io/crates/memsafe)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

🐧 **Linux** &nbsp;·&nbsp; 🍎 **macOS** &nbsp;·&nbsp; 🪟 **Windows** &nbsp;·&nbsp; ⚙️ **any Unix**
<br/><sub>CI-proven on **10 OS/architecture targets** — x86_64 · aarch64 · ARM · i686 · RISC-V · PowerPC</sub>

</div>

---

The password you `drop()` doesn't die: its bytes linger in freed heap blocks, get paged to swap, and show up in core dumps. `memsafe` gives it armor instead — one call runs the full protection pipeline that production secret stores build by hand:

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
<sub>¹ Linux. See [platform notes](#platform-specific-notes) for exactly what each OS gets — we don't claim what an OS can't deliver.</sub>

### The life of your secret

| | in a plain `String` | in a `memsafe::Secret` |
|---|---|---|
| Swapped to disk under memory pressure | 😬 whenever the kernel feels like it | 🔒 never — page is `mlock`'d in RAM |
| Visible in a core dump | 😬 yes | 🙈 excluded on Linux (`MADV_DONTDUMP`) |
| Readable while your code isn't using it | 😬 by any stray pointer or overflow | 🚫 page is `PROT_NONE` (Unix) — even *your own process* faults on access |
| Bytes after drop | 😬 linger on the freed heap | 🧹 volatile-zeroed + compiler-fenced — the optimizer can't skip the wipe |
| Leaked by a stray `{:?}` in a log line | 😬 trivially | 🤐 `Secret` has no `Debug`, no `Display` |

**Why you can trust it:** a public API with zero `unsafe` for you to write, exactly two platform-gated dependencies (`libc` on Unix, `winapi` on Windows — nothing else), a CI matrix spanning Linux (x86_64, aarch64, i686, armv7, ppc64le, riscv64), macOS (x86_64, aarch64) and Windows (x86_64, i686), constructors that hand your data back instead of losing it on failure, and an [explicit threat model](#threat-model) that says out loud what we *don't* protect against.

**Contents** — [Quick start](#-quick-start-guard-a-secret-in-60-seconds) · [Going deeper](#-going-deeper-the-pro-path) · [What you get](#what-you-get) · [How it compares](#how-it-compares) · [Threat model](#threat-model) · [Platform notes](#platform-specific-notes) · [Under the hood](#under-the-hood) · [Roadmap](#roadmap)

---

## 🚀 Quick start: guard a secret in 60 seconds

```shell
cargo add memsafe
```

**Guard an API key, password, or token** with `Secret<N>` — pick `N` large enough for your secret; unused bytes stay zero:

```rust
use memsafe::Secret;

// Write the secret straight into protected memory — it never exists
// on the regular heap or in a stack temporary.
let mut secret = Secret::<64>::new_with(|buf| {
    buf[..10].copy_from_slice(b"my-api-key");
}).unwrap();

// Read it back through a guard. The page is unlocked only while
// `view` is alive, and re-sealed the moment it drops.
let view = secret.read().unwrap();
assert_eq!(&view[..10], b"my-api-key");
```

**Already have the secret in a `String` or `Vec<u8>`?** Hand it over — the source is volatile-zeroed after the copy, so no readable trace stays behind:

```rust
use memsafe::Secret;

let key = b"my-api-key".to_vec();
let mut secret = Secret::<64>::from_bytes(key).unwrap();

// Or via TryFrom:
let mut secret: Secret<64> = String::from("my-api-key").try_into().unwrap();
```

**Read a password without it ever touching a `String`:**

```rust
use memsafe::Secret;
use std::io::Read;

let mut secret = Secret::<256>::new_with(|buf| {
    let _ = std::io::stdin().read(&mut buf[..]).unwrap();
}).unwrap();
```

**And if construction fails, you don't lose your data.** Every owned-input constructor returns the source alongside the error, so you can retry with a bigger buffer or clean up on your own terms:

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

That's the whole onboarding. If all you need is a secret guard, you're done — `Secret<N>` defaults to the most protective behavior on every path. Everything below is for going deeper.

---

## 🔬 Going deeper: the pro path

Two types are exported, one per job:

| Type | Use it for |
|------|------------|
| **`Secret<N>`** | **Secrets.** Every constructor keeps all `N` bytes inline inside the protected page; the heap-pointer pitfall is unrepresentable. |
| **`MemSafe<T>`** | **Non-secret protected memory.** Any `T` that wants `mlock` + `mprotect` semantics — FFI scratch buffers, guard regions, data you want fault-on-touch while idle. |

### `Secret<N>` construction, precisely

| Constructor | Input | Source returned on error | Source zeroized |
|-------------|-------|--------------------------|-----------------|
| `Secret::<N>::new_with(F)` (`F: FnOnce(&mut [u8; N])`) | (closure writes in place) | N/A — no source | N/A — no source |
| `Secret::<N>::from_bytes(T)` (`T: AsMut<[u8]>`) | Owned bytes | **Yes**, with the error | **Yes** — `len` bytes overwritten before drop |
| `<Secret<N> as TryFrom<String>>::try_from` | Owned `String` | **Yes**, with the error | **Yes** — via `from_bytes` on `into_bytes()` |
| `<Secret<N> as TryFrom<&str>>::try_from` | Borrowed | N/A — borrow returned to caller | No (caller-managed) |

> **Capacity vs. length on `Vec` / `String`.** `from_bytes` only zeroes the bytes exposed by `AsMut::as_mut`, which is `len`, not `capacity`. If your `Vec` or `String` has unused trailing capacity that may have held earlier secret content, call `shrink_to_fit()` before passing it in.

### `MemSafe<T>` — the general-purpose protected container

`MemSafe<T>` is the lower-level building block: a protected memory region holding any `T`. It does **not** carry the secret-handling machinery — no `from_bytes`, no `TryFrom`, no source zeroization.

```rust
use memsafe::MemSafe;

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

### Type-state API — access states checked by the compiler

With the `type-state` feature, the buffer's access state is carried in the type, so reading a no-access buffer or writing through a read-only handle is a *compile-time* error:

```shell
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

## What you get

| Property | How it's enforced |
|----------|-------------------|
| Not paged to disk | `mlock` (Unix) / `VirtualLock` (Windows) on the backing page |
| Not in core dumps | `madvise(MADV_DONTDUMP)` — **Linux only** |
| Inaccessible between operations | `mprotect(PROT_NONE)` on Unix; `PAGE_READONLY` on Windows (the strictest level Windows offers in this model) |
| Zero-on-drop | Byte-wise `write_volatile` + `compiler_fence(SeqCst)` over the page immediately before `munmap` / `VirtualFree` |
| No allocator round-trip | Bytes are copied straight from the source into the protected page; they never reach the regular `malloc` heap |
| Source zeroization | `Secret::from_bytes(T)` volatile-overwrites the source byte slice before drop, for any `T: AsMut<[u8]>` |
| Recoverable on error | `Secret` constructors return the original source alongside the error so the caller can retry, inspect, or further zeroize it |
| In-place initialization | `Secret::new_with` lets a closure write straight into the protected page — the secret never visits a stack temporary or the regular heap |
| No `Debug`, no `Display` | `Secret` implements neither, so a stray `{:?}` in a log line cannot leak it |
| Heap-pointer pitfall unrepresentable | `Secret<N>` only ever wraps `[u8; N]` — by construction it is impossible to protect a header while leaving the payload on the unprotected heap |
| Compile-time access enforcement | Optional, behind the `type-state` feature |

## How it compares

The Rust ecosystem has excellent secret-hygiene crates; they solve different layers of the problem. `memsafe`'s niche is **automating the full OS-level stack behind a safe, typed API**:

| Capability | [`zeroize`](https://crates.io/crates/zeroize) | [`secrecy`](https://crates.io/crates/secrecy) | [`memsec`](https://crates.io/crates/memsec) | [`region`](https://crates.io/crates/region) | `memsafe` |
|---|---|---|---|---|---|
| Elision-resistant zero-on-drop | ✅ | ✅ (via zeroize) | manual (`memzero`) | — | ✅ automatic |
| Locked out of swap (`mlock`) | — | — | manual | manual | ✅ automatic |
| Page inaccessible between uses (`mprotect`) | — | — | manual | manual | ✅ automatic per-access |
| Core-dump exclusion | — | — | via its `mlock` (Linux) | — | ✅ automatic (Linux) |
| Secret bytes kept off the global heap | — | — | your responsibility | your responsibility | ✅ by construction (`Secret<N>`) |
| Safe API (no `unsafe` for the caller) | ✅ | ✅ | ❌ raw primitives | ✅ | ✅ |
| Source returned on constructor failure | — | — | — | — | ✅ |

These are complements, not competitors: `zeroize`/`secrecy` give you type-level hygiene for secrets that must live in ordinary structs, `memsec` and `region` give you raw primitives to build your own container — and `memsafe` is that container, already built, tested, and cross-platform.

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
- **Cross-platform by construction.** `libc` is pulled in only on `cfg(unix)` and `winapi` only on `cfg(windows)`; the correct backend is selected automatically — consumers never pick a platform feature flag. CI covers Linux (x86_64, aarch64, i686, armv7, ppc64le, riscv64), macOS (x86_64, aarch64), and Windows (x86_64, i686), with both default and `type-state` feature variants.

## Under the hood

The implementation behind each guarantee, for readers who want the details:

- **Allocation and locking.** Each instance allocates one or more pages via `mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)` on Unix or `VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)` on Windows. The page is then pinned with `mlock` / `VirtualLock` so the kernel cannot page it out to swap or include it in a hibernation file. On Linux, `madvise(MADV_DONTDUMP)` additionally tells the kernel to omit the page from any core dump produced for the process.

- **Access transitions.** All access to the backing page goes through the internal `Cell` abstraction, which calls `mprotect` (Unix) or `VirtualProtect` (Windows) to elevate the page for the duration of a read or write. As soon as the temporary access guard is dropped, the page is restored to its lowest-privilege state (`PROT_NONE` on Unix, `PAGE_READONLY` on Windows). The `type-state` feature lifts this state machine into the type system.

- **In-place initialization avoids a stack copy.** `Secret::<N>::new_with(|buf| ...)` allocates the protected page first, then hands the closure a `&mut [u8; N]` that points *inside* the locked region. The secret bytes are written directly into protected memory; they never live in a stack-allocated `[u8; N]` that the compiler would otherwise leave behind in the calling frame.

- **Panic-safe construction.** Construction is guarded by an internal RAII rollback guard: if any setup step fails, or a caller-provided `new_with` closure panics after writing partial secret bytes, unwinding volatile-zeroes the page, unlocks it, and unmaps it before the error or panic propagates. A partially-built secret can neither leak nor linger.

- **Source zeroization for `Secret::from_bytes`.** After copying the source bytes into the protected page, `from_bytes` walks the source slice (everything `AsMut::as_mut` exposes) and overwrites every byte with `ptr::write_volatile(0)`, followed by a `compiler_fence(Ordering::SeqCst)`. Volatile stores are guaranteed side effects the compiler may not elide, and the fence prevents the wipe from being reordered past later code. On a memory-protection error the zeroization has already run; on a length-mismatch error the source is returned untouched so the caller can decide what to do with it.

- **Drop-time zeroization is volatile and fenced.** The `Drop` implementation re-elevates the page to read/write, runs `drop_in_place` on the contents, overwrites the page byte-by-byte with `write_volatile`, emits a `compiler_fence(SeqCst)`, releases the lock with `munlock` / `VirtualUnlock`, and finally returns the page to the OS with `munmap` / `VirtualFree`. The volatile + fence guarantee is language-level — independent of whether the following syscall acts as an opaque barrier.

- **Heap-pointer footgun is structurally prevented.** `Secret<N>` is a newtype over `MemSafe<[u8; N]>`. Its `new_with`, `from_bytes`, `TryFrom<&str>`, and `TryFrom<String>` constructors all produce inline byte storage; there is no way to instantiate a `Secret` whose payload lives behind an indirection.

## Roadmap

Planned hardening work, roughly in priority order:

- **Closure-based access API.** Replace `read()` / `write()` guards with `read(|r| ...)` / `write(|w| ...)` closures, so the page is provably returned to its lowest-privilege state when the closure returns.
- **Guard pages.** Allocate adjacent inaccessible pages around the protected region to turn over- and under-runs into immediate faults.
- **Windows core-dump exclusion.** Mark protected pages so they are omitted from minidumps.
- **In-memory encryption at rest.** Encrypt the page contents while the buffer is in its lowest-privilege state, decrypting only inside `read()` / `write()`. Defense in depth against attackers who can read the process's memory.
- **Anti-debugging hooks.** Detect or refuse `ptrace` / debugger attachment.
- **Side-channel mitigation.** Constant-time read/write paths to resist timing and speculative-execution attacks.
- **Custom allocator.** Randomized placement and integrity checks to obscure memory locations.

See the [Milestones](https://github.com/po0uyan/memsafe/milestones) for live status.

## Security notice

`memsafe` is designed against the threat model documented above and has not undergone a formal third-party security audit. We recommend reviewing the [Threat model](#threat-model) section against your own requirements before relying on this crate for sensitive data. Bug reports and security findings are very welcome — please open an issue or a PR.

## Contributing

Issues and pull requests are welcome at [github.com/po0uyan/memsafe](https://github.com/po0uyan/memsafe) — enhancements, security fixes, and anything that pushes the crate toward the [Roadmap](#roadmap).

```shell
cargo test                              # default features
cargo test --features type-state       # compile-time state machine
cargo clippy --all-targets             # lints
```

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.
