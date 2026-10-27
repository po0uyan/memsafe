<div align="center">

# 🔐 memsafe

Keep secrets in memory that is locked, sealed, and wiped when you're done.

[![Crates.io](https://img.shields.io/crates/v/memsafe.svg)](https://crates.io/crates/memsafe)
[![Downloads](https://img.shields.io/crates/d/memsafe.svg)](https://crates.io/crates/memsafe)
[![GitHub](https://img.shields.io/badge/GitHub-po0uyan%2Fmemsafe-181717?logo=github)](https://github.com/po0uyan/memsafe)
[![docs.rs](https://img.shields.io/badge/docs.rs-memsafe-1f425f?logo=docs.rs)](https://docs.rs/memsafe)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

## 🕵️ Try to steal it

```text
$ cargo run --example attack_demo

  plain String
    🔓 stray read while idle ........ "correct-horse-battery-staple"
    🔓 bytes after drop ............. "ttery-staple" still there

  memsafe::Secret
    🔒 stray read while sealed ...... SIGSEGV, process killed
    🔒 stray read after drop ........ SIGSEGV, process killed
    🔒 swap ......................... locked in RAM (kernel flag `lo`)
    🔒 core dump .................... excluded (kernel flag `dd`)
    🔒 fork() child ................. gets zeroes (kernel flag `wf`)
```

**On Unix, a sealed secret can't be read, not even by your own process.** Real output from
Linux ([source](examples/attack_demo.rs)); macOS skips the kernel-flag rows.

## 🛡️ What it does

`Secret<N>` keeps your secret in its own locked memory pages, away from the heap, from the
moment it's created until the moment it's wiped:

```rust
use memsafe::Secret;

let mut secret = Secret::<64>::new_with(|buf| {
    buf[..10].copy_from_slice(b"my-api-key");
}).unwrap();

let view = secret.read().unwrap();   // page is readable while `view` lives
assert_eq!(&view[..10], b"my-api-key");
// `view` drops: page is sealed again
// `secret` drops: bytes are wiped, page is unlocked and freed
```

Every secret is:

- **locked in RAM** (`mlock`), so it never goes to swap;
- **sealed between uses** (`PROT_NONE` on Unix), so even a stray pointer in your own process
  crashes instead of reading it;
- **left out of core dumps** (Linux, FreeBSD) and **zeroed in forked children** (Linux);
- **wiped on drop** with volatile writes the compiler can't optimize away.

You never write `unsafe`. Formatting a `Secret` with `{:?}` doesn't compile, so it can't slip
into a log line.

It's used in [spg](https://github.com/po0uyan/rust-secure-pass-gen), a password generator.

## ⚠️ What it does not protect against

Read this before relying on it.

- **Anyone with your privileges or more.** A debugger, `ptrace`, or root can read the page.
- **Hibernation.** The suspend image contains all of RAM, locked pages included. Use full-disk
  or encrypted swap.
- **`fork()` outside Linux.** The child gets a copy. Create secrets after forking.
- **Side channels** (timing, speculation, power) and copies left in CPU registers.
- **Physical attacks** such as cold boot, DMA, or RowHammer.
- **Reads on Windows.** Windows can only make the page read-only, so stray reads still work
  there; only writes are blocked.

memsafe has not had a third-party security audit. If your threat model includes the list
above, treat it as one layer of defense, not the whole thing. Security reports are welcome.

## 🚀 Usage

```shell
cargo add memsafe
```

`Secret<N>` holds up to `N` bytes; unused bytes stay zero.

**Write the secret in place.** `new_with` hands your closure a buffer that is already inside
the locked page. Read from stdin or a file straight into it, and the secret never exists
anywhere else.

**Or hand over one you already have.** `from_bytes` and `TryFrom<String>` copy the bytes in and
then zero the original:

```rust
let secret = Secret::<64>::from_bytes(b"my-api-key".to_vec()).unwrap();
let secret: Secret<64> = String::from("my-api-key").try_into().unwrap();
```

If that fails (input too long, or the OS lock limit is reached), you get the original back with
the error instead of losing it. (If the copy succeeded but sealing the page then failed, which
is rare, it comes back already zeroed.)

```rust
match Secret::<4>::try_from(String::from("way-too-long")) {
    Ok(_) => unreachable!(),
    Err((source, err)) => eprintln!("failed ({err}); got back {} bytes", source.len()),
}
```

Zeroing covers the vector's length, not its spare capacity, and can't reach older copies left
behind when a `Vec` or `String` grew. If that matters, use `new_with`.

`TryFrom<&str>` also works, but it can't zero a borrow; that's up to you.

### Protected memory for other types

`MemSafe<T>` is the building block underneath: a locked, sealed region holding any `T`, with
`read()` and `write()` guards. Use it for data you want protected that isn't a secret.

Don't use `MemSafe<String>` for a password. A `String` keeps its bytes on the heap, so only its
header (24 bytes on 64-bit) would be protected. That's why `Secret<N>` only accepts a fixed-size byte array.

### Compile-time access states

With the `type-state` feature, the access mode is part of the type, so reading a sealed buffer
is a compile error:

```rust
use memsafe::type_state::MemSafe;

let secret = MemSafe::new([0_u8; 32]).unwrap();  // sealed
let mut secret = secret.read_write().unwrap();   // writable
secret[..4].copy_from_slice(b"data");
let secret = secret.read_only().unwrap();        // read-only
```

`Secret<N>` doesn't have a type-state version yet.

## Cost

Creating a secret takes three syscalls, four on FreeBSD, or five on Linux. Every `read()` or
`write()` takes two more, to unseal and reseal. From the
[criterion benches](benches/memsafe_bench.rs) on Apple Silicon (`cargo bench` to run them
yourself):

| Operation | memsafe | `Vec<u8>` |
|---|---|---|
| Create and drop a 64 B secret | ~2.8 µs | ~9.5 ns |
| Create and drop a 4 KiB secret | ~3.8 µs | |
| Read (unseal, read, reseal) | ~1.1 µs | ~0.35 ns |
| Write (unseal, write, reseal) | ~1.1 µs | |

That's nothing for keys and passwords. In a hot loop, open one guard and do all the work inside
it.

Each secret takes at least one whole page (4 KiB on most Linux and Windows machines, 16 KiB on
Apple Silicon) and counts toward the OS limit on locked memory. On Linux that limit is 8 MiB on
recent kernels and 64 KiB on older ones, so check `ulimit -l` if you need many secrets.

## 💻 Platforms

🐧 Linux · 🍎 macOS · 🪟 Windows · 😈 FreeBSD · ⚙️ other Unixes, tested in CI on 11 targets
across x86_64, aarch64, ARM, i686, RISC-V, and PowerPC. FreeBSD runs in a real FreeBSD VM. The
right backend (`libc` or `winapi`) is picked automatically; there are no backend features to
choose.

Core-dump exclusion works on Linux and FreeBSD. Fork wiping is Linux-only for now.

## How it works

1. Allocate a private page with `mmap` (`VirtualAlloc` on Windows) and lock it with `mlock`
   (`VirtualLock`). On Linux, also mark it `MADV_DONTDUMP` and `MADV_WIPEONFORK`; on FreeBSD,
   `MADV_NOCORE`.
2. Run your `new_with` closure on a buffer inside that page.
3. Seal the page with `mprotect` (`VirtualProtect`). Each `read()` or `write()` guard unseals it
   and reseals it when dropped.
4. On drop, zero every byte with `write_volatile` and a compiler fence, then unlock and unmap.

If setup fails or your closure panics, the page is wiped and released the same way.

## 🆚 Others vs memsafe

Popular Rust crates for secrets fall into two groups: **wipe-on-drop wrappers**, which clear a
value when it's dropped, and **secure allocators**, which hand out locked, guarded memory as raw
pointers.

| | Wipe-on-drop wrappers | Secure allocators | memsafe |
|---|---|---|---|
| Wiped on drop | ✅ | on manual `free()` | ✅ |
| Kept out of swap | | ✅ | ✅ |
| Excluded from core dumps | | Linux, FreeBSD | Linux, FreeBSD |
| Sealed between uses | | manual `mprotect` calls | ✅ automatic |
| Guard pages and canary | | ✅ | planned |
| Safe API, no `unsafe` | ✅ | | ✅ |
| Cost per access | none | syscalls if you seal | two syscalls |

**Wrappers** are cheap, but while the secret is alive it sits in ordinary memory, where it can
be swapped to disk, end up in a crash dump, or be read through a stray pointer. **Secure
allocators** protect the memory well, but you get a raw pointer, write `unsafe` code, and seal
and free the memory yourself. **memsafe** does the locking, sealing, and wiping for you, behind
a safe type. Guard pages (no-access pages around the secret, so writing past its end crashes
right away) are next on the roadmap.

## Roadmap

- Fork protection on the BSDs (`minherit(INHERIT_ZERO)`)
- A closure-based access API, so the page is always resealed when the closure returns
- Guard pages around each secret, so overruns crash immediately
- Excluding secrets from Windows crash dumps
- Encrypting the page while it's sealed

See the [milestones](https://github.com/po0uyan/memsafe/milestones) for progress.

## Contributing

Issues and pull requests are welcome.

```shell
cargo test
cargo test --features type-state
cargo clippy --all-targets
```

## License

MIT. See [LICENSE](LICENSE).
