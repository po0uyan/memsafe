# memsafe
One of the most secure cross-platform Rust libraries for securely wrapping data in memory.

[![Crates.io](https://img.shields.io/crates/v/memsafe.svg)](https://crates.io/crates/memsafe)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This is the official `memsafe` crate, hosted at [GitHub](https://github.com/po0uyan/memsafe), and published on [crates.io](https://crates.io/crates/memsafe).


**`memsafe`** locks sensitive data in memory, restricts access, and ensures secure cleanup—built from the ground up with simplicity and security in mind.

## Usage

```rust
use memsafe::MemSafe;

// initialize a 32-bytes buffer in no access state
let secret = MemSafe::new([0_u8; 32]).unwrap();

// make the buffer read-write and write into it
let info = "my-scret-info";
let mut secret = secret.read_write().unwrap();
secret[..info.len()].copy_from_slice(info.as_bytes());

// make array read only read from it
let secret = secret.read_only().unwrap();
println!("Secure data: {:02X?}", *secret);
```
## Features
- **Memory Locking**: Prevents swapping to disk using `mlock` (Unix) or `VirtualLock` (Windows).
- **Access Restriction**: Defaults to no-access mode, with temporary read/write windows.
- **Secure Cleanup**: Zeroes memory on drop.
- **Cross-Platform**: Supports Unix (via `libc`) and Windows (via `winapi`) with optional dependencies.

## Installation
Run the following in the root of your project:
```shell
cargo add memsafe
```

## Security Mechanisms: A Deep Dive for Technical Enthusiasts

The following milestones highlight the technical implementation and security mechanisms completed in `memsafe`, ensuring robust memory management for sensitive data in Rust:

- **Secure Memory Wrapper Implementation**
    - **Technical Details**: The `MemSafe` struct encapsulates sensitive data within a custom memory region allocated via `mmap` on Unix-like systems (Linux, macOS) with `MAP_PRIVATE | MAP_ANONYMOUS` flags, and `VirtualAlloc` on Windows with `MEM_COMMIT | MEM_RESERVE`. Memory permissions are controlled using `mprotect` (Unix) and `VirtualProtect` (Windows), setting `PROT_NONE`/`PAGE_NOACCESS` by default to deny all access. The `mlock` (Unix) and `VirtualLock` (Windows) functions pin the memory in RAM, preventing swap to disk, while `madvise(MADV_DONTDUMP)` on Unix excludes it from core dumps.
    - **Security Handling**: This ensures data remains in physical memory and is inaccessible outside explicit operations, reducing exposure to swap-based attacks and limiting visibility in crash scenarios on Unix systems.

- **Cross-Platform Compatibility with Feature Flags**
    - **Technical Details**: Conditional compilation via `#[cfg(unix)]` and `#[cfg(windows)]` directives isolates platform-specific code. The `unix` feature activates `libc` for POSIX calls, while the `windows` feature leverages `winapi` for Windows API functions, with `default = ["unix"]` in `Cargo.toml` enabling Unix support out of the box. CI testing uses a matrix strategy (`ubuntu-latest`, `macos-latest` with `unix`; `windows-latest` with `windows`) to build and test with `--no-default-features --features ${{ matrix.features }}`.
    - **Security Handling**: This guarantees uniform security behavior across platforms, preventing gaps from missing platform-specific protections (e.g., no `mlock` fallback on Windows) and ensuring dependency minimization.

- **Secure Memory Cleanup on Drop**
    - **Technical Details**: The `Drop` implementation zeroes the memory region using `ptr::write_bytes(ptr, 0, len)` before deallocation. On Unix, `munlock` releases the memory lock, followed by `munmap` to free the region. On Windows, `VirtualUnlock` unlocks the memory, and `VirtualFree` with `MEM_RELEASE` deallocates it. This process is executed within an `unsafe` block to handle raw pointer operations.
    - **Security Handling**: By overwriting memory with zeros prior to release, this prevents residual data from being accessed post-deallocation, mitigating risks of memory scraping or reuse attacks.

- **Automated Multi-Platform Testing**
    - **Technical Details**: A GitHub Actions workflow triggers on `dev` branch pushes, running `cargo build` and `cargo test` with `--verbose` across a matrix of `ubuntu-latest`, `macos-latest`, and `windows-latest`. The matrix excludes invalid feature combinations (e.g., `windows` on Unix) using `exclude` rules. Rust is set up with `dtolnay/rust-toolchain@stable`, and Linux requires `build-essential` for `libc` linking.
    - **Security Handling**: This ensures that memory protection, locking, and access controls function correctly on all platforms, catching platform-specific regressions or misconfigurations early in the development cycle.


## Milestones
To further harden `memsafe` against vulnerabilities, the following technical improvements are targeted:

- **Controlled Access Interface**: Transition to closure-based `write` and `read` methods to enforce strict permission toggling, preventing reads after writes by reverting to an inaccessible state post-operation.
- **In-Memory Encryption**: Integrate encryption to safeguard data at rest against physical or kernel-level breaches.
- **Guard Pages**: Allocate protective, inaccessible pages around memory to detect and thwart buffer overflows.
- **Pre-Allocation Zeroing**: Zero memory prior to initial use to eliminate risks from pre-existing data.
- **Thread Safety**: Add synchronization primitives (e.g., `Mutex`) for secure multi-threaded access.
- **Windows Core Dump Protection**: Implement mechanisms to exclude memory from Windows crash dumps.
- **Anti-Debugging Measures**: Restrict debugger attachment to minimize exposure during operations.
- **Custom Allocator**: Develop a randomized allocator with integrity checks to obscure memory locations.
- **Side-Channel Mitigation**: Optimize for constant-time operations to resist timing and speculative execution attacks.
  See the full Milestone in the [Milestones](https://github.com/po0uyan/memsafe/milestones).


## Repository
- **Source**: [https://github.com/po0uyan/memsafe](https://github.com/po0uyan/memsafe)

## Security Notice
Please note that while `memsafe` is designed with security best practices in mind, it has not undergone a formal security audit yet. We encourage users to perform their own security assessment for their specific use cases. We are committed to maintaining and improving the security of this library.

## License
Licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing
Issues and pull requests are welcome at [https://github.com/po0uyan/memsafe](https://github.com/po0uyan/memsafe).
I'll be more than happy to merge enhancements! security updates and any steps towards making software world a better place for everyone.



