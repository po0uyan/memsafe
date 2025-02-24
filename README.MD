# memsafe
One of the most secure cross-platform Rust libraries for securely wrapping data in memory.

[![Crates.io](https://img.shields.io/crates/v/memsafe.svg)](https://crates.io/crates/memsafe)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This is the official `memsafe` crate, hosted at [GitHub](https://github.com/po0uyan/memsafe), and published on [crates.io](https://crates.io/crates/memsafe).

**`memsafe`** locks sensitive data in memory, restricts access, and ensures secure cleanup—built from the ground up with simplicity and security in mind.

## Usage

```rust
use memsafe::MemSafe;
let mut secret = MemSafe::new(String::from("secret")).unwrap();
secret.push_str(" data");
println!("Secure data: {}", secret);
```
## Features
- **Memory Locking**: Prevents swapping to disk using `mlock` (Unix) or `VirtualLock` (Windows).
- **Access Restriction**: Defaults to no-access mode, with temporary read/write windows.
- **Secure Cleanup**: Zeroes memory on drop.
- **Cross-Platform**: Supports Unix (via `libc`) and Windows (via `winapi`) with optional dependencies.

## Installation
Add to your `Cargo.toml`:
```toml
[dependencies]
memsafe = "0.1.6"
```

For Windows support only:
```toml
[dependencies]
memsafe = { version = "0.1.6", default-features = false, features = ["windows"] }
```

## Milestones
The development of `memsafe` has focused on delivering a technically robust and secure memory management solution in Rust. The following milestones have been achieved from a security and implementation perspective:

- **Secure Memory Wrapper Implementation**: Engineered the `MemSafe` struct to encapsulate sensitive data with platform-specific protections—`mprotect`, `mlock`, and `madvise` on Unix-like systems (Linux, macOS), and `VirtualProtect` and `VirtualLock` on Windows—ensuring memory is pinned in RAM and defaults to an inaccessible state for enhanced isolation.

- **Cross-Platform Compatibility with Feature Flags**: Structured the crate with conditional compilation (`#[cfg(unix)]` and `#[cfg(windows)]`) and optional dependencies (`libc` and `winapi`) via `unix` and `windows` features, validated through multi-platform CI, to maintain consistent security across operating systems.

- **Secure Memory Cleanup on Drop**: Implemented the `Drop` trait to zero memory contents before deallocation, using `munlock` and `munmap` on Unix, and `VirtualUnlock` and `VirtualFree` on Windows, preventing residual data exposure.

- **Automated Multi-Platform Testing**: Established a CI workflow on GitHub Actions, executing `cargo build` and `cargo test` across Ubuntu, macOS, and Windows with appropriate feature flags, ensuring security properties hold universally.

### Planned Security Enhancements
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



