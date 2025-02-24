# memsafe
A cross-platform Rust library for securely wrapping data in memory.

[![Crates.io](https://img.shields.io/crates/v/memsafe.svg)](https://crates.io/crates/memsafe)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This is the official `memsafe` crate, hosted at [GitHub](https://github.com/po0uyan/memsafe), and published on crates.io at [here](https://crates.io/crates/memsafe).

`memsafe` locks sensitive data in memory, restricts access, and ensures secure cleanup—built from the ground up with simplicity and security in mind.

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
1. **Secure Memory Wrapper Implementation:** Engineered the MemSafe struct to encapsulate sensitive data, leveraging mprotect, mlock, and madvise on Unix-like systems (Linux and macOS), and VirtualProtect and VirtualLock on Windows. This ensures memory is locked in RAM, excluded from core dumps where possible, and defaults to an inaccessible state for maximum security.
2. **Controlled Access Interface:** Introduced write and read methods utilizing closure-based APIs to enforce strict access controls. These methods temporarily adjust memory permissions for writing or reading, immediately reverting to an inaccessible state (PROT_NONE/PAGE_NOACCESS) post-operation, preventing unauthorized reads after writes.
3. **Crate Naming and Branding:** Explored naming options such as MemVault, LockMem, and SafeBox, ultimately selecting memsafe for its concise, intuitive representation of the crate’s purpose—safe memory handling with broad appeal.
4. **Cross-Platform Compatibility:** Structured the crate with optional dependencies (libc for Unix, winapi for Windows) via unix and windows feature flags, defaulting to unix for seamless compatibility across common development environments while ensuring Windows support.
5. **Open-Source Licensing:** Adopted the MIT License (Copyright (c) 2025 Pouyan) to balance permissiveness with attribution, fostering adoption while acknowledging authorship.
6. **Publication and Distribution:** Established the crate with a streamlined workflow, initialized a Git repository (rust-memsafe), and published to crates.io, accompanied by CI/CD processes to validate functionality across platforms.
   See the full story in the [GitHub repository](https://github.com/po0uyan/memsafe).

## Repository
- **Source**: [https://github.com/po0uyan/memsafe](https://github.com/po0uyan/memsafe)

## Security Notice
Please note that while `memsafe` is designed with security best practices in mind, it has not undergone a formal security audit yet. We encourage users to perform their own security assessment for their specific use cases. We are committed to maintaining and improving the security of this library.

## License
Licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing
Issues and pull requests are welcome at [https://github.com/po0uyan/memsafe](https://github.com/po0uyan/memsafe).
I'll be more than happy to merge enhancements! security updates and any steps towards making software world a better place for everyone.



