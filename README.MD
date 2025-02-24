# memsafe
A cross-platform Rust library for securely wrapping data in memory.

[![Crates.io](https://img.shields.io/crates/v/memsafe.svg)](https://crates.io/crates/memsafe)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This is the official `memsafe` repository, hosted at [https://github.com/po0uyan/memsafe](https://github.com/po0uyan/memsafe), and published on crates.io at [https://crates.io/crates/memsafe](https://crates.io/crates/memsafe).

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
memsafe = "0.1.0"
```

For Windows support only:
```toml
[dependencies]
memsafe = { version = "0.1.0", default-features = false, features = ["windows"] }
```

## Milestones
The journey to create `memsafe` involved several key steps:
1. **Secure Memory Wrapper**: Developed a Rust struct (`MemSafe`) using `mprotect`, `mlock`, and `madvise` on Unix, and `VirtualProtect`, `VirtualLock` on Windows, ensuring data stays locked and inaccessible by default.
2. **Naming the Crate**: Brainstormed names like `MemVault`, `LockMem`, and settled on `memsafe` for its simplicity and clarity.
3. **Cross-Platform Support**: Made `libc` and `winapi` optional dependencies with `unix` and `windows` features, defaulting to Unix for broad compatibility.
4. **Licensing**: Chose the MIT License to require attribution (`Copyright (c) 2025 Pouyan`) while keeping it permissive.
5. **SSH Configuration**: Set up an SSH config using `pouyan.key` for GitHub (`github.com/po0uyan/memsafe`), with a catch-all for other connections.
6. **Publishing**: Created the crate, initialized a Git repo, and published to crates.io with a streamlined workflow.

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
---

