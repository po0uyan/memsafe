//! Try to steal a secret from a plain `String` and from a `memsafe::Secret`,
//! and print what each attempt actually got.
//!
//! ```shell
//! cargo run --example attack_demo
//! ```
//!
//! Attacks that are expected to crash run in a child process (this same
//! binary, re-executed with an argument), so the parent can report how the
//! child died instead of dying itself.
//!
//! Reading freed or sealed memory is undefined behavior; that is the point.
//! It stands in for a bug elsewhere in the program, or an attacker with a
//! stray pointer. Don't copy these reads into real code.

#[cfg(unix)]
const PASSWORD: &str = "correct-horse-battery-staple";

#[cfg(unix)]
fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("sealed-read") => child_sealed_read(),
        Some("read-after-drop") => child_read_after_drop(),
        _ => run(),
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("the attack demo uses Unix signals; run it on Linux or macOS");
}

#[cfg(unix)]
fn run() {
    println!();
    println!("  plain String");
    row(false, "stray read while idle", &string_stray_read());
    row(false, "bytes after drop", &string_after_drop());
    println!();
    println!("  memsafe::Secret");
    row(
        true,
        "stray read while sealed",
        &attack_in_child("sealed-read"),
    );
    row(
        true,
        "stray read after drop",
        &attack_in_child("read-after-drop"),
    );
    #[cfg(target_os = "linux")]
    {
        row(true, "swap", &kernel_flag("lo", "locked in RAM"));
        row(true, "core dump", &kernel_flag("dd", "excluded"));
        row(true, "fork() child", &kernel_flag("wf", "gets zeroes"));
    }
    println!();
}

#[cfg(unix)]
fn row(safe: bool, label: &str, outcome: &str) {
    let icon = if safe { "🔒" } else { "🔓" };
    println!("    {icon} {:.<30} {outcome}", format!("{label} "));
}

/// Read a live `String` through a raw pointer, as any bug elsewhere could.
#[cfg(unix)]
fn string_stray_read() -> String {
    let password = String::from(PASSWORD);
    let ptr = password.as_ptr();
    let bytes: Vec<u8> = (0..password.len())
        .map(|i| unsafe { std::ptr::read_volatile(ptr.add(i)) })
        .collect();
    format!("\"{}\"", String::from_utf8_lossy(&bytes))
}

/// Drop a `String` and look at the freed bytes it left behind.
#[cfg(unix)]
fn string_after_drop() -> String {
    let leaked = String::from(PASSWORD);
    let (ptr, len) = (leaked.as_ptr(), leaked.len());
    drop(leaked);

    let bytes: Vec<u8> = (0..len)
        .map(|i| unsafe { std::ptr::read_volatile(ptr.add(i)) })
        .collect();
    // The allocator may reuse the start of the block for bookkeeping, so
    // show the longest readable run rather than demanding an exact match.
    let text = String::from_utf8_lossy(&bytes);
    let found = text
        .split(|c: char| !c.is_ascii_graphic())
        .max_by_key(|s| s.len())
        .unwrap_or("");
    if found.len() >= 4 && PASSWORD.contains(found) {
        format!("\"{found}\" still there")
    } else if bytes.iter().all(|&b| b == 0) {
        "zeroed by this platform's allocator".to_string()
    } else {
        "overwritten by the allocator".to_string()
    }
}

/// Re-run this binary with `role` and describe how the child ended.
#[cfg(unix)]
fn attack_in_child(role: &str) -> String {
    use std::os::unix::process::ExitStatusExt;

    let exe = std::env::current_exe().expect("current exe");
    let status = std::process::Command::new(exe)
        .arg(role)
        .status()
        .expect("spawn child");
    match status.signal() {
        Some(sig) => format!("{}, process killed", signal_name(sig)),
        None => "read succeeded (protection failed!)".to_string(),
    }
}

#[cfg(unix)]
fn signal_name(sig: i32) -> String {
    match sig {
        libc::SIGSEGV => "SIGSEGV".to_string(),
        libc::SIGBUS => "SIGBUS".to_string(),
        other => format!("signal {other}"),
    }
}

/// Child: keep a pointer from an open read guard, let the guard drop so the
/// page is sealed again, then read through the pointer.
#[cfg(unix)]
fn child_sealed_read() {
    let mut secret = make_secret();
    let addr = secret.read().map(|v| v.as_ptr() as usize).unwrap_or(0);
    let byte = unsafe { std::ptr::read_volatile(addr as *const u8) };
    std::process::exit(i32::from(byte == 0));
}

/// Child: keep a pointer into the secret, drop the secret, then read.
#[cfg(unix)]
fn child_read_after_drop() {
    let mut secret = make_secret();
    let addr = secret.read().map(|v| v.as_ptr() as usize).unwrap_or(0);
    drop(secret);
    let byte = unsafe { std::ptr::read_volatile(addr as *const u8) };
    std::process::exit(i32::from(byte == 0));
}

/// The secret every `memsafe` attack goes after.
#[cfg(unix)]
fn make_secret() -> memsafe::Secret<64> {
    memsafe::Secret::try_from(PASSWORD).unwrap_or_else(|e| {
        eprintln!("could not create secret: {e}");
        std::process::exit(2)
    })
}

/// Ask the kernel whether the secret's page carries a VmFlags entry.
#[cfg(target_os = "linux")]
fn kernel_flag(flag: &str, meaning: &str) -> String {
    let mut secret = make_secret();
    let view = match secret.read() {
        Ok(v) => v,
        Err(e) => return format!("could not open secret: {e}"),
    };
    let addr = view.as_ptr() as usize;
    let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap_or_default();

    let mut in_block = false;
    for line in smaps.lines() {
        if let Some((start, end)) = line.split(' ').next().and_then(|r| r.split_once('-')) {
            if let (Ok(s), Ok(e)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            ) {
                in_block = s <= addr && addr < e;
            }
        }
        if in_block && line.starts_with("VmFlags:") {
            return if line.split_whitespace().any(|f| f == flag) {
                format!("{meaning} (kernel flag `{flag}`)")
            } else {
                format!("kernel flag `{flag}` missing!")
            };
        }
    }
    "page not found in /proc/self/smaps".to_string()
}
