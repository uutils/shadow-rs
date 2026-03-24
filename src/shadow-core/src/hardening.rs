// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Security hardening utilities for setuid-root tools.
//!
//! Every shadow-utils tool runs as setuid-root and must defend against
//! hostile callers. These functions implement the standard hardening
//! steps that all tools share.

/// Suppress core dumps (`RLIMIT_CORE=0`) and prevent ptrace attachment.
///
/// A core dump from a setuid-root process could expose password hashes
/// and plaintext passwords. `PR_SET_DUMPABLE=0` also prevents
/// `/proc/pid/mem` reads by other processes.
pub fn suppress_core_dumps() {
    let _ = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl with PR_SET_DUMPABLE is a simple flag set, no pointers.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0);
        }
    }
}

/// Raise `RLIMIT_FSIZE` to prevent truncated file writes.
///
/// A malicious caller could `ulimit -f 1` before invoking a setuid-root
/// tool, causing `/etc/shadow` to be truncated mid-write.
pub fn raise_file_size_limit() {
    let _ = nix::sys::resource::setrlimit(
        nix::sys::resource::Resource::RLIMIT_FSIZE,
        nix::sys::resource::RLIM_INFINITY,
        nix::sys::resource::RLIM_INFINITY,
    );
}

/// Sanitize the environment for setuid-root context.
///
/// Clears all environment variables except essential ones (`TERM`, `LANG`,
/// `LC_*`) and sets `PATH` to a safe default. Prevents environment variable
/// injection attacks (`LD_PRELOAD`, `IFS`, `CDPATH`, etc.).
pub fn sanitize_env() {
    let saved: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| k == "TERM" || k == "LANG" || k.starts_with("LC_"))
        .collect();

    let keys: Vec<std::ffi::OsString> = std::env::vars_os().map(|(k, _)| k).collect();
    for key in keys {
        std::env::remove_var(&key);
    }

    std::env::set_var("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");

    for (key, val) in saved {
        std::env::set_var(&key, &val);
    }
}

/// Run all standard hardening steps for a setuid-root tool.
///
/// Call at the top of `uumain` before any argument parsing.
pub fn harden_process() {
    suppress_core_dumps();
    raise_file_size_limit();
    sanitize_env();
}
