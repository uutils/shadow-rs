// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore setuid seteuid setgid initgroups sigprocmask getpwuid

//! Process-level POSIX wrappers for setuid-root tools.
//!
//! These functions call libc directly because rustix intentionally does not
//! provide process-wide `setuid`/`setgid` or per-thread `sigprocmask` (they
//! require libc coordination for thread safety). The `libc` crate is already
//! a dependency for PAM FFI.
//!
//! This is one of the few modules that permits `unsafe` — all unsafe is
//! confined to well-understood POSIX C library calls.

use std::ffi::CStr;
use std::io;

// ---------------------------------------------------------------------------
// UID / GID manipulation (process-wide via libc)
// ---------------------------------------------------------------------------

/// `setuid(uid)` — set the real and effective user ID of the calling process.
///
/// This calls the libc `setuid()` which is process-wide (unlike the raw
/// syscall which is per-thread on Linux).
pub fn setuid(uid: u32) -> io::Result<()> {
    // SAFETY: setuid is a standard POSIX function. The only precondition
    // is that uid is a valid UID value, which u32 always satisfies.
    let ret = unsafe { libc::setuid(uid) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `seteuid(uid)` — set the effective user ID of the calling process.
///
/// This calls the libc `seteuid()` which is process-wide.
pub fn seteuid(uid: u32) -> io::Result<()> {
    // SAFETY: seteuid is a standard POSIX function.
    let ret = unsafe { libc::seteuid(uid) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `setgid(gid)` — set the real and effective group ID of the calling process.
///
/// This calls the libc `setgid()` which is process-wide.
pub fn setgid(gid: u32) -> io::Result<()> {
    // SAFETY: setgid is a standard POSIX function.
    let ret = unsafe { libc::setgid(gid) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `initgroups(user, gid)` — initialize the supplementary group list.
///
/// Sets the supplementary groups for `user` plus `gid`.
pub fn initgroups(user: &CStr, gid: u32) -> io::Result<()> {
    // SAFETY: initgroups is a standard POSIX function. `user` is a valid
    // null-terminated CStr.
    let ret = unsafe { libc::initgroups(user.as_ptr(), gid) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// ---------------------------------------------------------------------------
// exec
// ---------------------------------------------------------------------------

/// `execv(path, argv)` — replace the current process image.
///
/// On success this function never returns. On failure it returns an error.
pub fn execv(path: &CStr, argv: &[&CStr]) -> io::Error {
    // Build a null-terminated array of pointers for execv.
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    // SAFETY: execv is a standard POSIX function. The argv array is
    // null-terminated and all CStr pointers are valid.
    unsafe {
        libc::execv(path.as_ptr(), argv_ptrs.as_ptr());
    }
    // execv only returns on error.
    io::Error::last_os_error()
}

// ---------------------------------------------------------------------------
// Signal blocking (per-thread via libc sigprocmask)
// ---------------------------------------------------------------------------

/// A saved signal mask, used by [`block_critical_signals`] and
/// [`restore_signals`].
///
/// Wraps a `libc::sigset_t`.
pub struct SavedSigSet {
    set: libc::sigset_t,
}

/// Block `SIGINT`, `SIGTERM`, `SIGHUP` and return the previous signal mask.
///
/// Calls `sigprocmask`, which modifies the *calling thread's* signal mask.
/// For single-threaded shadow-rs tools this is effectively process-wide.
///
/// Prevents these signals from interrupting a lock-modify-write sequence.
pub fn block_critical_signals() -> io::Result<SavedSigSet> {
    // SAFETY: sigemptyset, sigaddset, and sigprocmask are standard POSIX
    // functions. We initialize the sigset_t with sigemptyset before use.
    unsafe {
        let mut block_set: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&raw mut block_set) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::sigaddset(&raw mut block_set, libc::SIGINT) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::sigaddset(&raw mut block_set, libc::SIGTERM) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::sigaddset(&raw mut block_set, libc::SIGHUP) != 0 {
            return Err(io::Error::last_os_error());
        }

        let mut old_set: libc::sigset_t = std::mem::zeroed();
        let ret = libc::sigprocmask(libc::SIG_BLOCK, &raw const block_set, &raw mut old_set);
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(SavedSigSet { set: old_set })
    }
}

/// Restore a previously saved signal mask.
pub fn restore_signals(saved: &SavedSigSet) -> io::Result<()> {
    // SAFETY: sigprocmask with SIG_SETMASK restores a previously captured mask.
    let ret = unsafe {
        libc::sigprocmask(
            libc::SIG_SETMASK,
            &raw const saved.set,
            std::ptr::null_mut(),
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// ---------------------------------------------------------------------------
// NSS user lookup (getpwuid_r)
// ---------------------------------------------------------------------------

/// Result of an NSS user lookup via `getpwuid_r`.
///
/// Contains the fields from `struct passwd` that shadow-rs tools need.
/// Unlike reading `/etc/passwd` directly, this goes through NSS and works
/// with LDAP, SSSD, systemd-homed, and other name-service backends.
pub struct PwEntry {
    /// Login name.
    pub name: String,
    /// Encrypted password (usually `x`).
    pub passwd: String,
    /// Numeric user ID.
    pub uid: u32,
    /// Numeric primary group ID.
    pub gid: u32,
    /// GECOS / comment field.
    pub gecos: String,
    /// Home directory.
    pub home: String,
    /// Login shell.
    pub shell: String,
}

/// Look up a user by UID via `getpwuid_r` (NSS-backed).
///
/// Returns `None` if no user exists for the given UID.
/// Returns `Err` on system errors (e.g., I/O failure in NSS backend).
pub fn getpwuid(uid: u32) -> io::Result<Option<PwEntry>> {
    // Start with a 1 KiB buffer; grow on ERANGE.
    let mut buf_size: usize = 1024;

    loop {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf: Vec<u8> = vec![0u8; buf_size];
        let mut result: *mut libc::passwd = std::ptr::null_mut();

        // SAFETY: getpwuid_r is a POSIX thread-safe function. We pass a
        // properly sized buffer and a zeroed passwd struct. The result
        // pointer tells us whether an entry was found.
        let ret = unsafe {
            libc::getpwuid_r(
                uid,
                &raw mut pwd,
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf_size,
                &raw mut result,
            )
        };

        if ret == libc::ERANGE {
            // Buffer too small — double and retry.
            buf_size = buf_size.saturating_mul(2);
            if buf_size > 1024 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "getpwuid_r buffer exceeded 1 MiB",
                ));
            }
            continue;
        }

        if ret != 0 {
            return Err(io::Error::from_raw_os_error(ret));
        }

        if result.is_null() {
            // No entry found for this UID.
            return Ok(None);
        }

        // SAFETY: getpwuid_r succeeded and `result` is non-null, so all
        // string fields in `pwd` point into `buf` and are valid C strings.
        let entry = unsafe {
            PwEntry {
                name: CStr::from_ptr(pwd.pw_name).to_string_lossy().into_owned(),
                passwd: CStr::from_ptr(pwd.pw_passwd).to_string_lossy().into_owned(),
                uid: pwd.pw_uid,
                gid: pwd.pw_gid,
                gecos: CStr::from_ptr(pwd.pw_gecos).to_string_lossy().into_owned(),
                home: CStr::from_ptr(pwd.pw_dir).to_string_lossy().into_owned(),
                shell: CStr::from_ptr(pwd.pw_shell).to_string_lossy().into_owned(),
            }
        };

        return Ok(Some(entry));
    }
}

/// Look up a username by UID via NSS (`getpwuid_r`).
///
/// Convenience wrapper that returns just the login name.
pub fn lookup_username(uid: u32) -> io::Result<Option<String>> {
    Ok(getpwuid(uid)?.map(|e| e.name))
}
