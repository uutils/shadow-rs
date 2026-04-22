// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore setuid seteuid setgid initgroups sigprocmask

//! Process-level POSIX wrappers for setuid-root tools.
//!
//! These functions call libc directly because rustix intentionally does not
//! provide process-wide `setuid`/`setgid`/`sigprocmask` (they require libc
//! coordination for thread safety). The `libc` crate is already a dependency
//! for PAM FFI.
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
// Signal blocking (process-wide via libc)
// ---------------------------------------------------------------------------

/// A saved signal mask, used by [`block_signals`] and [`restore_signals`].
///
/// Wraps a `libc::sigset_t`.
pub struct SavedSigSet {
    set: libc::sigset_t,
}

/// Block `SIGINT`, `SIGTERM`, `SIGHUP` and return the previous signal mask.
///
/// Prevents these signals from interrupting a lock-modify-write sequence.
pub fn block_critical_signals() -> io::Result<SavedSigSet> {
    // SAFETY: sigemptyset, sigaddset, and sigprocmask are standard POSIX
    // functions. We initialize the sigset_t with sigemptyset before use.
    unsafe {
        let mut block_set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut block_set);
        libc::sigaddset(&raw mut block_set, libc::SIGINT);
        libc::sigaddset(&raw mut block_set, libc::SIGTERM);
        libc::sigaddset(&raw mut block_set, libc::SIGHUP);

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
