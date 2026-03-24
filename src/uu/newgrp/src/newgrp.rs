// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore setgid setuid gshadow getgid getuid newgrp

//! `newgrp` — change effective group ID.
//!
//! Drop-in replacement for GNU shadow-utils / POSIX `newgrp(1)`.
//! Starts a new shell with the specified group as the effective GID.

use std::ffi::CString;
use std::fmt;
use std::path::Path;

use clap::{Arg, Command};

use shadow_core::group;
use shadow_core::gshadow;
use shadow_core::sysroot::SysRoot;

use uucore::error::{UError, UResult};

mod options {
    pub const GROUP: &str = "group";
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum NewgrpError {
    /// Exit 1 — general error.
    Error(String),
    /// Sentinel for errors already printed by clap.
    AlreadyPrinted(i32),
}

impl fmt::Display for NewgrpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(msg) => f.write_str(msg),
            Self::AlreadyPrinted(_) => Ok(()),
        }
    }
}

impl std::error::Error for NewgrpError {}

impl UError for NewgrpError {
    fn code(&self) -> i32 {
        match self {
            Self::Error(_) => 1,
            Self::AlreadyPrinted(code) => *code,
        }
    }
}

// ---------------------------------------------------------------------------
// Security hardening
// ---------------------------------------------------------------------------

// Hardening functions are now centralized in shadow_core::hardening.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn caller_is_root() -> bool {
    nix::unistd::getuid().is_root()
}

/// Get the current user's username from the real UID.
fn get_current_username() -> Result<String, NewgrpError> {
    let uid = nix::unistd::getuid();
    match nix::unistd::User::from_uid(uid) {
        Ok(Some(user)) => Ok(user.name),
        Ok(None) => Err(NewgrpError::Error(format!(
            "cannot determine current username for uid {uid}"
        ))),
        Err(e) => Err(NewgrpError::Error(format!(
            "cannot determine current username: {e}"
        ))),
    }
}

/// Get the current user's primary GID from the real UID.
fn get_current_gid() -> Result<u32, NewgrpError> {
    let uid = nix::unistd::getuid();
    match nix::unistd::User::from_uid(uid) {
        Ok(Some(user)) => Ok(user.gid.as_raw()),
        Ok(None) => Err(NewgrpError::Error(format!(
            "cannot determine current user for uid {uid}"
        ))),
        Err(e) => Err(NewgrpError::Error(format!(
            "cannot determine current user: {e}"
        ))),
    }
}

/// Determine the shell to exec. Uses `$SHELL` if set and non-empty,
/// otherwise falls back to `/bin/sh`.
fn get_shell() -> String {
    std::env::var("SHELL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/bin/sh".to_string())
}

/// Check if the user is a member of the group (either as primary GID
/// in /etc/passwd or in the group's member list in /etc/group).
fn is_member(username: &str, user_gid: u32, target_gid: u32, group_members: &[String]) -> bool {
    if user_gid == target_gid {
        return true;
    }
    group_members.iter().any(|m| m == username)
}

/// Check if the group has a usable password in /etc/gshadow.
/// A password of `!`, `*`, `!!`, or empty means no password access.
fn group_has_password(gshadow_path: &Path, group_name: &str) -> Option<String> {
    let entries = gshadow::read_gshadow_file(gshadow_path).ok()?;
    let entry = entries.iter().find(|e| e.name == group_name)?;

    if entry.passwd.is_empty() || entry.passwd == "!" || entry.passwd == "*" || entry.passwd == "!!"
    {
        return None;
    }

    Some(entry.passwd.clone())
}

/// RAII guard that restores terminal echo on drop.
struct EchoGuard {
    tty: std::fs::File,
    old_termios: nix::sys::termios::Termios,
}

impl EchoGuard {
    /// Disable echo on the given tty file.
    fn disable(tty: std::fs::File) -> Result<Self, NewgrpError> {
        use std::os::unix::io::AsFd;

        let old_termios = nix::sys::termios::tcgetattr(tty.as_fd())
            .map_err(|e| NewgrpError::Error(format!("cannot get terminal attributes: {e}")))?;

        let mut new_termios = old_termios.clone();
        new_termios.local_flags &= !nix::sys::termios::LocalFlags::ECHO;
        nix::sys::termios::tcsetattr(
            tty.as_fd(),
            nix::sys::termios::SetArg::TCSANOW,
            &new_termios,
        )
        .map_err(|e| NewgrpError::Error(format!("cannot disable echo: {e}")))?;

        Ok(Self { tty, old_termios })
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        use std::os::unix::io::AsFd;
        let _ = nix::sys::termios::tcsetattr(
            self.tty.as_fd(),
            nix::sys::termios::SetArg::TCSANOW,
            &self.old_termios,
        );
    }
}

/// Read a password from `/dev/tty` with echo disabled.
fn read_password(prompt: &str) -> Result<String, NewgrpError> {
    use std::io::{BufRead, Write};

    let tty = std::fs::File::options()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| NewgrpError::Error(format!("cannot open /dev/tty: {e}")))?;

    // Write the prompt.
    (&tty)
        .write_all(prompt.as_bytes())
        .map_err(|e| NewgrpError::Error(format!("cannot write prompt: {e}")))?;
    (&tty)
        .flush()
        .map_err(|e| NewgrpError::Error(format!("cannot flush prompt: {e}")))?;

    // Clone the tty handle: one for the guard (to restore echo), one for reading.
    let tty_for_guard = tty
        .try_clone()
        .map_err(|e| NewgrpError::Error(format!("cannot clone tty handle: {e}")))?;

    // Disable echo; restored automatically on drop.
    let guard = EchoGuard::disable(tty_for_guard)?;

    let mut buf = String::new();
    let mut reader = std::io::BufReader::new(&tty);
    reader
        .read_line(&mut buf)
        .map_err(|e| NewgrpError::Error(format!("cannot read password: {e}")))?;

    // Echo was off, so print newline after the user presses Enter.
    drop(guard);
    let _ = (&tty).write_all(b"\n");

    Ok(buf.trim_end_matches('\n').to_string())
}

// Link against libcrypt for crypt(3).
#[link(name = "crypt")]
extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
}

/// Verify a password against a crypt(3) hash.
///
/// Uses the POSIX `crypt(3)` function for verification.
fn verify_password(password: &str, hash: &str) -> Result<bool, NewgrpError> {
    let c_password =
        CString::new(password).map_err(|_| NewgrpError::Error("invalid password".into()))?;
    let c_hash = CString::new(hash).map_err(|_| NewgrpError::Error("invalid hash".into()))?;

    // SAFETY: crypt() is provided by libcrypt/glibc, both arguments are valid
    // null-terminated C strings. The returned pointer is to a static
    // buffer (or thread-local on glibc).
    let result = unsafe { crypt(c_password.as_ptr(), c_hash.as_ptr()) };

    if result.is_null() {
        return Ok(false);
    }

    // SAFETY: crypt returned a non-null pointer to a null-terminated string.
    let result_str = unsafe { std::ffi::CStr::from_ptr(result) };
    let result_str = result_str.to_str().unwrap_or("");

    Ok(result_str == hash)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    shadow_core::hardening::suppress_core_dumps();
    // We intentionally do NOT fully sanitize env for newgrp because it
    // needs to preserve $SHELL and $HOME for the new shell session.
    // However, we do save/restore SHELL before any env manipulation.
    let saved_shell = std::env::var("SHELL").ok();
    let saved_home = std::env::var("HOME").ok();
    shadow_core::hardening::sanitize_env();
    // Restore SHELL and HOME for the new shell session.
    if let Some(shell) = &saved_shell {
        std::env::set_var("SHELL", shell);
    }
    if let Some(home) = &saved_home {
        std::env::set_var("HOME", home);
    }

    let matches = match uu_app().try_get_matches_from(args) {
        Ok(m) => m,
        Err(e) => {
            e.print().ok();
            if !e.use_stderr() {
                return Ok(());
            }
            return Err(NewgrpError::AlreadyPrinted(1).into());
        }
    };

    let root = SysRoot::default();
    let username = get_current_username()?;
    let user_gid = get_current_gid()?;

    let group_name = matches.get_one::<String>(options::GROUP);

    // Resolve the target GID.
    let target_gid = if let Some(gname) = group_name {
        // Look up the group in /etc/group.
        let group_path = root.group_path();
        let groups = group::read_group_file(&group_path).map_err(|e| {
            NewgrpError::Error(format!("cannot read {}: {e}", group_path.display()))
        })?;

        let Some(group_entry) = groups.iter().find(|g| g.name == *gname) else {
            return Err(NewgrpError::Error(format!("group '{gname}' does not exist")).into());
        };

        let gid = group_entry.gid;

        // Check membership: if the user is not a member, they need the
        // group password. Root always gets in.
        if !caller_is_root() && !is_member(&username, user_gid, gid, &group_entry.members) {
            // Check if the group has a password in /etc/gshadow.
            let gshadow_path = root.gshadow_path();
            match group_has_password(&gshadow_path, gname) {
                Some(hash) => {
                    let password = read_password("Password: ")?;
                    if !verify_password(&password, &hash)? {
                        return Err(NewgrpError::Error("incorrect password".into()).into());
                    }
                }
                None => {
                    return Err(NewgrpError::Error(format!(
                        "permission denied for group '{gname}'"
                    ))
                    .into());
                }
            }
        }

        gid
    } else {
        // No group specified — change to user's primary group.
        user_gid
    };

    // Set the new GID.
    let gid = nix::unistd::Gid::from_raw(target_gid);
    nix::unistd::setgid(gid)
        .map_err(|e| NewgrpError::Error(format!("cannot set group ID to {target_gid}: {e}")))?;

    // Drop back to the real UID (in case we are setuid-root).
    let real_uid = nix::unistd::getuid();
    if nix::unistd::geteuid() != real_uid {
        nix::unistd::setuid(real_uid)
            .map_err(|e| NewgrpError::Error(format!("cannot drop privileges: {e}")))?;
    }

    // Exec the user's shell.
    let shell = get_shell();
    let shell_cstr = CString::new(shell.as_str())
        .map_err(|_| NewgrpError::Error("invalid shell path".into()))?;

    // Build argv: the shell name prefixed with '-' to indicate a login shell,
    // matching traditional newgrp behavior.
    let shell_basename = Path::new(&shell)
        .file_name()
        .map_or_else(|| "sh".to_string(), |n| n.to_string_lossy().to_string());
    let login_name = format!("-{shell_basename}");
    let login_cstr = CString::new(login_name.as_str())
        .map_err(|_| NewgrpError::Error("invalid shell name".into()))?;

    // SAFETY: execv replaces the current process. The CStrings are valid
    // and null-terminated. If execv fails, we return an error.
    match nix::unistd::execv(&shell_cstr, &[login_cstr]) {
        Ok(infallible) => match infallible {},
        Err(e) => Err(NewgrpError::Error(format!("cannot exec {shell}: {e}")).into()),
    }
}

/// Build the clap `Command` for `newgrp`.
#[must_use]
pub fn uu_app() -> Command {
    Command::new("newgrp")
        .about("Log in to a new group")
        .override_usage("newgrp [group]")
        .disable_version_flag(true)
        .arg(Arg::new(options::GROUP).help("Group to change to").index(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_builds() {
        uu_app().debug_assert();
    }

    // -----------------------------------------------------------------------
    // Membership tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_member_by_primary_gid() {
        assert!(is_member("alice", 1000, 1000, &[]));
    }

    #[test]
    fn test_is_member_by_group_list() {
        let members = vec!["alice".to_string(), "bob".to_string()];
        assert!(is_member("alice", 1000, 27, &members));
    }

    #[test]
    fn test_is_not_member() {
        let members = vec!["bob".to_string()];
        assert!(!is_member("alice", 1000, 27, &members));
    }

    // -----------------------------------------------------------------------
    // Group password tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_group_has_password_locked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gshadow");
        std::fs::write(&path, "testgroup:!::\n").expect("write");
        assert!(group_has_password(&path, "testgroup").is_none());
    }

    #[test]
    fn test_group_has_password_star() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gshadow");
        std::fs::write(&path, "testgroup:*::\n").expect("write");
        assert!(group_has_password(&path, "testgroup").is_none());
    }

    #[test]
    fn test_group_has_password_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gshadow");
        std::fs::write(&path, "testgroup:::\n").expect("write");
        assert!(group_has_password(&path, "testgroup").is_none());
    }

    #[test]
    fn test_group_has_password_with_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gshadow");
        std::fs::write(&path, "testgroup:$6$saltsalt$hashhere::\n").expect("write");
        let pw = group_has_password(&path, "testgroup");
        assert!(pw.is_some());
        assert_eq!(pw.expect("should have password"), "$6$saltsalt$hashhere");
    }

    #[test]
    fn test_group_has_password_nonexistent_group() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gshadow");
        std::fs::write(&path, "other:!::\n").expect("write");
        assert!(group_has_password(&path, "testgroup").is_none());
    }

    #[test]
    fn test_group_has_password_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nonexistent");
        assert!(group_has_password(&path, "testgroup").is_none());
    }

    // -----------------------------------------------------------------------
    // Clap validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_help_does_not_error() {
        let result = uu_app().try_get_matches_from(["newgrp", "--help"]);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(!err.use_stderr());
    }

    #[test]
    fn test_group_arg_parses() {
        let matches = uu_app()
            .try_get_matches_from(["newgrp", "docker"])
            .expect("should parse");
        assert_eq!(
            matches
                .get_one::<String>(options::GROUP)
                .map(String::as_str),
            Some("docker")
        );
    }

    #[test]
    fn test_no_group_arg_parses() {
        let matches = uu_app()
            .try_get_matches_from(["newgrp"])
            .expect("should parse");
        assert!(matches.get_one::<String>(options::GROUP).is_none());
    }

    // -----------------------------------------------------------------------
    // get_shell tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_shell_default() {
        // This test is environment-dependent but should at least not panic.
        let shell = get_shell();
        assert!(!shell.is_empty());
    }
}
