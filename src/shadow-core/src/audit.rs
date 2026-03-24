// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Audit logging for shadow-rs tools.
//!
//! On systems with `auditd` running, shadow-utils operations (password
//! changes, account creation/deletion, group changes) should be logged
//! to the audit subsystem.
//!
//! This module provides a best-effort logging interface that silently
//! succeeds when audit is not available.

/// Log a user account event to the audit subsystem.
///
/// `event_type` should be one of: `ADD_USER`, `DEL_USER`, `MOD_USER`,
/// `ADD_GROUP`, `DEL_GROUP`, `MOD_GROUP`, `CHNG_PASSWD`.
///
/// Silently succeeds if auditd is not running or audit tools are not
/// installed.
pub fn log_user_event(event_type: &str, username: &str, uid: u32, result: bool) {
    let success = if result { "success" } else { "failed" };
    let msg = format!(
        "op={event_type} acct=\"{username}\" exe=\"shadow-rs\" \
         hostname=? addr=? terminal=? res={success}"
    );

    // Use /sbin/auditctl or write to /dev/audit if available.
    // For now, use logger as a fallback to syslog.
    let _ = std::process::Command::new("/usr/bin/logger")
        .arg("-t")
        .arg("shadow-rs")
        .arg("-p")
        .arg("auth.info")
        .arg(&msg)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .status();

    // Also attempt to use ausearch-compatible format via audisp.
    let _ = std::process::Command::new("/sbin/auditctl")
        .arg("-m")
        .arg(format!(
            "shadow-rs: {event_type} user={username} uid={uid} res={success}"
        ))
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .status();
}
