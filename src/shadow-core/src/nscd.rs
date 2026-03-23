// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore nscd sssd

//! `nscd` (Name Service Cache Daemon) cache invalidation.
//!
//! After modifying `/etc/passwd`, `/etc/shadow`, or `/etc/group`,
//! the `nscd` cache must be invalidated so lookups reflect the changes.
//! Also supports `sssd` cache invalidation.

use std::process::Command;

/// Invalidate the `nscd` and `sssd` caches for the given database.
///
/// The `database` should be one of `"passwd"`, `"shadow"`, or `"group"`.
///
/// Silently succeeds if `nscd`/`sssd` is not installed or not running —
/// this matches GNU shadow-utils behavior.
pub fn invalidate_cache(database: &str) {
    // Use absolute paths to avoid PATH-based lookups in setuid context.
    let _ = Command::new("/usr/sbin/nscd")
        .arg("-i")
        .arg(database)
        .status();

    // sssd: sss_cache with the appropriate flag
    let flag = match database {
        "passwd" | "shadow" => "-U",
        "group" => "-G",
        _ => return,
    };
    let _ = Command::new("/usr/sbin/sss_cache").arg(flag).status();
}
