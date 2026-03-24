// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! `SELinux` security context handling for file operations.
//!
//! When `SELinux` is enforcing, newly created files must have the correct
//! security context. This module provides functions to get and set file
//! contexts during atomic file replacement.
//!
//! Feature-gated behind `selinux`. When disabled, all operations are no-ops.

use std::path::Path;

use crate::error::ShadowError;

/// Copy the `SELinux` security context from the source file to the destination.
///
/// Best-effort: silently succeeds if `SELinux` is not available, not enforcing,
/// or if context operations fail. This matches GNU shadow-utils behavior where
/// SELinux context handling is non-fatal.
pub fn copy_file_context(source: &Path, dest: &Path) -> Result<(), ShadowError> {
    // Implementation requires libselinux FFI.
    // For now, attempt to use the `setfilecon` command-line tool as a fallback.
    let source_ctx = get_file_context(source);
    if let Some(ctx) = source_ctx {
        set_file_context(dest, &ctx)?;
    }
    Ok(())
}

/// Get the `SELinux` security context of a file.
///
/// Returns `None` if `SELinux` is not available or the file has no context.
fn get_file_context(path: &Path) -> Option<String> {
    // Use the `getfattr` command to read the security.selinux xattr.
    let output = std::process::Command::new("/usr/bin/getfattr")
        .arg("--only-values")
        .arg("-n")
        .arg("security.selinux")
        .arg(path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .output()
        .ok()?;

    if output.status.success() {
        let ctx = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if ctx.is_empty() { None } else { Some(ctx) }
    } else {
        None
    }
}

/// Set the `SELinux` security context of a file.
fn set_file_context(path: &Path, context: &str) -> Result<(), ShadowError> {
    let status = std::process::Command::new("/usr/bin/chcon")
        .arg(context)
        .arg(path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .status();

    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(_) => {
            // chcon failed — non-fatal, SELinux may not be enforcing.
            Ok(())
        }
        Err(_) => {
            // chcon not found — SELinux not available, silently succeed.
            Ok(())
        }
    }
}

/// Restore the default `SELinux` context for a file based on policy.
///
/// Best-effort equivalent of `restorecon <path>`. Silently succeeds if
/// `SELinux` is not available or `restorecon` is not installed.
pub fn restore_default_context(path: &Path) -> Result<(), ShadowError> {
    let _ = std::process::Command::new("/usr/sbin/restorecon")
        .arg(path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .status();
    Ok(())
}
