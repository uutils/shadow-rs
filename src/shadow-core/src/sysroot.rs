// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore chroot sysroot

//! System root path resolver for `--root` and `--prefix` support.
//!
//! `--prefix DIR` prepends DIR to all file paths (no `chroot` syscall).
//! `--root DIR` does an actual `chroot()` — paths are then relative to `/`.

use std::path::{Component, Path, PathBuf};

/// Resolves file paths relative to an optional prefix directory.
#[derive(Debug, Clone)]
pub struct SysRoot {
    prefix: PathBuf,
}

impl SysRoot {
    /// Create a new `SysRoot` with the given prefix.
    ///
    /// If `prefix` is `None`, paths resolve against the real root `/`.
    #[must_use]
    pub fn new(prefix: Option<&Path>) -> Self {
        Self {
            prefix: prefix.unwrap_or_else(|| Path::new("/")).to_owned(),
        }
    }

    /// Resolve a path relative to the prefix.
    ///
    /// Strips leading `/` from `relative` before joining with the prefix.
    /// Returns `None` if the path contains `..` components (path traversal).
    pub fn try_resolve(&self, relative: &str) -> Option<PathBuf> {
        let stripped = relative.strip_prefix('/').unwrap_or(relative);
        let joined = self.prefix.join(stripped);
        // Reject path traversal: ".." components could escape the prefix.
        for component in joined.components() {
            if matches!(component, Component::ParentDir) {
                return None;
            }
        }
        Some(joined)
    }

    /// Resolve a path relative to the prefix.
    ///
    /// Strips leading `/` from `relative` before joining with the prefix.
    /// Only for hardcoded paths — use [`try_resolve`] for user-controlled input.
    #[must_use]
    pub fn resolve(&self, relative: &str) -> PathBuf {
        // All callers pass hardcoded paths like "/etc/passwd" — never ".."
        self.try_resolve(relative)
            .unwrap_or_else(|| unreachable!("resolve() called with path traversal: {relative:?}"))
    }

    /// Path to `/etc/passwd`.
    #[must_use]
    pub fn passwd_path(&self) -> PathBuf {
        self.resolve("/etc/passwd")
    }

    /// Path to `/etc/shadow`.
    #[must_use]
    pub fn shadow_path(&self) -> PathBuf {
        self.resolve("/etc/shadow")
    }

    /// Path to `/etc/group`.
    #[must_use]
    pub fn group_path(&self) -> PathBuf {
        self.resolve("/etc/group")
    }

    /// Path to `/etc/gshadow`.
    #[must_use]
    pub fn gshadow_path(&self) -> PathBuf {
        self.resolve("/etc/gshadow")
    }

    /// Path to `/etc/login.defs`.
    #[must_use]
    pub fn login_defs_path(&self) -> PathBuf {
        self.resolve("/etc/login.defs")
    }

    /// Path to `/etc/subuid`.
    #[must_use]
    pub fn subuid_path(&self) -> PathBuf {
        self.resolve("/etc/subuid")
    }

    /// Path to `/etc/subgid`.
    #[must_use]
    pub fn subgid_path(&self) -> PathBuf {
        self.resolve("/etc/subgid")
    }

    /// Path to `/etc/skel`.
    #[must_use]
    pub fn skel_path(&self) -> PathBuf {
        self.resolve("/etc/skel")
    }

    /// Path to `/etc/shells`.
    #[must_use]
    pub fn shells_path(&self) -> PathBuf {
        self.resolve("/etc/shells")
    }
}

impl Default for SysRoot {
    fn default() -> Self {
        Self::new(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_root() {
        let root = SysRoot::default();
        assert_eq!(root.shadow_path(), PathBuf::from("/etc/shadow"));
        assert_eq!(root.passwd_path(), PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn test_with_prefix() {
        let root = SysRoot::new(Some(Path::new("/tmp/test")));
        assert_eq!(root.shadow_path(), PathBuf::from("/tmp/test/etc/shadow"));
        assert_eq!(root.passwd_path(), PathBuf::from("/tmp/test/etc/passwd"));
        assert_eq!(
            root.login_defs_path(),
            PathBuf::from("/tmp/test/etc/login.defs")
        );
    }

    #[test]
    fn test_resolve_strips_leading_slash() {
        let root = SysRoot::new(Some(Path::new("/mnt")));
        assert_eq!(
            root.resolve("/etc/shadow"),
            PathBuf::from("/mnt/etc/shadow")
        );
        assert_eq!(root.resolve("etc/shadow"), PathBuf::from("/mnt/etc/shadow"));
    }

    #[test]
    fn test_try_resolve_rejects_path_traversal() {
        let root = SysRoot::new(Some(Path::new("/mnt/chroot")));
        // Attempting to escape the prefix via ".." returns None.
        assert_eq!(root.try_resolve("/../etc/shadow"), None);
        assert_eq!(root.try_resolve("/home/../../etc/shadow"), None);
    }

    #[test]
    fn test_try_resolve_accepts_valid_paths() {
        let root = SysRoot::new(Some(Path::new("/mnt/chroot")));
        assert_eq!(
            root.try_resolve("/etc/shadow"),
            Some(PathBuf::from("/mnt/chroot/etc/shadow"))
        );
    }
}
