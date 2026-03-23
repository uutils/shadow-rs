// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore fsync

//! Atomic file replacement.
//!
//! Implements the write-tmp-then-rename pattern:
//! 1. Write to a temporary file in the same directory as the target
//! 2. `fsync` the temporary file
//! 3. `rename` the temporary file over the target (atomic on POSIX)

use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::error::ShadowError;

/// Atomically replace a file's contents.
///
/// Creates a temporary file in the same directory, writes content via the
/// provided closure, fsyncs, then renames over the target. If any step
/// fails, the temporary file is cleaned up and the original is untouched.
///
/// # Errors
///
/// Returns `ShadowError` if any I/O operation fails, or if the closure returns an error.
pub fn atomic_write<F>(target: &Path, f: F) -> Result<(), ShadowError>
where
    F: FnOnce(&mut File) -> Result<(), ShadowError>,
{
    let dir = target.parent().ok_or_else(|| {
        ShadowError::Other(format!("no parent directory for {}", target.display()))
    })?;

    let tmp_path = tmp_path_for(target);

    let mut tmp_file =
        File::create(&tmp_path).map_err(|e| ShadowError::IoPath(e, tmp_path.clone()))?;

    // Preserve original file permissions if the target exists.
    if let Ok(meta) = fs::metadata(target) {
        let permissions = meta.permissions();
        tmp_file
            .set_permissions(permissions)
            .map_err(|e| ShadowError::IoPath(e, tmp_path.clone()))?;
    }

    let result = f(&mut tmp_file);

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
        return result;
    }

    // Flush and fsync.
    tmp_file
        .flush()
        .map_err(|e| ShadowError::IoPath(e, tmp_path.clone()))?;
    nix::unistd::fsync(tmp_file.as_raw_fd())
        .map_err(|e| ShadowError::IoPath(io::Error::from(e), tmp_path.clone()))?;

    // Atomic rename.
    fs::rename(&tmp_path, target).map_err(|e| ShadowError::IoPath(e, target.to_owned()))?;

    // Fsync the parent directory to ensure the rename is durable.
    if let Ok(dir_fd) = File::open(dir) {
        let _ = nix::unistd::fsync(dir_fd.as_raw_fd());
    }

    Ok(())
}

/// Generate a temporary file path in the same directory as the target.
fn tmp_path_for(target: &Path) -> PathBuf {
    let file_name = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let pid = std::process::id();
    target.with_file_name(format!(".{file_name}.shadow-rs.{pid}.tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_atomic_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("test_file");

        atomic_write(&target, |f| {
            writeln!(f, "hello")?;
            Ok(())
        })
        .unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "hello\n");
    }

    #[test]
    fn test_atomic_write_replaces_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("test_file");
        fs::write(&target, "old content").unwrap();

        atomic_write(&target, |f| {
            write!(f, "new content")?;
            Ok(())
        })
        .unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "new content");
    }

    #[test]
    fn test_atomic_write_failure_preserves_original() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("test_file");
        fs::write(&target, "original").unwrap();

        let result = atomic_write(&target, |_f| {
            Err(ShadowError::Other("intentional failure".into()))
        });

        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "original");
    }

    #[test]
    fn test_tmp_path_is_hidden() {
        let target = Path::new("/etc/passwd");
        let tmp = tmp_path_for(target);
        let name = tmp.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with('.'));
        assert!(name.contains("shadow-rs"));
        assert!(name.ends_with(".tmp"));
    }
}
