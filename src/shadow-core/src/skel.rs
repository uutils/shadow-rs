// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Copy `/etc/skel` directory contents into a new home directory.
//!
//! When `useradd -m` creates a home directory, it populates it with
//! files from the skeleton directory (typically `/etc/skel`).

use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::atomic::UmaskGuard;
use crate::error::ShadowError;

/// Recursively copy the skeleton directory into the target home directory.
///
/// Sets ownership of all copied files and directories to the given `uid`/`gid`.
/// Preserves file permissions. Recreates symlinks without following them.
///
/// If `skel_dir` does not exist, returns `Ok(())` (nothing to copy).
///
/// # Errors
///
/// Returns `ShadowError` on I/O failures or if ownership cannot be set.
pub fn copy_skel(skel_dir: &Path, home_dir: &Path, uid: u32, gid: u32) -> Result<(), ShadowError> {
    if !skel_dir.exists() {
        return Ok(());
    }

    // Reset umask so the modes passed to mkdir/open are honored exactly.
    // Without this, an inherited umask would leave copied files and
    // subdirectories more permissive than the source until set_permissions
    // is called — a window during which they are owned by root.
    let _umask = UmaskGuard::zero();

    copy_dir_recursive(skel_dir, home_dir, uid, gid)
}

fn copy_dir_recursive(src: &Path, dst: &Path, uid: u32, gid: u32) -> Result<(), ShadowError> {
    let entries = std::fs::read_dir(src).map_err(|e| ShadowError::IoPath(e, src.to_owned()))?;

    for entry in entries {
        let entry = entry.map_err(|e| ShadowError::IoPath(e, src.to_owned()))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_type = entry
            .file_type()
            .map_err(|e| ShadowError::IoPath(e, src_path.clone()))?;

        if file_type.is_dir() {
            // Preserve the source directory's permissions atomically by
            // passing the mode to mkdir(2) via DirBuilder. Mask to permission
            // and special bits only — `mode()` returns raw st_mode which
            // includes file-type bits we must not pass to mkdir.
            let src_mode = std::fs::metadata(&src_path)
                .map_err(|e| ShadowError::IoPath(e, src_path.clone()))?
                .permissions()
                .mode()
                & 0o7777;
            std::fs::DirBuilder::new()
                .mode(src_mode)
                .create(&dst_path)
                .map_err(|e| ShadowError::IoPath(e, dst_path.clone()))?;
            copy_dir_recursive(&src_path, &dst_path, uid, gid)?;
        } else if file_type.is_symlink() {
            let target = std::fs::read_link(&src_path)
                .map_err(|e| ShadowError::IoPath(e, src_path.clone()))?;
            std::os::unix::fs::symlink(&target, &dst_path)
                .map_err(|e| ShadowError::IoPath(e, dst_path.clone()))?;
        } else if file_type.is_file() {
            // std::fs::copy uses File::create internally, which applies the
            // umask and leaves a window where the file is more permissive
            // than the source. Open the destination with the source's mode
            // baked into the open(2) call instead. Mask raw st_mode to
            // permission and special bits only.
            let src_mode = std::fs::metadata(&src_path)
                .map_err(|e| ShadowError::IoPath(e, src_path.clone()))?
                .permissions()
                .mode()
                & 0o7777;
            let mut src_file = std::fs::File::open(&src_path)
                .map_err(|e| ShadowError::IoPath(e, src_path.clone()))?;
            let mut dst_file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(src_mode)
                .open(&dst_path)
                .map_err(|e| ShadowError::IoPath(e, dst_path.clone()))?;
            std::io::copy(&mut src_file, &mut dst_file)
                .map_err(|e| ShadowError::IoPath(e, dst_path.clone()))?;
        }
        // Silently skip FIFOs, sockets, and device nodes — copying them
        // would block indefinitely (FIFOs) or create security issues (devices).
        else {
            continue;
        }

        // Set ownership (lchown for symlinks — doesn't follow the target).
        std::os::unix::fs::lchown(&dst_path, Some(uid), Some(gid))
            .map_err(|e| ShadowError::IoPath(e, dst_path))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonexistent_skel_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let result = copy_skel(
            &dir.path().join("no-such-skel"),
            &dir.path().join("home"),
            1000,
            1000,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_copy_files() {
        if !rustix::process::geteuid().is_root() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let skel = dir.path().join("skel");
        let home = dir.path().join("home");
        std::fs::create_dir_all(&skel).unwrap();
        std::fs::create_dir_all(&home).unwrap();

        std::fs::write(skel.join(".bashrc"), "# bashrc\n").unwrap();
        std::fs::write(skel.join(".profile"), "# profile\n").unwrap();

        copy_skel(&skel, &home, 1000, 1000).unwrap();

        assert!(home.join(".bashrc").exists());
        assert!(home.join(".profile").exists());
        assert_eq!(
            std::fs::read_to_string(home.join(".bashrc")).unwrap(),
            "# bashrc\n"
        );
    }

    #[test]
    fn test_copy_subdirectory() {
        if !rustix::process::geteuid().is_root() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let skel = dir.path().join("skel");
        let home = dir.path().join("home");
        std::fs::create_dir_all(skel.join(".config/subdir")).unwrap();
        std::fs::create_dir_all(&home).unwrap();

        std::fs::write(skel.join(".config/subdir/file.txt"), "content").unwrap();

        copy_skel(&skel, &home, 1000, 1000).unwrap();

        assert!(home.join(".config/subdir/file.txt").exists());
    }

    #[test]
    fn test_copy_symlink() {
        if !rustix::process::geteuid().is_root() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let skel = dir.path().join("skel");
        let home = dir.path().join("home");
        std::fs::create_dir_all(&skel).unwrap();
        std::fs::create_dir_all(&home).unwrap();

        std::fs::write(skel.join("real_file"), "data").unwrap();
        std::os::unix::fs::symlink("real_file", skel.join("link")).unwrap();

        copy_skel(&skel, &home, 1000, 1000).unwrap();

        assert!(home.join("link").exists());
        let target = std::fs::read_link(home.join("link")).unwrap();
        assert_eq!(target.to_str().unwrap(), "real_file");
    }
}
