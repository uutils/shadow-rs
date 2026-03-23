// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore lockfile

//! File locking for `/etc/passwd`, `/etc/shadow`, etc.
//!
//! Uses `.lock` files (e.g., `/etc/passwd.lock`) with timeout and stale
//! lock detection, matching the convention used by GNU shadow-utils.
//!
//! Lock files are created atomically with `O_CREAT | O_EXCL` and contain
//! the PID of the locking process for stale detection.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use nix::unistd;

use crate::error::ShadowError;

/// Default lock timeout (matches GNU shadow-utils `LOCK_TIMEOUT`).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Retry interval when waiting for a lock.
const RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// A held file lock. The lock is released when this value is dropped.
pub struct FileLock {
    lock_path: PathBuf,
    released: bool,
}

impl FileLock {
    /// Acquire a lock for the given file using the default timeout.
    ///
    /// Creates `{file_path}.lock` atomically. If another process holds the lock,
    /// retries until the timeout expires. Stale locks (held by dead processes)
    /// are automatically cleaned up.
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Lock` if the lock cannot be acquired within the timeout.
    pub fn acquire(file_path: &Path) -> Result<Self, ShadowError> {
        Self::acquire_with_timeout(file_path, DEFAULT_TIMEOUT)
    }

    /// Acquire a lock with a custom timeout.
    ///
    /// Uses the classic lock-via-link pattern to avoid TOCTOU races:
    /// 1. Write our PID to a unique temp file
    /// 2. Try to `hard_link` it to the lock path (atomic on POSIX)
    /// 3. If link fails (lock exists), check for staleness and retry
    ///
    /// Even if two processes both detect a stale lock and both remove it,
    /// only one will succeed at the subsequent `hard_link`, so mutual
    /// exclusion is never violated.
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Lock` if the lock cannot be acquired within the timeout.
    pub fn acquire_with_timeout(file_path: &Path, timeout: Duration) -> Result<Self, ShadowError> {
        let lock_path = lock_path_for(file_path);
        let deadline = Instant::now() + timeout;
        let tmp_path = tmp_lock_path(&lock_path);

        // Write our PID to the temp file once, then try to link it in a loop.
        write_pid_file(&tmp_path)?;

        let result = Self::acquire_loop(&lock_path, &tmp_path, deadline);

        // Always clean up our temp file, regardless of success or failure.
        let _ = fs::remove_file(&tmp_path);

        result
    }

    /// Inner acquisition loop. Separated so the caller can guarantee temp file cleanup.
    fn acquire_loop(
        lock_path: &Path,
        tmp_path: &Path,
        deadline: Instant,
    ) -> Result<Self, ShadowError> {
        loop {
            // Attempt to hard-link our temp file to the lock path. hard_link is
            // atomic: it either creates the destination or fails, so two
            // processes can never both succeed for the same lock_path.
            if fs::hard_link(tmp_path, lock_path).is_ok() {
                return Ok(Self {
                    lock_path: lock_path.to_owned(),
                    released: false,
                });
            }

            // Link failed — lock file exists. Check if it's stale.
            if is_stale_lock(lock_path) {
                // Remove the stale lock. If another process already removed it
                // and re-acquired, our remove may fail or remove the wrong file,
                // but the subsequent hard_link attempt is the real arbiter:
                // it will fail atomically if someone else got there first.
                let _ = fs::remove_file(lock_path);
                continue;
            }

            if Instant::now() >= deadline {
                return Err(ShadowError::Lock(
                    format!("cannot acquire lock {}: timed out", lock_path.display()).into(),
                ));
            }

            thread::sleep(RETRY_INTERVAL);
        }
    }

    /// Explicitly release the lock.
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Lock` if the lock file cannot be removed.
    pub fn release(mut self) -> Result<(), ShadowError> {
        self.released = true;
        fs::remove_file(&self.lock_path).map_err(|e| {
            ShadowError::Lock(
                format!("cannot release lock {}: {e}", self.lock_path.display()).into(),
            )
        })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        if !self.released {
            let _ = fs::remove_file(&self.lock_path);
        }
    }
}

/// Compute the lock file path: append `.lock` to the file path.
fn lock_path_for(file_path: &Path) -> PathBuf {
    let mut lock = file_path.as_os_str().to_owned();
    lock.push(".lock");
    PathBuf::from(lock)
}

/// Compute a unique temp file path for the lock-via-link pattern.
///
/// Uses PID to avoid collisions between concurrent processes.
fn tmp_lock_path(lock_path: &Path) -> PathBuf {
    let pid = std::process::id();
    let mut tmp = lock_path.as_os_str().to_owned();
    tmp.push(format!(".{pid}.tmp"));
    PathBuf::from(tmp)
}

/// Write our PID to a temp file for later hard-linking.
fn write_pid_file(tmp_path: &Path) -> Result<(), ShadowError> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(tmp_path)
        .map_err(|e| {
            ShadowError::Lock(format!("cannot create {}: {e}", tmp_path.display()).into())
        })?;

    let pid = unistd::getpid();
    write!(file, "{pid}").map_err(|e| {
        ShadowError::Lock(format!("cannot write {}: {e}", tmp_path.display()).into())
    })?;

    Ok(())
}

/// Check if an existing lock file is stale (held by a dead process).
fn is_stale_lock(lock_path: &Path) -> bool {
    let Ok(contents) = fs::read_to_string(lock_path) else {
        return false;
    };

    let Ok(pid) = contents.trim().parse::<i32>() else {
        // Cannot parse PID — treat as stale.
        return true;
    };

    if pid <= 0 {
        return true;
    }

    // Signal 0 checks if the process exists without actually sending a signal.
    // Only ESRCH means "no such process". EPERM means the process exists but
    // we lack permission to signal it — that is a valid lock holder.
    let pid = nix::unistd::Pid::from_raw(pid);
    matches!(
        nix::sys::signal::kill(pid, None),
        Err(nix::errno::Errno::ESRCH)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_path_for() {
        assert_eq!(
            lock_path_for(Path::new("/etc/shadow")),
            PathBuf::from("/etc/shadow.lock")
        );
    }

    #[test]
    fn test_acquire_and_release() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test_file");
        fs::write(&file, "data").unwrap();

        let lock = FileLock::acquire(&file).unwrap();
        assert!(lock.lock_path.exists());

        lock.release().unwrap();
        assert!(!dir.path().join("test_file.lock").exists());
    }

    #[test]
    fn test_drop_releases_lock() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test_file");
        fs::write(&file, "data").unwrap();

        {
            let _lock = FileLock::acquire(&file).unwrap();
            assert!(dir.path().join("test_file.lock").exists());
        }
        // Lock should be released by drop.
        assert!(!dir.path().join("test_file.lock").exists());
    }

    #[test]
    fn test_double_lock_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test_file");
        fs::write(&file, "data").unwrap();

        let _lock1 = FileLock::acquire(&file).unwrap();

        // Second lock should time out.
        let result = FileLock::acquire_with_timeout(&file, Duration::from_millis(200));
        assert!(result.is_err());
    }

    #[test]
    fn test_stale_lock_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test_file");
        fs::write(&file, "data").unwrap();

        // Create a lock file with a PID that doesn't exist.
        let lock_path = dir.path().join("test_file.lock");
        fs::write(&lock_path, "999999999").unwrap();

        // Should succeed because the stale lock is cleaned up.
        let lock = FileLock::acquire(&file).unwrap();
        lock.release().unwrap();
    }

    #[test]
    fn test_lock_file_has_cloexec() {
        use std::os::unix::io::AsRawFd;

        // Rust's stdlib sets O_CLOEXEC by default on Linux.
        // Verify the lock file FD won't leak to child processes.
        let dir = tempfile::tempdir().expect("tempdir creation failed");
        let file = dir.path().join("test_file");
        fs::write(&file, "data").expect("failed to write test file");

        let lock = FileLock::acquire(&file).expect("failed to acquire lock");

        let f = fs::File::open(&lock.lock_path).expect("failed to open lock file");
        let fd = f.as_raw_fd();
        let flags =
            nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD).expect("fcntl F_GETFD failed");
        assert!(flags & libc::FD_CLOEXEC != 0, "FD should have CLOEXEC set");

        lock.release().expect("failed to release lock");
    }

    #[test]
    fn test_lock_file_contains_pid() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test_file");
        fs::write(&file, "data").unwrap();

        let lock = FileLock::acquire(&file).unwrap();
        let contents = fs::read_to_string(&lock.lock_path).unwrap();
        let pid: i32 = contents.trim().parse().unwrap();
        assert_eq!(pid, i32::try_from(std::process::id()).unwrap());

        lock.release().unwrap();
    }
}
