// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore chpasswd chroot sigprocmask yescrypt

//! `chpasswd` — update passwords in batch mode.
//!
//! Drop-in replacement for GNU shadow-utils `chpasswd(8)`.
//! Reads `username:password` pairs from stdin and updates `/etc/shadow`.

use std::fmt;
use std::io::{self, BufRead};
use std::path::Path;

use clap::{Arg, ArgAction, Command};

use shadow_core::lock::FileLock;
use shadow_core::shadow::{self};
use shadow_core::sysroot::SysRoot;
use shadow_core::{atomic, nscd};

use uucore::error::{UError, UResult};

mod options {
    pub const CRYPT_METHOD: &str = "crypt-method";
    pub const ENCRYPTED: &str = "encrypted";
    pub const MD5: &str = "md5";
    pub const ROOT: &str = "root";
    pub const SHA_ROUNDS: &str = "sha-rounds";
}

// ---------------------------------------------------------------------------
// Error type — implements uucore::error::UError
// ---------------------------------------------------------------------------

/// Errors that the `chpasswd` utility can produce.
///
/// GNU `chpasswd(8)` exits 1 for all errors.
#[derive(Debug)]
enum ChpasswdError {
    /// Exit 1 — insufficient privileges.
    PermissionDenied(String),
    /// Exit 1 — an unexpected runtime failure.
    UnexpectedFailure(String),
    /// Exit 1 — could not acquire the shadow lock file.
    FileBusy(String),
    /// Exit 1 — invalid input line.
    InvalidInput(String),
    /// Sentinel used when the error has already been printed (e.g. by clap).
    AlreadyPrinted(i32),
}

impl fmt::Display for ChpasswdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied(msg)
            | Self::UnexpectedFailure(msg)
            | Self::FileBusy(msg)
            | Self::InvalidInput(msg) => f.write_str(msg),
            Self::AlreadyPrinted(_) => Ok(()),
        }
    }
}

impl std::error::Error for ChpasswdError {}

impl UError for ChpasswdError {
    fn code(&self) -> i32 {
        match self {
            Self::PermissionDenied(_)
            | Self::UnexpectedFailure(_)
            | Self::FileBusy(_)
            | Self::InvalidInput(_) => 1,
            Self::AlreadyPrinted(code) => *code,
        }
    }
}

// Hardening functions are now centralized in shadow_core::hardening.

// ---------------------------------------------------------------------------
// Signal blocking during critical sections
// ---------------------------------------------------------------------------

/// RAII guard that blocks signals during critical sections and restores on drop.
struct SignalBlocker {
    old_mask: nix::sys::signal::SigSet,
}

impl SignalBlocker {
    /// Block `SIGINT`, `SIGTERM`, `SIGHUP` to prevent partial file writes.
    fn block_critical() -> Result<Self, ChpasswdError> {
        use nix::sys::signal::{SigSet, SigmaskHow, Signal};

        let mut block_set = SigSet::empty();
        block_set.add(Signal::SIGINT);
        block_set.add(Signal::SIGTERM);
        block_set.add(Signal::SIGHUP);

        let mut old_mask = SigSet::empty();
        nix::sys::signal::sigprocmask(SigmaskHow::SIG_BLOCK, Some(&block_set), Some(&mut old_mask))
            .map_err(|e| ChpasswdError::UnexpectedFailure(format!("cannot block signals: {e}")))?;

        Ok(Self { old_mask })
    }
}

impl Drop for SignalBlocker {
    fn drop(&mut self) {
        let _ = nix::sys::signal::sigprocmask(
            nix::sys::signal::SigmaskHow::SIG_SETMASK,
            Some(&self.old_mask),
            None,
        );
    }
}

// ---------------------------------------------------------------------------
// Input parsing
// ---------------------------------------------------------------------------

/// A parsed `username:password` pair from stdin.
///
/// The password field uses `Zeroizing` to ensure it is scrubbed from
/// memory when dropped, preventing password leaks via core dumps or
/// heap inspection.
struct PasswordPair {
    username: String,
    password: zeroize::Zeroizing<String>,
}

/// Parse a single input line into a `username:password` pair.
///
/// The format is `username:password` where username cannot be empty
/// and the password is everything after the first colon (may be empty
/// only if the `-e` flag is used).
fn parse_input_line(line: &str, line_number: usize) -> Result<PasswordPair, ChpasswdError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(ChpasswdError::InvalidInput(format!(
            "line {line_number}: empty line"
        )));
    }

    let colon_pos = trimmed.find(':').ok_or_else(|| {
        ChpasswdError::InvalidInput(format!("line {line_number}: missing ':' separator"))
    })?;

    let username = &trimmed[..colon_pos];
    let password = &trimmed[colon_pos + 1..];

    if username.is_empty() {
        return Err(ChpasswdError::InvalidInput(format!(
            "line {line_number}: empty username"
        )));
    }

    Ok(PasswordPair {
        username: username.to_string(),
        password: zeroize::Zeroizing::new(password.to_string()),
    })
}

/// Read all `username:password` pairs from stdin.
fn read_pairs_from_stdin() -> Result<Vec<PasswordPair>, ChpasswdError> {
    let stdin = io::stdin();
    let reader = stdin.lock();
    let mut pairs = Vec::new();

    for (idx, line) in reader.lines().enumerate() {
        let line = line
            .map_err(|e| ChpasswdError::UnexpectedFailure(format!("error reading stdin: {e}")))?;

        // Skip empty lines.
        if line.trim().is_empty() {
            continue;
        }

        pairs.push(parse_input_line(&line, idx + 1)?);
    }

    if pairs.is_empty() {
        return Err(ChpasswdError::InvalidInput(
            "no username:password pairs provided on stdin".into(),
        ));
    }

    Ok(pairs)
}

/// Compute the current day since epoch (for `last_change` field).
fn days_since_epoch() -> i64 {
    // SAFETY: time(NULL) is always safe.
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    now / 86400
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for the `chpasswd` utility.
#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    shadow_core::hardening::harden_process();

    let matches = match uu_app().try_get_matches_from(args) {
        Ok(m) => m,
        Err(e) => {
            e.print().ok();
            if !e.use_stderr() {
                return Ok(());
            }
            return Err(ChpasswdError::AlreadyPrinted(1).into());
        }
    };

    // Handle --root / -R: chroot before anything else.
    if let Some(chroot_dir) = matches.get_one::<String>(options::ROOT) {
        do_chroot(chroot_dir)?;
    }

    let root = SysRoot::default();

    // chpasswd always requires root.
    if !caller_is_root() {
        return Err(ChpasswdError::PermissionDenied("Permission denied.".into()).into());
    }

    let is_encrypted = matches.get_flag(options::ENCRYPTED);
    let _use_md5 = matches.get_flag(options::MD5);
    let _crypt_method = matches.get_one::<String>(options::CRYPT_METHOD);
    let _sha_rounds = matches.get_one::<i64>(options::SHA_ROUNDS);

    // Hashing support: only pre-encrypted mode (-e) is currently supported.
    // For non-encrypted mode, we would need libc::crypt or a pure-Rust
    // implementation. For now, give a clear error.
    if !is_encrypted {
        return Err(ChpasswdError::UnexpectedFailure(
            "plaintext password hashing is not yet implemented; \
             use -e/--encrypted with pre-hashed passwords, \
             or pipe through 'openssl passwd -6' first"
                .into(),
        )
        .into());
    }

    // Read all pairs from stdin before acquiring locks.
    let pairs = read_pairs_from_stdin()?;

    // Apply all password changes in a single locked transaction.
    apply_password_changes(&root, &pairs)
}

/// Build the clap `Command` for `chpasswd`.
#[must_use]
pub fn uu_app() -> Command {
    Command::new("chpasswd")
        .about("Update passwords in batch mode")
        .override_usage("chpasswd [options]")
        .disable_version_flag(true)
        .arg(
            Arg::new(options::CRYPT_METHOD)
                .short('c')
                .long("crypt-method")
                .help("the crypt method (SHA256, SHA512, YESCRYPT, etc.)")
                .value_name("METHOD")
                .value_parser(["SHA256", "SHA512", "YESCRYPT", "DES", "MD5"]),
        )
        .arg(
            Arg::new(options::ENCRYPTED)
                .short('e')
                .long("encrypted")
                .help("supplied passwords are encrypted (pre-hashed)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::MD5)
                .short('m')
                .long("md5")
                .help("encrypt the clear text password using the MD5 algorithm (deprecated)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::ROOT)
                .short('R')
                .long("root")
                .help("directory to chroot into")
                .value_name("CHROOT_DIR"),
        )
        .arg(
            Arg::new(options::SHA_ROUNDS)
                .short('s')
                .long("sha-rounds")
                .help("number of SHA rounds for SHA256/SHA512 crypt method")
                .value_name("ROUNDS")
                .value_parser(clap::value_parser!(i64)),
        )
}

// ---------------------------------------------------------------------------
// Command implementation
// ---------------------------------------------------------------------------

/// Apply all password changes to `/etc/shadow` in a single locked transaction.
fn apply_password_changes(root: &SysRoot, pairs: &[PasswordPair]) -> UResult<()> {
    // Consolidate real + effective UID to root for file operations.
    if nix::unistd::geteuid().is_root() {
        let _ = nix::unistd::setuid(nix::unistd::Uid::from_raw(0));
    }

    // Block signals for the entire critical section.
    let _signals = SignalBlocker::block_critical()?;

    let shadow_path = root.shadow_path();

    // Acquire lock.
    let lock = FileLock::acquire(&shadow_path).map_err(|_| {
        ChpasswdError::FileBusy(format!(
            "cannot lock {}: try again later",
            shadow_path.display()
        ))
    })?;

    // Read current entries.
    let mut entries = match shadow::read_shadow_file(&shadow_path) {
        Ok(e) => e,
        Err(e) => {
            drop(lock);
            return Err(ChpasswdError::UnexpectedFailure(format!(
                "Cannot open {}: {e}",
                shadow_path.display()
            ))
            .into());
        }
    };

    let today = days_since_epoch();

    // Apply each pair.
    for pair in pairs {
        let Some(entry) = entries.iter_mut().find(|e| e.name == pair.username) else {
            drop(lock);
            return Err(ChpasswdError::InvalidInput(format!(
                "user '{}' does not exist in {}",
                pair.username,
                shadow_path.display()
            ))
            .into());
        };

        // Update the password hash and last_change date.
        entry.passwd.clone_from(&*pair.password);
        entry.last_change = Some(today);
    }

    // Write back atomically.
    let write_result = atomic::atomic_write(&shadow_path, |file| {
        shadow::write_shadow(&entries, file)?;
        Ok(())
    });

    if let Err(e) = write_result {
        drop(lock);
        return Err(ChpasswdError::UnexpectedFailure(format!(
            "failed to write {}: {e}",
            shadow_path.display()
        ))
        .into());
    }

    // Release lock and invalidate caches.
    drop(lock);
    nscd::invalidate_cache("shadow");

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if the *real* caller is root (not just setuid-root).
fn caller_is_root() -> bool {
    nix::unistd::getuid().is_root()
}

/// Perform `chroot(2)` into the specified directory.
fn do_chroot(dir: &str) -> Result<(), ChpasswdError> {
    if !caller_is_root() {
        return Err(ChpasswdError::PermissionDenied(
            "only root may use --root".into(),
        ));
    }

    let path = Path::new(dir);
    nix::unistd::chroot(path)
        .map_err(|e| ChpasswdError::UnexpectedFailure(format!("cannot chroot to '{dir}': {e}")))?;

    nix::unistd::chdir("/").map_err(|e| {
        ChpasswdError::UnexpectedFailure(format!("cannot chdir to / after chroot: {e}"))
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Basic clap / app tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_app_builds() {
        uu_app().debug_assert();
    }

    #[test]
    fn test_encrypted_flag() {
        let m = uu_app()
            .try_get_matches_from(["chpasswd", "-e"])
            .expect("should parse -e flag");
        assert!(m.get_flag(options::ENCRYPTED));
    }

    #[test]
    fn test_md5_flag() {
        let m = uu_app()
            .try_get_matches_from(["chpasswd", "-m"])
            .expect("should parse -m flag");
        assert!(m.get_flag(options::MD5));
    }

    #[test]
    fn test_crypt_method_valid() {
        let m = uu_app()
            .try_get_matches_from(["chpasswd", "-c", "SHA512"])
            .expect("should parse -c SHA512");
        assert_eq!(
            m.get_one::<String>(options::CRYPT_METHOD)
                .map(String::as_str),
            Some("SHA512")
        );
    }

    #[test]
    fn test_crypt_method_invalid() {
        let result = uu_app().try_get_matches_from(["chpasswd", "-c", "INVALID"]);
        assert!(result.is_err(), "invalid crypt method should fail");
    }

    #[test]
    fn test_sha_rounds_flag() {
        let m = uu_app()
            .try_get_matches_from(["chpasswd", "-s", "5000"])
            .expect("should parse -s 5000");
        assert_eq!(m.get_one::<i64>(options::SHA_ROUNDS).copied(), Some(5000));
    }

    #[test]
    fn test_root_flag() {
        let m = uu_app()
            .try_get_matches_from(["chpasswd", "-R", "/mnt/chroot"])
            .expect("should parse -R flag");
        assert_eq!(
            m.get_one::<String>(options::ROOT).map(String::as_str),
            Some("/mnt/chroot")
        );
    }

    #[test]
    fn test_combined_flags() {
        let m = uu_app()
            .try_get_matches_from(["chpasswd", "-e", "-R", "/mnt"])
            .expect("should parse combined flags");
        assert!(m.get_flag(options::ENCRYPTED));
        assert_eq!(
            m.get_one::<String>(options::ROOT).map(String::as_str),
            Some("/mnt")
        );
    }

    #[test]
    fn test_all_crypt_methods() {
        for method in &["SHA256", "SHA512", "YESCRYPT", "DES", "MD5"] {
            let m = uu_app()
                .try_get_matches_from(["chpasswd", "-c", method])
                .unwrap_or_else(|_| panic!("should parse -c {method}"));
            assert_eq!(
                m.get_one::<String>(options::CRYPT_METHOD)
                    .map(String::as_str),
                Some(*method)
            );
        }
    }

    // -----------------------------------------------------------------------
    // Input parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_input_line_valid() {
        let pair = parse_input_line("testuser:$6$hash", 1).expect("should parse");
        assert_eq!(pair.username, "testuser");
        assert_eq!(&*pair.password, "$6$hash");
    }

    #[test]
    fn test_parse_input_line_empty_password() {
        let pair = parse_input_line("testuser:", 1).expect("should parse empty password");
        assert_eq!(pair.username, "testuser");
        assert_eq!(&*pair.password, "");
    }

    #[test]
    fn test_parse_input_line_password_with_colons() {
        // The password itself may contain colons (e.g., in a hash).
        let pair = parse_input_line("testuser:$6$salt:hash:rest", 1).expect("should parse");
        assert_eq!(pair.username, "testuser");
        // Only the first colon is the separator; rest is password.
        assert_eq!(&*pair.password, "$6$salt:hash:rest");
    }

    #[test]
    fn test_parse_input_line_missing_colon() {
        let result = parse_input_line("nocolon", 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_input_line_empty_username() {
        let result = parse_input_line(":password", 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_input_line_empty_line() {
        let result = parse_input_line("", 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_input_line_whitespace_only() {
        let result = parse_input_line("   ", 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_input_line_leading_whitespace() {
        let pair = parse_input_line("  testuser:$6$hash  ", 1).expect("should handle whitespace");
        assert_eq!(pair.username, "testuser");
        assert_eq!(&*pair.password, "$6$hash");
    }

    // -----------------------------------------------------------------------
    // Error code tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_errors_exit_one() {
        use uucore::error::UError;

        assert_eq!(ChpasswdError::PermissionDenied("test".into()).code(), 1);
        assert_eq!(ChpasswdError::UnexpectedFailure("test".into()).code(), 1);
        assert_eq!(ChpasswdError::FileBusy("test".into()).code(), 1);
        assert_eq!(ChpasswdError::InvalidInput("test".into()).code(), 1);
    }

    #[test]
    fn test_already_printed_preserves_code() {
        use uucore::error::UError;

        assert_eq!(ChpasswdError::AlreadyPrinted(1).code(), 1);
        assert_eq!(ChpasswdError::AlreadyPrinted(2).code(), 2);
    }

    #[test]
    fn test_error_display() {
        let err = ChpasswdError::PermissionDenied("no access".into());
        assert_eq!(format!("{err}"), "no access");

        let err = ChpasswdError::InvalidInput("bad line".into());
        assert_eq!(format!("{err}"), "bad line");

        let err = ChpasswdError::AlreadyPrinted(1);
        assert_eq!(format!("{err}"), "");
    }

    #[test]
    fn test_error_is_std_error() {
        let err = ChpasswdError::UnexpectedFailure("fail".into());
        let _: &dyn std::error::Error = &err;
    }

    // -----------------------------------------------------------------------
    // days_since_epoch sanity test
    // -----------------------------------------------------------------------

    #[test]
    fn test_days_since_epoch_reasonable() {
        let days = days_since_epoch();
        // Should be at least 2024-01-01 (~19723 days) and less than 2100-01-01 (~47482 days).
        assert!(
            days > 19700,
            "days since epoch should be > 19700, got {days}"
        );
        assert!(
            days < 47500,
            "days since epoch should be < 47500, got {days}"
        );
    }
}
