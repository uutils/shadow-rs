// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Unified error types for shadow-rs utilities.

use std::fmt;
use std::io;

/// Result type alias used across all shadow-rs utilities.
pub type ShadowResult<T> = Result<T, ShadowError>;

/// Top-level error type for shadow-rs operations.
#[derive(Debug)]
pub enum ShadowError {
    /// I/O error with optional context.
    Io(io::Error),
    /// I/O error with path context.
    IoPath(io::Error, std::path::PathBuf),
    /// File format parse error.
    Parse(String),
    /// Lock acquisition failed.
    Lock(String),
    /// Validation error (invalid username, UID range, etc.).
    Validation(String),
    /// Authentication error (PAM failure, wrong password, etc.).
    Auth(String),
    /// Permission denied.
    Permission(String),
    /// Generic error with message.
    Other(String),
}

impl fmt::Display for ShadowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::IoPath(e, path) => write!(f, "{}: {e}", path.display()),
            Self::Parse(msg) => write!(f, "parse error: {msg}"),
            Self::Lock(msg) => write!(f, "lock error: {msg}"),
            Self::Auth(msg) => write!(f, "authentication error: {msg}"),
            Self::Permission(msg) => write!(f, "permission denied: {msg}"),
            Self::Validation(msg) | Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ShadowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) | Self::IoPath(e, _) => Some(e),
            Self::Parse(_)
            | Self::Lock(_)
            | Self::Validation(_)
            | Self::Auth(_)
            | Self::Permission(_)
            | Self::Other(_) => None,
        }
    }
}

impl From<io::Error> for ShadowError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Print an error message prefixed with the utility name to stderr.
#[macro_export]
macro_rules! show_error {
    ($util:expr, $($arg:tt)*) => {
        eprintln!("{}: {}", $util, format_args!($($arg)*));
    };
}

/// Print a warning message prefixed with the utility name to stderr.
#[macro_export]
macro_rules! show_warning {
    ($util:expr, $($arg:tt)*) => {
        eprintln!("{}: warning: {}", $util, format_args!($($arg)*));
    };
}
