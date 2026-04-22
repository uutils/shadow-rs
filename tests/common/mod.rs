// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Shared test helpers for shadow-rs integration tests.
//!
//! Import with `#[path = "../common/mod.rs"] mod common;` in test files.

/// Skip the test when not running as root (euid != 0).
///
/// Returns `true` if the test should be skipped.
pub fn skip_unless_root() -> bool {
    !rustix::process::geteuid().is_root()
}
