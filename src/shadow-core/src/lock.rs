// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! File locking for `/etc/passwd`, `/etc/shadow`, etc.
//!
//! Uses `.lock` files (e.g., `/etc/passwd.lock`) with timeout and stale
//! lock detection, matching the convention used by GNU shadow-utils.
