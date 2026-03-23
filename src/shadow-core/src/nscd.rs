// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore nscd

//! nscd (Name Service Cache Daemon) cache invalidation.
//!
//! After modifying `/etc/passwd`, `/etc/shadow`, or `/etc/group`,
//! the nscd cache must be invalidated so lookups reflect the changes.
