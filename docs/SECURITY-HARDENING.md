# Security Hardening Roadmap

Techniques adopted from OpenBSD and best practices for setuid-root tools.

## Implemented

- [x] `caller_is_root()` uses `getuid()` not `geteuid()` for authorization
- [x] Atomic file writes with `fsync` + `rename`
- [x] Temp files created with `0o600` (no world-readable window)
- [x] Lock-via-hard-link (TOCTOU-resistant)
- [x] Stale lock detection only on `ESRCH` (not `EPERM`)
- [x] Password strings zeroed via `zeroize` crate
- [x] Absolute paths for subprocess execution (`/usr/sbin/nscd`)
- [x] PAM delegation (no custom password hashing)
- [x] `TmpGuard` drop pattern (no leaked temp files)
- [x] Signal blocking during file writes (#38 — `SignalBlocker` RAII)
- [x] Environment sanitization (#40 — `sanitized_env()` / `harden_process()`)
- [x] Privilege drop during PAM conversation (#39 — `PrivDrop` RAII)
- [x] Core dump suppression (#43 — `suppress_core_dumps()`)
- [x] Resource limit hardening (#44 — `raise_file_size_limit()`)
- [x] Zero-length output guard (#45 — in `atomic_write`)
- [x] setuid(0) consolidation (#47 — before file operations)
- [x] Password input interrupt handling (#48 — custom SIGINT handler removed; signal blocking during file writes covers critical sections)
- [x] User enumeration prevention (#49 — early permission check for non-root callers)
- [x] O_CLOEXEC on file descriptors (#50)
- [x] Umask reset (#51 — `UmaskGuard` RAII)
- [x] Landlock filesystem restriction (#41 — `apply_landlock()` in passwd)
- [x] PAM password buffer zeroization (immediate `zeroize` after use)
- [x] `initgroups()` in newgrp (prevent supplementary group leak across exec)
- [x] `UmaskGuard` `!Send`/`!Sync` (`PhantomData<Rc<()>>` — prevent cross-thread umask corruption)
- [x] `atomic_write` retry on stale temp file from prior crash
- [x] `SignalBlocker` scoped to critical sections only (dropped before long-running ops)
- [x] Centralized hardening in `shadow_core::hardening` (deduplicated across tools)
- [x] Targeted hardening in newgrp (no `RLIMIT_FSIZE` leak to exec'd shell)

## Not Yet Implemented

### Seccomp-BPF
Restrict syscalls to only what passwd needs after initialization.
Complex but effective — sudo-rs uses this approach.

## References

- OpenBSD pledge(2): https://man.openbsd.org/pledge.2
- OpenBSD unveil(2): https://man.openbsd.org/unveil.2
- Linux landlock: https://docs.kernel.org/userspace-api/landlock.html
- Linux seccomp: https://man7.org/linux/man-pages/man2/seccomp.2.html
- sudo-rs security: https://github.com/trifectatechfoundation/sudo-rs
