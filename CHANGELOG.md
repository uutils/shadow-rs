# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-24

### Added

- All 14 shadow-utils tools implemented as drop-in replacements:
  `passwd`, `useradd`, `userdel`, `usermod`, `groupadd`, `groupdel`,
  `groupmod`, `pwck`, `grpck`, `chage`, `chpasswd`, `chfn`, `chsh`, `newgrp`
- Single multicall binary with symlink dispatch (894 KB stripped)
- PAM integration for password authentication and changes
- Atomic file writes with lock-via-hard-link pattern (TOCTOU resistant)
- Stale lock detection via ESRCH-only PID checking
- Password zeroing via `zeroize` crate
- Core dump suppression and file size limit hardening
- Environment sanitization (safe for setuid-root context)
- Signal blocking during critical file operations
- SELinux file context support (best-effort via external tools)
- Audit logging to syslog and auditd
- subuid/subgid allocation for rootless containers (useradd)
- Recursive chown on UID change (usermod)
- Proper date validation with leap year and month-length rules
- GNU-compatible output and exit codes for all tools
- 460+ unit tests, property-based tests (proptest), 4 fuzz targets
- Integration tests for 14 tools
- Docker test matrix: Debian (glibc), Alpine (musl), Fedora (SELinux)
- CI gates: fmt, clippy, test, MSRV (1.94.0), cargo-deny
- Debian and RPM packaging
- Man pages for all 14 tools
- GNU compatibility test suite and PAM end-to-end test

### Security

- `unsafe_code = "deny"` enforced at workspace level (only PAM/crypt FFI exempted)
- `dead_code = "deny"` enforced at workspace level
- O_EXCL temp files (symlink attack prevention)
- Umask guard (RAII) for restrictive file permissions
- GPL clean-room development (MIT license, no GPL source referenced)
- Reviewed by GitHub Copilot (automated) and Google Gemini CLI (manual)
- 20+ security findings addressed across 4 review rounds
