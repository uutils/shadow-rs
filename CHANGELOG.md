# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `usermod -p/--password` flag for setting pre-hashed passwords (#114)
- End-to-end deployment tests in Docker: 117 assertions covering symlink
  dispatch, setuid, PAM, Landlock, nscd, and Ansible interop (#102, #115)
- Docker multi-distro CI in GitHub Actions (debian, alpine, fedora)
- Shell completion generation for bash, zsh, fish (#106)
- Renovate for automated dependency updates
- `rust-toolchain.toml` for contributor convenience
- `feat_common_core` feature alias (all 14 tools)

### Changed

- Cargo.toml metadata aligned with uutils ecosystem conventions
- Tool crate descriptions normalized to `"tool ~ (shadow-rs) verb phrase"` format
- Edition 2024 consistently applied across root and workspace packages
- `make install` now defaults to 14 standalone per-tool binaries with
  least-privilege setuid layout matching GNU shadow-utils (#138). Only
  `passwd`/`chfn`/`chsh`/`newgrp` are setuid-root; the other 10 are `0755`.
  The previous multicall install is available as `make install-multicall`.

### Fixed

- Password hash validation rejects `:`, `\n`, `\r` (field injection prevention)
- Error on missing shadow entry in usermod (was silent no-op)
- `days_since_epoch()` centralized in shadow-core (was duplicated)

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
