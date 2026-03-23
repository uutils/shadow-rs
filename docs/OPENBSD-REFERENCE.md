# OpenBSD Security Reference for shadow-rs

Reference notes from OpenBSD's passwd implementation (ISC license).
These are design patterns and hardening techniques to adopt.

## Key OpenBSD Security Patterns

### 1. pledge(2) — Syscall Restriction

OpenBSD's passwd calls `pledge("stdio rpath wpath cpath flock proc exec getpw id tty", NULL)`
immediately after startup, restricting the process to only the syscalls it needs.

**Linux equivalent**: `seccomp-bpf` or `landlock`. We should investigate adding
a seccomp filter after initialization to restrict syscalls.

**Status**: Not implemented. Future work.

### 2. unveil(2) — Filesystem Restriction

OpenBSD restricts file access to only:
- `/etc/` (read/write for shadow files)
- `/dev/tty` (read/write for password prompts)

**Linux equivalent**: `landlock` (kernel 5.13+). Could restrict filesystem
access to only `/etc/passwd`, `/etc/shadow`, `/dev/tty`.

**Status**: Not implemented. Future work.

### 3. Privilege Separation

OpenBSD drops privileges as early as possible. The passwd binary:
1. Reads files as root
2. Drops to the target user's UID for PAM interaction
3. Re-elevates only for the final file write

**Our approach**: We use `caller_is_root()` (getuid) for authorization but
run the entire operation with full privileges. Could improve by dropping
euid to caller's uid during PAM conversation.

### 4. Signal Handling

OpenBSD blocks `SIGINT`, `SIGQUIT`, `SIGHUP`, `SIGTSTP` during critical
sections (file writes) to prevent partial updates, then restores them.

**Our approach**: We rely on RAII (lock drop, echo guard drop) but don't
block signals during the file write itself. A signal between the rename
and the lock release is harmless, but a signal during the write closure
could leave a partial temp file (mitigated by TmpGuard).

### 5. Memory Zeroing

OpenBSD uses `explicit_bzero()` on all password buffers — this cannot be
optimized away by the compiler (unlike `memset`).

**Our approach**: We use the `zeroize` crate which uses volatile writes
to prevent compiler optimization. Equivalent security.

### 6. File Locking

OpenBSD uses `flock(2)` (advisory locks) instead of `.lock` files.
The `.lock` file approach (used by GNU shadow-utils and us) has the
TOCTOU race we mitigated with hard-link pattern.

`flock(2)` is cleaner but:
- Not compatible with GNU shadow-utils convention
- Doesn't work across NFS (neither do .lock files)

**Our approach**: Hard-link pattern is correct for GNU compatibility.

### 7. Atomic File Replacement

OpenBSD's `pw_mkdb` creates the file with restrictive permissions from
the start (like our fix in #19), fsyncs, then renames.

**Our approach**: Same pattern. Already implemented correctly.

## Recommendations for shadow-rs

| Priority | What | OpenBSD Pattern | Effort |
|----------|------|-----------------|--------|
| High | Drop privileges during PAM conversation | `seteuid(caller_uid)` | Medium |
| High | Block signals during file write | `sigprocmask` | Low |
| Medium | Add landlock filesystem restriction (Linux 5.13+) | Like `unveil` | Medium |
| Medium | Add seccomp filter after init | Like `pledge` | High |
| Low | Environment sanitization | Clear env except essentials | Low |

## File References

- OpenBSD passwd.c: https://cvsweb.openbsd.org/src/usr.bin/passwd/
- OpenBSD pw_dup.c: https://cvsweb.openbsd.org/src/lib/libc/gen/pw_dup.c
- sudo-rs privilege handling: https://github.com/trifectatechfoundation/sudo-rs
