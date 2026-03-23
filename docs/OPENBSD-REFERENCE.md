# OpenBSD Security Reference for shadow-rs

Detailed analysis of OpenBSD's passwd implementation (ISC license).
Source: `cvsweb.openbsd.org/src/usr.bin/passwd/` and `src/lib/libutil/passwd.c`.

## Findings — What OpenBSD Does That We Should

### Already Implemented

| # | Pattern | Status |
|---|---------|--------|
| Signal blocking during file writes | #38 — `SignalBlocker` RAII |
| Privilege drop during PAM conversation | #39 — `PrivDrop` RAII |
| Environment sanitization | #40 — `sanitize_env()` |
| Landlock stub | #41 — documented, needs crate dep |
| Absolute paths for subprocesses | #20 — `/usr/sbin/nscd` |
| Password zeroing | #7 — `zeroize` crate |
| Secure temp file permissions | #19 — `0o600` from creation |
| TOCTOU-resistant locking | #18 — lock-via-hard-link |

### Not Yet Implemented

#### CRITICAL: Core Dump Suppression
OpenBSD's `pw_init()` sets `RLIMIT_CORE` to 0. A core dump from a setuid
passwd process could expose password hashes and plaintext passwords.

```rust
nix::sys::resource::setrlimit(Resource::RLIMIT_CORE, 0, 0)?;
```

Also: `prctl(PR_SET_DUMPABLE, 0)` prevents ptrace attachment.

#### HIGH: Resource Limit Hardening
OpenBSD raises `RLIMIT_FSIZE` to infinity before file writes. A malicious
caller could `ulimit -f 1` before invoking setuid passwd, truncating
`/etc/shadow` mid-write.

```rust
nix::sys::resource::setrlimit(Resource::RLIMIT_FSIZE, RLIM_INFINITY, RLIM_INFINITY)?;
```

#### HIGH: setuid(0) Before File Operations
OpenBSD calls `setuid(0)` before the critical section to consolidate both
real and effective UID to root. Some filesystem configurations check real UID.

#### MEDIUM: Zero-Length Output Guard
OpenBSD checks that the output file is non-zero-length before replacing the
original. A zero-length `/etc/shadow` locks out all users.

```rust
// In atomic_write, after the closure runs:
if tmp_file.metadata()?.len() == 0 {
    return Err(ShadowError::Other("refusing to write zero-length file"));
}
```

#### MEDIUM: User Enumeration Prevention
OpenBSD rejects non-root callers targeting other usernames before PAM auth.
Our current flow lets PAM auth fail, potentially leaking timing information
about whether the account exists.

#### MEDIUM: Clean SIGINT Handler During Password Input
OpenBSD's `kbintr` handler uses `_exit(0)` and `dprintf` (async-signal-safe).
Prints "Password unchanged." and exits cleanly. Our PAM EchoGuard may not
run its Drop destructor on signal-induced termination.

#### LOW: Umask Reset
OpenBSD saves/restores umask around lock file creation. Defense-in-depth
against edge cases where umask interacts with file permissions.

## Implementation Priority

**Immediate** (before any release):
1. Core dump suppression — 5 lines
2. Resource limit hardening — 10 lines
3. Zero-length output guard — 5 lines in `atomic_write`

**Next sprint**:
4. setuid(0) consolidation
5. User enumeration prevention
6. SIGINT handler for password input

**Roadmap**:
7. Full Landlock implementation
8. seccomp-bpf filter
9. Umask handling

## File References

- OpenBSD passwd.c: https://cvsweb.openbsd.org/src/usr.bin/passwd/passwd.c
- OpenBSD local_passwd.c: https://cvsweb.openbsd.org/src/usr.bin/passwd/local_passwd.c
- OpenBSD pw_init/pw_lock: https://cvsweb.openbsd.org/src/lib/libutil/passwd.c
- OpenBSD pw_dup.c: https://cvsweb.openbsd.org/src/lib/libc/gen/pw_dup.c
- OpenBSD pwd_check.c: https://cvsweb.openbsd.org/src/usr.bin/passwd/pwd_check.c
