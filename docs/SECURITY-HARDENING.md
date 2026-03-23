# Security Hardening Roadmap

Techniques to adopt from OpenBSD and best practices for setuid-root tools.

## Already Implemented

- [x] `caller_is_root()` uses `getuid()` not `geteuid()` for authorization
- [x] Atomic file writes with `fsync` + `rename`
- [x] Temp files created with `0o600` (no world-readable window)
- [x] Lock-via-hard-link (TOCTOU-resistant)
- [x] Stale lock detection only on `ESRCH` (not `EPERM`)
- [x] Password strings zeroed via `zeroize` crate
- [x] Absolute paths for subprocess execution (`/usr/sbin/nscd`)
- [x] PAM delegation (no custom password hashing)
- [x] `TmpGuard` drop pattern (no leaked temp files)

## Phase 1: Quick Wins

### Signal Blocking During File Writes
Block `SIGINT`/`SIGTERM`/`SIGHUP` during the critical section between
lock acquisition and lock release. Prevents partial shadow file updates.

```rust
use nix::sys::signal::{SigSet, SigmaskHow, sigprocmask};

let mut oldset = SigSet::empty();
let mut blockset = SigSet::empty();
blockset.add(Signal::SIGINT);
blockset.add(Signal::SIGTERM);
blockset.add(Signal::SIGHUP);
sigprocmask(SigmaskHow::SIG_BLOCK, Some(&blockset), Some(&mut oldset))?;

// ... critical section: lock, write, rename, unlock ...

sigprocmask(SigmaskHow::SIG_SETMASK, Some(&oldset), None)?;
```

### Environment Sanitization
Clear the environment on startup for setuid binaries, keeping only:
- `PATH=/usr/bin:/bin`
- `TERM`
- `LANG`/`LC_*`

```rust
fn sanitize_env() {
    let keep = ["TERM", "LANG", "LC_ALL", "LC_MESSAGES"];
    let saved: Vec<_> = keep.iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (*k, v)))
        .collect();
    // Clear everything
    for (key, _) in std::env::vars() {
        std::env::remove_var(&key);
    }
    // Restore kept vars + safe PATH
    std::env::set_var("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    for (key, val) in saved {
        std::env::set_var(key, val);
    }
}
```

### Privilege Drop During PAM Conversation
Drop effective UID to caller's real UID during the PAM conversation,
re-elevate only for file writes:

```rust
let caller_uid = nix::unistd::getuid();
nix::unistd::seteuid(caller_uid)?;  // drop privs
pam.authenticate(0)?;
pam.chauthtok(0)?;
nix::unistd::seteuid(Uid::from_raw(0))?;  // re-elevate for file write
```

## Phase 2: Linux-Specific Hardening

### Landlock (Linux 5.13+)
Restrict filesystem access to only the files we need:

```rust
// Only allow: /etc/passwd, /etc/shadow, /etc/shadow.lock, /dev/tty
let ruleset = Ruleset::new()
    .handle_access(AccessFs::ReadFile | AccessFs::WriteFile)?
    .create()?;
ruleset.add_rule(PathBeneath::new(PathFd::new("/etc/")?, AccessFs::all()))?;
ruleset.add_rule(PathBeneath::new(PathFd::new("/dev/tty")?, AccessFs::all()))?;
ruleset.restrict_self()?;
```

### Seccomp-BPF
Restrict syscalls to only what passwd needs after initialization.
Complex but effective — sudo-rs uses this approach.

## References

- OpenBSD pledge(2): https://man.openbsd.org/pledge.2
- OpenBSD unveil(2): https://man.openbsd.org/unveil.2
- Linux landlock: https://docs.kernel.org/userspace-api/landlock.html
- Linux seccomp: https://man7.org/linux/man-pages/man2/seccomp.2.html
- sudo-rs security: https://github.com/trifectatechfoundation/sudo-rs
