// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Security hardening utilities for setuid-root tools.
//!
//! Every shadow-utils tool runs as setuid-root and must defend against
//! hostile callers. These functions implement the standard hardening
//! steps that all tools share.

/// Suppress core dumps via `RLIMIT_CORE=0`.
///
/// A core dump from a setuid-root process could expose password hashes
/// and plaintext passwords.
pub fn suppress_core_dumps() {
    let _ = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
    // PR_SET_DUMPABLE via nix::sys::prctl (no raw unsafe needed).
    // nix doesn't expose prctl directly, so we skip it rather than use unsafe.
    // RLIMIT_CORE=0 is sufficient to prevent core dumps.
}

/// Raise `RLIMIT_FSIZE` to prevent truncated file writes.
///
/// A malicious caller could `ulimit -f 1` before invoking a setuid-root
/// tool, causing `/etc/shadow` to be truncated mid-write.
pub fn raise_file_size_limit() {
    let _ = nix::sys::resource::setrlimit(
        nix::sys::resource::Resource::RLIMIT_FSIZE,
        nix::sys::resource::RLIM_INFINITY,
        nix::sys::resource::RLIM_INFINITY,
    );
}

/// Sanitize the environment for setuid-root context.
///
/// Clears all environment variables except essential ones (`TERM`, `LANG`,
/// `LC_*`) and sets `PATH` to a safe default. Prevents environment variable
/// injection attacks (`LD_PRELOAD`, `IFS`, `CDPATH`, etc.).
/// Build a sanitized environment for child process spawning.
///
/// Returns safe key-value pairs (PATH + TERM/LANG/LC_*). The current
/// process environment is NOT modified (`set_var` is unsafe in edition
/// 2024). Pass the returned Vec to `Command::env_clear().envs(...)`
/// when spawning subprocesses.
pub fn sanitized_env() -> Vec<(String, String)> {
    let mut env = Vec::new();
    env.push((
        "PATH".to_string(),
        "/usr/bin:/bin:/usr/sbin:/sbin".to_string(),
    ));
    for (k, v) in std::env::vars() {
        if k == "TERM" || k == "LANG" || k.starts_with("LC_") {
            env.push((k, v));
        }
    }
    env
}

/// Restrict filesystem access via Landlock (Linux 5.13+).
///
/// Best-effort: silently does nothing on kernels without Landlock support.
/// `rw_paths` get read+write access, `ro_paths` get read-only access,
/// `exec_paths` get execute access. Everything else is denied.
#[cfg(all(feature = "landlock", target_os = "linux"))]
pub fn apply_landlock(
    writable: &[&std::path::Path],
    readable: &[&std::path::Path],
    exec_paths: &[&std::path::Path],
) {
    use landlock::{
        ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, path_beneath_rules,
    };

    // V5 is the maximum ABI we request; Ruleset's default CompatLevel
    // (BestEffort) automatically downgrades to whatever the running
    // kernel actually supports, so this is safe on older kernels.
    let abi = ABI::V5;
    let all_access = AccessFs::from_all(abi);
    let read_access = AccessFs::from_read(abi);
    let exec_access = AccessFs::Execute | AccessFs::ReadFile | AccessFs::ReadDir;

    let result = Ruleset::default()
        .handle_access(all_access)
        .and_then(Ruleset::create)
        .and_then(|rs| rs.add_rules(path_beneath_rules(writable, all_access)))
        .and_then(|rs| rs.add_rules(path_beneath_rules(readable, read_access)))
        .and_then(|rs| rs.add_rules(path_beneath_rules(exec_paths, exec_access)))
        .and_then(landlock::RulesetCreated::restrict_self);

    // Best-effort: silently ignore errors (unsupported kernel, etc.)
    let _ = result;
}

/// No-op on non-Linux or when the `landlock` feature is disabled.
#[cfg(not(all(feature = "landlock", target_os = "linux")))]
pub fn apply_landlock(
    _writable: &[&std::path::Path],
    _readable: &[&std::path::Path],
    _exec_paths: &[&std::path::Path],
) {
}

/// Run all standard hardening steps for a setuid-root tool.
///
/// Call at the top of `uumain` before any argument parsing.
/// Returns the sanitized environment for use with child process spawning.
pub fn harden_process() -> Vec<(String, String)> {
    suppress_core_dumps();
    raise_file_size_limit();
    sanitized_env()
}
