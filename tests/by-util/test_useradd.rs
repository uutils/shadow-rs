// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore useradd nologin skel gecos gshadow

//! Integration tests for the `useradd` utility.
//!
//! Tests that require root are guarded by `skip_unless_root()` and run inside
//! Docker CI containers. Non-root tests exercise clap parsing and error paths
//! that do not need privilege.

use std::ffi::OsString;

/// Skip the test when not running as root (uid != 0).
fn skip_unless_root() -> bool {
    !nix::unistd::getuid().is_root()
}

/// Run `uumain` with the given args, returning the exit code.
fn run(args: &[&str]) -> i32 {
    let os_args: Vec<OsString> = args.iter().map(|s| (*s).into()).collect();
    useradd::uumain(os_args.into_iter())
}

/// Helper to create a temp dir with the basic files useradd needs:
/// - etc/passwd (with root entry)
/// - etc/shadow (with root entry)
/// - etc/group (with root group)
/// - etc/login.defs (with UID/GID ranges)
fn setup_root_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("failed to create etc dir");

    std::fs::write(etc.join("passwd"), "root:x:0:0:root:/root:/bin/bash\n")
        .expect("failed to write passwd file");

    std::fs::write(etc.join("shadow"), "root:$6$hash:19500:0:99999:7:::\n")
        .expect("failed to write shadow file");

    std::fs::write(etc.join("group"), "root:x:0:\n").expect("failed to write group file");

    std::fs::write(
        etc.join("login.defs"),
        "\
UID_MIN 1000\n\
UID_MAX 60000\n\
SYS_UID_MIN 100\n\
SYS_UID_MAX 999\n\
GID_MIN 1000\n\
GID_MAX 60000\n\
SYS_GID_MIN 100\n\
SYS_GID_MAX 999\n\
USERGROUPS_ENAB yes\n\
CREATE_HOME no\n\
",
    )
    .expect("failed to write login.defs");

    dir
}

/// Run `uumain` with a `--root` dir prepended to the args.
fn run_with_root(dir: &tempfile::TempDir, extra_args: &[&str]) -> i32 {
    let root_str = dir.path().to_str().expect("non-UTF-8 temp path");
    let mut args = vec!["useradd", "-R", root_str];
    args.extend_from_slice(extra_args);
    run(&args)
}

/// Read the passwd file content back from a root dir.
fn read_passwd(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/passwd")).expect("failed to read passwd file")
}

/// Read the shadow file content back from a root dir.
fn read_shadow(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/shadow")).expect("failed to read shadow file")
}

/// Read the group file content back from a root dir.
fn read_group(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/group")).expect("failed to read group file")
}

// ---------------------------------------------------------------------------
// Non-root tests -- exercise clap parsing and error paths
// ---------------------------------------------------------------------------

#[test]
fn test_help_exits_zero() {
    let code = run(&["useradd", "--help"]);
    assert_eq!(code, 0, "--help should exit 0");
}

#[test]
fn test_unknown_flag_exits_error() {
    let code = run(&["useradd", "--bogus"]);
    assert_eq!(code, 2, "unknown flag should exit 2");
}

#[test]
fn test_missing_login_exits_error() {
    let code = run(&["useradd"]);
    assert_eq!(code, 2, "missing LOGIN should exit 2");
}

#[test]
fn test_defaults_flag() {
    // -D should print defaults; requires root for login.defs read on real system,
    // but we only care that clap parses it without error. If not root, we expect
    // exit 1 (permission denied).
    let code = run(&["useradd", "-D"]);
    if nix::unistd::getuid().is_root() {
        assert_eq!(code, 0, "-D should exit 0 when root");
    } else {
        assert_eq!(code, 1, "-D should exit 1 when not root");
    }
}

#[test]
fn test_conflicting_create_no_create_home() {
    let code = run(&["useradd", "-m", "-M", "testuser"]);
    assert_eq!(code, 2, "-m -M conflict should exit 2");
}

#[test]
fn test_conflicting_user_group_no_user_group() {
    let code = run(&["useradd", "-U", "-N", "testuser"]);
    assert_eq!(code, 2, "-U -N conflict should exit 2");
}

// ---------------------------------------------------------------------------
// Root-only tests -- exercise real operations via --root
// ---------------------------------------------------------------------------

#[test]
fn test_create_user_basic() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["-N", "testuser"]);
    assert_eq!(code, 0, "basic useradd should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("testuser:"),
        "passwd should contain testuser entry, got: {passwd}"
    );

    let shadow = read_shadow(&dir);
    assert!(
        shadow.contains("testuser:"),
        "shadow should contain testuser entry, got: {shadow}"
    );
}

#[test]
fn test_create_user_with_home() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    // Create skel directory so -m does not fail on missing skel.
    let skel = dir.path().join("etc/skel");
    std::fs::create_dir_all(&skel).expect("failed to create skel dir");
    // Create /home base directory so create_dir (not create_dir_all) succeeds.
    let home_base = dir.path().join("home");
    std::fs::create_dir_all(&home_base).expect("failed to create home base dir");

    let code = run_with_root(&dir, &["-m", "-N", "homeuser"]);
    assert_eq!(code, 0, "useradd -m should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("homeuser:"),
        "passwd should contain homeuser, got: {passwd}"
    );

    // Verify home directory was created.
    let home_path = dir.path().join("home/homeuser");
    assert!(
        home_path.exists(),
        "home directory should have been created at {}",
        home_path.display()
    );
}

#[test]
fn test_create_user_with_uid() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["-u", "5000", "-N", "uiduser"]);
    assert_eq!(code, 0, "useradd -u 5000 should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("uiduser:x:5000:"),
        "passwd should contain UID 5000, got: {passwd}"
    );
}

#[test]
fn test_create_user_with_shell() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["-s", "/bin/zsh", "-N", "shelluser"]);
    assert_eq!(code, 0, "useradd -s /bin/zsh should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains(":/bin/zsh\n") || passwd.contains(":/bin/zsh"),
        "passwd should contain /bin/zsh as shell, got: {passwd}"
    );
}

#[test]
fn test_create_user_system() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["-r", "-N", "sysuser"]);
    assert_eq!(code, 0, "useradd -r should exit 0");

    let passwd = read_passwd(&dir);
    // Parse the UID from the passwd entry for sysuser.
    let sysuser_line = passwd
        .lines()
        .find(|l| l.starts_with("sysuser:"))
        .expect("sysuser entry should exist in passwd");
    let fields: Vec<&str> = sysuser_line.split(':').collect();
    let uid: u32 = fields[2].parse().expect("UID should be a valid number");
    assert!(
        (100..=999).contains(&uid),
        "system user UID should be in range 100-999, got: {uid}"
    );
}

#[test]
fn test_create_user_with_group() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    // Use numeric GID to avoid needing the group to exist by name.
    let code = run_with_root(&dir, &["-g", "1000", "-N", "grpuser"]);
    assert_eq!(code, 0, "useradd -g 1000 should exit 0");

    let passwd = read_passwd(&dir);
    // The GID (4th field) should be 1000.
    let grpuser_line = passwd
        .lines()
        .find(|l| l.starts_with("grpuser:"))
        .expect("grpuser entry should exist in passwd");
    let fields: Vec<&str> = grpuser_line.split(':').collect();
    assert_eq!(
        fields[3], "1000",
        "primary GID should be 1000, got: {}",
        fields[3]
    );
}

#[test]
fn test_duplicate_user_fails() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();

    // First creation should succeed.
    let code = run_with_root(&dir, &["-N", "dupuser"]);
    assert_eq!(code, 0, "first useradd should succeed");

    // Second creation with same name should fail (exit 9).
    let code = run_with_root(&dir, &["-N", "dupuser"]);
    assert_eq!(code, 9, "duplicate user should exit 9");
}

#[test]
fn test_create_user_with_comment() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["-c", "Test User", "-N", "commentuser"]);
    assert_eq!(code, 0, "useradd -c should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("Test User"),
        "GECOS should contain comment, got: {passwd}"
    );
}

#[test]
fn test_create_user_creates_user_group() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    // Default behavior: create a user group with same name.
    let code = run_with_root(&dir, &["grpuser2"]);
    assert_eq!(code, 0, "useradd with user group should exit 0");

    let group = read_group(&dir);
    assert!(
        group.contains("grpuser2:"),
        "group file should contain user group entry, got: {group}"
    );
}

#[test]
fn test_create_user_preserves_existing_entries() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["-N", "newuser"]);
    assert_eq!(code, 0, "useradd should succeed");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("root:x:0:0:root:/root:/bin/bash"),
        "root entry should be preserved, got: {passwd}"
    );
    assert!(
        passwd.contains("newuser:"),
        "newuser entry should be added, got: {passwd}"
    );

    let shadow = read_shadow(&dir);
    assert!(
        shadow.contains("root:$6$hash:19500:0:99999:7:::"),
        "root shadow entry should be preserved, got: {shadow}"
    );
}

#[test]
fn test_create_user_with_home_dir_flag() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["-d", "/custom/home", "-N", "customhome"]);
    assert_eq!(code, 0, "useradd -d should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains(":/custom/home:"),
        "passwd should contain custom home path, got: {passwd}"
    );
}
