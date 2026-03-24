// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore userdel gshadow

//! Integration tests for the `userdel` utility.
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
    userdel::uumain(os_args.into_iter())
}

/// Helper to create a temp dir with pre-populated files for userdel tests:
/// - etc/passwd with root + testuser
/// - etc/shadow with root + testuser
/// - etc/group with root group + a group containing testuser as member
fn setup_root_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("failed to create etc dir");

    std::fs::write(
        etc.join("passwd"),
        "\
root:x:0:0:root:/root:/bin/bash\n\
testuser:x:1000:1000:Test User:/home/testuser:/bin/bash\n\
otheruser:x:1001:1001:Other User:/home/otheruser:/bin/bash\n",
    )
    .expect("failed to write passwd file");

    std::fs::write(
        etc.join("shadow"),
        "\
root:$6$roothash:19500:0:99999:7:::\n\
testuser:$6$testhash:19500:0:99999:7:::\n\
otheruser:$6$otherhash:19500:0:99999:7:::\n",
    )
    .expect("failed to write shadow file");

    std::fs::write(
        etc.join("group"),
        "\
root:x:0:\n\
testgroup:x:1000:testuser\n\
othergroup:x:1001:otheruser\n\
shared:x:1002:testuser,otheruser\n",
    )
    .expect("failed to write group file");

    dir
}

/// Run `uumain` with a `--root` dir prepended to the args.
fn run_with_root(dir: &tempfile::TempDir, extra_args: &[&str]) -> i32 {
    let root_str = dir.path().to_str().expect("non-UTF-8 temp path");
    let mut args = vec!["userdel", "-R", root_str];
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
    let code = run(&["userdel", "--help"]);
    assert_eq!(code, 0, "--help should exit 0");
}

#[test]
fn test_unknown_flag_exits_error() {
    let code = run(&["userdel", "--bogus"]);
    assert_eq!(code, 2, "unknown flag should exit 2");
}

#[test]
fn test_missing_login_exits_error() {
    let code = run(&["userdel"]);
    assert_eq!(code, 2, "missing LOGIN should exit 2");
}

// ---------------------------------------------------------------------------
// Root-only tests -- exercise real operations via --root
// ---------------------------------------------------------------------------

#[test]
fn test_delete_user_basic() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["testuser"]);
    assert_eq!(code, 0, "userdel testuser should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        !passwd.contains("testuser:"),
        "passwd should not contain testuser after deletion, got: {passwd}"
    );

    let shadow = read_shadow(&dir);
    assert!(
        !shadow.contains("testuser:"),
        "shadow should not contain testuser after deletion, got: {shadow}"
    );
}

#[test]
fn test_delete_user_remove_home() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();

    // Create the home directory that userdel -r should remove.
    let home_path = dir.path().join("home/testuser");
    std::fs::create_dir_all(&home_path).expect("failed to create home dir");
    std::fs::write(home_path.join("somefile.txt"), "content")
        .expect("failed to write file in home");

    // Update passwd to point home to the temp dir path.
    let passwd_path = dir.path().join("etc/passwd");
    let home_str = "/home/testuser";
    let passwd_content = format!(
        "\
root:x:0:0:root:/root:/bin/bash\n\
testuser:x:1000:1000:Test User:{home_str}:/bin/bash\n\
otheruser:x:1001:1001:Other User:/home/otheruser:/bin/bash\n"
    );
    std::fs::write(&passwd_path, &passwd_content).expect("failed to rewrite passwd");

    let code = run_with_root(&dir, &["-r", "testuser"]);
    assert_eq!(code, 0, "userdel -r testuser should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        !passwd.contains("testuser:"),
        "passwd should not contain testuser, got: {passwd}"
    );

    // The home directory should be removed.
    assert!(
        !home_path.exists(),
        "home directory should have been removed at {}",
        home_path.display()
    );
}

#[test]
fn test_delete_nonexistent_user_fails() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["nouser"]);
    assert_ne!(code, 0, "deleting nonexistent user should fail");
}

#[test]
fn test_delete_user_preserves_others() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["testuser"]);
    assert_eq!(code, 0, "userdel testuser should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("root:x:0:0:root:/root:/bin/bash"),
        "root entry should be preserved, got: {passwd}"
    );
    assert!(
        passwd.contains("otheruser:x:1001:1001:Other User:/home/otheruser:/bin/bash"),
        "otheruser entry should be preserved, got: {passwd}"
    );
    assert!(
        !passwd.contains("testuser:"),
        "testuser should be removed, got: {passwd}"
    );

    let shadow = read_shadow(&dir);
    assert!(
        shadow.contains("root:"),
        "root shadow entry should be preserved, got: {shadow}"
    );
    assert!(
        shadow.contains("otheruser:"),
        "otheruser shadow entry should be preserved, got: {shadow}"
    );
}

#[test]
fn test_delete_user_removes_group_membership() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["testuser"]);
    assert_eq!(code, 0, "userdel testuser should exit 0");

    let group = read_group(&dir);
    // testuser should be removed from all group membership lists.
    assert!(
        !group.contains("testuser"),
        "testuser should be removed from group membership lists, got: {group}"
    );

    // otheruser should still be a member of shared group.
    assert!(
        group.contains("otheruser"),
        "otheruser should remain in group membership lists, got: {group}"
    );
}

#[test]
fn test_delete_user_shadow_entry_removed() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["testuser"]);
    assert_eq!(code, 0, "userdel should exit 0");

    let shadow = read_shadow(&dir);
    assert!(
        !shadow.contains("testuser:"),
        "shadow entry should be removed, got: {shadow}"
    );
    assert!(
        shadow.contains("otheruser:$6$otherhash:"),
        "otheruser shadow entry should be intact, got: {shadow}"
    );
}

#[test]
fn test_delete_user_force_flag_accepted() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    // -f is accepted without error (force removal even if user is logged in).
    let code = run_with_root(&dir, &["-f", "testuser"]);
    assert_eq!(code, 0, "userdel -f should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        !passwd.contains("testuser:"),
        "testuser should be deleted with -f, got: {passwd}"
    );
}

#[test]
fn test_delete_multiple_users_sequentially() {
    if skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();

    let code = run_with_root(&dir, &["testuser"]);
    assert_eq!(code, 0, "first userdel should succeed");

    let code = run_with_root(&dir, &["otheruser"]);
    assert_eq!(code, 0, "second userdel should succeed");

    let passwd = read_passwd(&dir);
    assert!(
        !passwd.contains("testuser:"),
        "testuser should be gone, got: {passwd}"
    );
    assert!(
        !passwd.contains("otheruser:"),
        "otheruser should be gone, got: {passwd}"
    );
    assert!(
        passwd.contains("root:"),
        "root should remain, got: {passwd}"
    );
}
