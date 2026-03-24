// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore usermod

//! `usermod` — modify a user account.
//!
//! Drop-in replacement for GNU shadow-utils `usermod(8)`.

use std::fmt;
use std::path::Path;

use clap::{Arg, ArgAction, Command};
use uucore::error::{UError, UResult};

use shadow_core::group::{self};
use shadow_core::lock::FileLock;
use shadow_core::passwd::{self};
use shadow_core::shadow::{self};
use shadow_core::sysroot::SysRoot;
use shadow_core::{atomic, nscd};

mod options {
    pub const COMMENT: &str = "comment";
    pub const HOME: &str = "home";
    pub const EXPIREDATE: &str = "expiredate";
    pub const INACTIVE: &str = "inactive";
    pub const GID: &str = "gid";
    pub const GROUPS: &str = "groups";
    pub const APPEND: &str = "append";
    pub const LOCK: &str = "lock";
    pub const UNLOCK: &str = "unlock";
    pub const LOGIN: &str = "login";
    pub const SHELL: &str = "shell";
    pub const UID: &str = "uid";
    pub const ROOT: &str = "root";
    pub const PREFIX: &str = "prefix";
    pub const USER: &str = "USER";
}

#[derive(Debug)]
enum UsermodError {
    CantUpdate(String),
    UserNotFound(String),
    UidInUse(String),
    AlreadyPrinted(i32),
}

impl fmt::Display for UsermodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CantUpdate(msg) | Self::UserNotFound(msg) | Self::UidInUse(msg) => {
                f.write_str(msg)
            }
            Self::AlreadyPrinted(_) => Ok(()),
        }
    }
}

impl std::error::Error for UsermodError {}

impl UError for UsermodError {
    fn code(&self) -> i32 {
        match self {
            Self::CantUpdate(_) => 1,
            Self::UserNotFound(_) => 6,
            Self::UidInUse(_) => 4,
            Self::AlreadyPrinted(c) => *c,
        }
    }
}

#[uucore::main]
#[allow(clippy::too_many_lines)]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let matches = match uu_app().try_get_matches_from(args) {
        Ok(m) => m,
        Err(e) => {
            e.print().ok();
            if !e.use_stderr() {
                return Ok(());
            }
            return Err(UsermodError::AlreadyPrinted(2).into());
        }
    };

    let login = matches
        .get_one::<String>(options::USER)
        .expect("USER is required");
    let prefix = matches.get_one::<String>(options::PREFIX).map(Path::new);
    let root = SysRoot::new(prefix);

    if !nix::unistd::getuid().is_root() {
        return Err(UsermodError::CantUpdate("Permission denied.".into()).into());
    }

    // Modify /etc/passwd.
    let passwd_path = root.passwd_path();
    let lock = FileLock::acquire(&passwd_path)
        .map_err(|e| UsermodError::CantUpdate(format!("cannot lock: {e}")))?;

    let mut entries = passwd::read_passwd_file(&passwd_path)
        .map_err(|e| UsermodError::CantUpdate(format!("{e}")))?;

    let Some(idx) = entries.iter().position(|e| e.name == *login) else {
        drop(lock);
        return Err(UsermodError::UserNotFound(format!("user '{login}' does not exist")).into());
    };

    // Save the old UID and home dir before mutation so we can chown if needed.
    let old_uid = entries[idx].uid;
    let home_for_chown = entries[idx].home.clone();
    let home_is_changing = matches.get_one::<String>(options::HOME).is_some();

    // Check UID collision before mutating.
    if let Some(&uid) = matches.get_one::<u32>(options::UID) {
        if entries.iter().any(|e| e.uid == uid && e.name != *login) {
            drop(lock);
            return Err(UsermodError::UidInUse(format!("UID {uid} already in use")).into());
        }
        entries[idx].uid = uid;
    }

    if let Some(c) = matches.get_one::<String>(options::COMMENT) {
        entries[idx].gecos.clone_from(c);
    }
    if let Some(h) = matches.get_one::<String>(options::HOME) {
        entries[idx].home.clone_from(h);
    }
    if let Some(s) = matches.get_one::<String>(options::SHELL) {
        entries[idx].shell.clone_from(s);
    }
    if let Some(&gid) = matches.get_one::<u32>(options::GID) {
        entries[idx].gid = gid;
    }
    if let Some(new_login) = matches.get_one::<String>(options::LOGIN) {
        entries[idx].name.clone_from(new_login);
    }

    let new_uid = entries[idx].uid;

    atomic::atomic_write(&passwd_path, |f| passwd::write_passwd(&entries, f))
        .map_err(|e| UsermodError::CantUpdate(format!("{e}")))?;
    drop(lock);

    // If the UID changed and the home directory was not explicitly moved,
    // chown the existing home directory to the new UID.
    if new_uid != old_uid && !home_is_changing && !home_for_chown.is_empty() {
        let home_path = root.resolve(&home_for_chown);
        if home_path.exists() {
            let _ = nix::unistd::chown(&home_path, Some(nix::unistd::Uid::from_raw(new_uid)), None);
        }
    }

    // Shadow modifications.
    let shadow_path = root.shadow_path();
    let do_lock = matches.get_flag(options::LOCK);
    let do_unlock = matches.get_flag(options::UNLOCK);
    let expire = matches.get_one::<String>(options::EXPIREDATE);
    let inactive = matches.get_one::<i64>(options::INACTIVE);

    if shadow_path.exists() && (do_lock || do_unlock || expire.is_some() || inactive.is_some()) {
        let slock = FileLock::acquire(&shadow_path)
            .map_err(|e| UsermodError::CantUpdate(format!("cannot lock shadow: {e}")))?;

        let mut se = shadow::read_shadow_file(&shadow_path)
            .map_err(|e| UsermodError::CantUpdate(format!("{e}")))?;

        if let Some(s) = se.iter_mut().find(|e| e.name == *login) {
            if do_lock {
                s.lock();
            }
            if do_unlock {
                s.unlock();
            }
            if let Some(exp) = expire {
                s.expire_date = if exp == "-1" { None } else { exp.parse().ok() };
            }
            if let Some(&i) = inactive {
                s.inactive_days = if i < 0 { None } else { Some(i) };
            }
        }

        atomic::atomic_write(&shadow_path, |f| shadow::write_shadow(&se, f))
            .map_err(|e| UsermodError::CantUpdate(format!("{e}")))?;
        drop(slock);
    }

    // Group modifications.
    if let Some(groups_str) = matches.get_one::<String>(options::GROUPS) {
        let group_path = root.group_path();
        if group_path.exists() {
            let append = matches.get_flag(options::APPEND);
            let new_groups: Vec<&str> = groups_str.split(',').map(str::trim).collect();

            let glock = FileLock::acquire(&group_path)
                .map_err(|e| UsermodError::CantUpdate(format!("cannot lock group: {e}")))?;

            let mut ge = group::read_group_file(&group_path)
                .map_err(|e| UsermodError::CantUpdate(format!("{e}")))?;

            if !append {
                for g in &mut ge {
                    g.members.retain(|m| m != login);
                }
            }
            for gname in &new_groups {
                if let Some(g) = ge.iter_mut().find(|g| g.name == *gname) {
                    if !g.members.iter().any(|m| m == login) {
                        g.members.push(login.clone());
                    }
                }
            }

            atomic::atomic_write(&group_path, |f| group::write_group(&ge, f))
                .map_err(|e| UsermodError::CantUpdate(format!("{e}")))?;
            drop(glock);
        }
    }

    nscd::invalidate_cache("passwd");
    nscd::invalidate_cache("group");
    Ok(())
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn uu_app() -> Command {
    Command::new("usermod")
        .about("Modify a user account")
        .override_usage("usermod [options] LOGIN")
        .arg(
            Arg::new(options::COMMENT)
                .short('c')
                .long("comment")
                .value_name("COMMENT")
                .help("New GECOS field"),
        )
        .arg(
            Arg::new(options::HOME)
                .short('d')
                .long("home")
                .value_name("HOME_DIR")
                .help("New home directory"),
        )
        .arg(
            Arg::new(options::EXPIREDATE)
                .short('e')
                .long("expiredate")
                .value_name("EXPIRE_DATE")
                .help("Account expiration date"),
        )
        .arg(
            Arg::new(options::INACTIVE)
                .short('f')
                .long("inactive")
                .value_name("INACTIVE")
                .value_parser(clap::value_parser!(i64))
                .help("Password inactive period"),
        )
        .arg(
            Arg::new(options::GID)
                .short('g')
                .long("gid")
                .value_name("GROUP")
                .value_parser(clap::value_parser!(u32))
                .help("New primary GID"),
        )
        .arg(
            Arg::new(options::GROUPS)
                .short('G')
                .long("groups")
                .value_name("GROUPS")
                .help("Supplementary groups"),
        )
        .arg(
            Arg::new(options::APPEND)
                .short('a')
                .long("append")
                .help("Append to groups (with -G)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::LOCK)
                .short('L')
                .long("lock")
                .help("Lock account")
                .conflicts_with(options::UNLOCK)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::UNLOCK)
                .short('U')
                .long("unlock")
                .help("Unlock account")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::LOGIN)
                .short('l')
                .long("login")
                .value_name("NEW_LOGIN")
                .help("New login name"),
        )
        .arg(
            Arg::new(options::SHELL)
                .short('s')
                .long("shell")
                .value_name("SHELL")
                .help("New login shell"),
        )
        .arg(
            Arg::new(options::UID)
                .short('u')
                .long("uid")
                .value_name("UID")
                .value_parser(clap::value_parser!(u32))
                .help("New UID"),
        )
        .arg(
            Arg::new(options::ROOT)
                .short('R')
                .long("root")
                .value_name("CHROOT_DIR")
                .help("Chroot directory"),
        )
        .arg(
            Arg::new(options::PREFIX)
                .short('P')
                .long("prefix")
                .value_name("PREFIX_DIR")
                .help("Directory prefix"),
        )
        .arg(
            Arg::new(options::USER)
                .required(true)
                .index(1)
                .help("Login name"),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_builds() {
        uu_app().debug_assert();
    }

    #[test]
    fn test_user_required() {
        assert!(uu_app().try_get_matches_from(["usermod"]).is_err());
    }

    #[test]
    fn test_lock_unlock_conflict() {
        assert!(uu_app()
            .try_get_matches_from(["usermod", "-L", "-U", "u"])
            .is_err());
    }

    #[test]
    fn test_append_groups() {
        let m = uu_app()
            .try_get_matches_from(["usermod", "-a", "-G", "sudo,docker", "u"])
            .unwrap();
        assert!(m.get_flag(options::APPEND));
        assert_eq!(
            m.get_one::<String>(options::GROUPS).map(String::as_str),
            Some("sudo,docker")
        );
    }

    fn skip_unless_root() -> bool {
        !nix::unistd::geteuid().is_root()
    }

    #[test]
    fn test_modify_shell_with_prefix() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(
            etc.join("passwd"),
            "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        )
        .unwrap();

        let code = uumain(
            vec![
                "usermod".into(),
                "-s".into(),
                "/bin/zsh".into(),
                "-P".into(),
                dir.path().as_os_str().to_owned(),
                "testuser".into(),
            ]
            .into_iter(),
        );
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(etc.join("passwd")).unwrap();
        assert!(content.contains("/bin/zsh"));
    }
}
