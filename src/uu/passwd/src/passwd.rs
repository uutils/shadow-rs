// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! `passwd` — change user password.

use clap::{Arg, ArgAction, Command};

mod options {
    pub const USER: &str = "user";
    pub const STATUS: &str = "status";
    pub const LOCK: &str = "lock";
    pub const UNLOCK: &str = "unlock";
    pub const DELETE: &str = "delete";
}

/// Entry point for the `passwd` utility.
pub fn uumain(args: impl IntoIterator<Item = std::ffi::OsString>) -> i32 {
    let matches = uu_app().try_get_matches_from(args);

    let matches = match matches {
        Ok(m) => m,
        Err(e) => {
            e.print().ok();
            return i32::from(e.use_stderr());
        }
    };

    if matches.get_flag(options::STATUS) {
        eprintln!("passwd: --status not yet implemented");
        return 1;
    }

    eprintln!("passwd: not yet implemented");
    1
}

/// Build the clap `Command` for `passwd`.
#[must_use]
pub fn uu_app() -> Command {
    Command::new("passwd")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Change user password")
        .arg(
            Arg::new(options::STATUS)
                .short('S')
                .long("status")
                .help("Display account status information")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::LOCK)
                .short('l')
                .long("lock")
                .help("Lock the password of the named account")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::UNLOCK)
                .short('u')
                .long("unlock")
                .help("Unlock the password of the named account")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::DELETE)
                .short('d')
                .long("delete")
                .help("Delete the password of the named account")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::USER)
                .help("Username to change password for")
                .index(1),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_builds() {
        uu_app().debug_assert();
    }
}
