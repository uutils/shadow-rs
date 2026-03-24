// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! `chpasswd` — stub (not yet implemented).

use clap::Command;
use uucore::error::UResult;

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let _matches = uu_app().try_get_matches_from(args)?;
    eprintln!("chpasswd: not yet implemented");
    Ok(())
}

#[must_use]
pub fn uu_app() -> Command {
    Command::new("chpasswd").about("chpasswd — not yet implemented")
}
