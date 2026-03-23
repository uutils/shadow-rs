// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Multicall binary entry point for shadow-rs.
//!
//! Dispatches to the appropriate utility based on `argv[0]`.
//! When invoked as `shadow-rs <util>`, uses the first argument instead.

use std::path::Path;

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();

    let binary_name = args
        .first()
        .and_then(|a| {
            Path::new(a)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
        })
        .unwrap_or_default();

    // Direct invocation via symlink (e.g., argv[0] = "passwd")
    if let Some(code) = dispatch(&binary_name, &args) {
        std::process::exit(code);
    }

    // Multicall: `shadow-rs <util> [args...]`
    if args.len() > 1 {
        let util_name = args[1].to_string_lossy().to_string();

        if util_name == "--list" {
            print_available_utils();
            std::process::exit(0);
        }

        if let Some(code) = dispatch(&util_name, &args[1..]) {
            std::process::exit(code);
        }

        eprintln!("shadow-rs: unknown utility '{util_name}'");
        eprintln!("Run 'shadow-rs --list' for available utilities.");
        std::process::exit(1);
    }

    eprintln!("Usage: shadow-rs <utility> [arguments...]");
    eprintln!("Run 'shadow-rs --list' for available utilities.");
    std::process::exit(1);
}

fn dispatch(name: &str, args: &[std::ffi::OsString]) -> Option<i32> {
    match name {
        #[cfg(feature = "passwd")]
        "passwd" => Some(passwd::uumain(args.iter().cloned())),
        _ => None,
    }
}

fn print_available_utils() {
    println!("Available utilities:");

    #[cfg(feature = "passwd")]
    println!("  passwd");
}
