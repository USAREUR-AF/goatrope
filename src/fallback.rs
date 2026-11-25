// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! While the port to Rust is under way (ADR 0003), a verb this binary does not handle yet
//! runs in the Python tree beside it. This module goes when the last role is ported.

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where the Python package is: beside the checkout or unpacked release this binary came
/// from (bin/<arch>/goatrope -> ../../goatrope), or where `goatrope install` put it.
fn python_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    let mut candidates: Vec<PathBuf> = Vec::new();
    for up in exe.ancestors().skip(1).take(3) {
        candidates.push(up.to_path_buf());
    }
    candidates.push(PathBuf::from("/usr/local/lib/goatrope"));
    candidates
        .into_iter()
        .find(|d| d.join("goatrope").join("cli.py").is_file())
}

pub fn run(args: &[String]) -> i32 {
    let Some(root) = python_root() else {
        eprintln!(
            "goatrope: this build does not handle `{}` and no Python tree was found beside it",
            args.first().map(String::as_str).unwrap_or("")
        );
        return 1;
    };
    let code = "import sys; sys.path.insert(0, sys.argv.pop(1)); sys.argv[0] = 'goatrope'; \
                from goatrope.cli import main; sys.exit(main())";
    let exe = std::env::current_exe().unwrap_or_else(|_| Path::new("goatrope").to_path_buf());
    let err = Command::new("/usr/bin/python3")
        .args(["-I", "-B", "-c", code])
        .arg(&root)
        .args(args)
        .env("GOATROPE_EXE", exe)
        .exec();
    eprintln!(
        "goatrope: cannot run /usr/bin/python3: {}",
        crate::sys::strerror(&err)
    );
    1
}
