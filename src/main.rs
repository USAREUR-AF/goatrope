// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! goatrope command line.
//!
//! Exit codes: 0 success or match; 2 refused or invalid declaration; 3 check differs; 1 error.

#[allow(dead_code)] // the roles still in Python read most of the declaration (ADR 0003)
mod config;
mod fallback;
mod sys;
mod tap;

pub const VERSION: &str = include_str!("../VERSION");

pub const EXIT_OK: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_REFUSED: i32 = 2;
pub const EXIT_DIFFERS: i32 = 3;

const USAGE: &str = "\
usage: goatrope [-h] [--version] COMMAND ...

goatrope command line.

  goatrope install   [--config PATH]           apply the declaration (refuses, changing nothing, when unsafe)
  goatrope deploy    [--config PATH] [--dry-run] install only when the machine does not match already
  goatrope status    [--config PATH]           what the machine is doing now
  goatrope check     [--config PATH] [--json]  exit 0: matches the declaration; 3: differs; other: error
  goatrope uninstall [--purge]                 remove everything install wrote and restore the ports
  goatrope validate  [--config PATH]           check the declaration alone, without touching the machine
  goatrope relay     [--config PATH]           run the relay (WIP; see docs/adr/0002)
  goatrope boundary  key|sheet|up|check|down [--config PATH]
                                               the relay's boundary interface (transport = \"boundary\"):
                                               make the private key, print what the boundary point needs,
                                               bring the interface up, check it (0 matches, 3 differs), remove it

Exit codes: 0 success or match; 2 refused or invalid declaration; 3 check differs; 1 error.
";

pub fn version() -> &'static str {
    VERSION.trim()
}

/// `--config PATH` (or `--config=PATH`) from the arguments after the verb; the default otherwise.
fn config_path(rest: &[String]) -> Result<String, String> {
    let mut path = config::DEFAULT_PATH.to_string();
    let mut i = 0;
    while i < rest.len() {
        let a = &rest[i];
        if a == "--config" {
            path = rest
                .get(i + 1)
                .cloned()
                .ok_or("argument --config: expected one argument")?;
            i += 2;
            continue;
        }
        if let Some(v) = a.strip_prefix("--config=") {
            path = v.to_string();
        } else {
            return Err(format!("unrecognized arguments: {a}"));
        }
        i += 1;
    }
    Ok(path)
}

fn usage_error(msg: &str) -> i32 {
    eprintln!("usage: goatrope [-h] [--version] COMMAND ...");
    eprintln!("goatrope: error: {msg}");
    EXIT_REFUSED
}

fn validate(rest: &[String]) -> i32 {
    let path = match config_path(rest) {
        Ok(p) => p,
        Err(m) => return usage_error(&m),
    };
    match config::load(&path) {
        Ok(cfg) => {
            println!("{path}: valid");
            if let Some(t) = &cfg.tap {
                println!("{}", tap::banner(t));
            }
            EXIT_OK
        }
        Err(e) => {
            eprintln!("goatrope: refused: {e}");
            EXIT_REFUSED
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        None => usage_error("the following arguments are required: cmd"),
        Some("--version") => {
            println!("goatrope {}", version());
            EXIT_OK
        }
        Some("-h") | Some("--help") => {
            print!("{USAGE}");
            EXIT_OK
        }
        Some("validate") => validate(&args[1..]),
        Some(_) => fallback::run(&args),
    };
    std::process::exit(code);
}
