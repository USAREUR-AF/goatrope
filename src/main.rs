// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! goatrope command line.
//!
//! Exit codes: 0 success or match; 2 refused or invalid declaration; 3 check differs; 1 error.

mod boundary;
mod config;
mod link;
mod nl;
mod relay;
mod send;
mod sys;
mod sysutil;
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

/// The version of the software this binary belongs to: the VERSION file of the checkout,
/// unpacked release or installed tree it runs from, else the one it was built with. A release
/// is the archive, and its VERSION file is part of what the archive's hash covers.
pub fn version() -> String {
    if let Ok(exe) = std::env::current_exe().and_then(|e| e.canonicalize()) {
        let mut candidates: Vec<std::path::PathBuf> = exe.ancestors().skip(1).take(3).map(|d| d.join("VERSION")).collect();
        candidates.push("/usr/local/lib/goatrope/VERSION".into());
        candidates.push("/usr/local/lib/goatrope/goatrope/VERSION".into());
        for c in candidates {
            if let Ok(v) = std::fs::read_to_string(&c) {
                let v = v.trim();
                if !v.is_empty() {
                    return v.to_string();
                }
            }
        }
    }
    VERSION.trim().to_string()
}

struct Args {
    pos: Vec<String>,
    flags: Vec<String>,
    config: String,
}

/// The arguments after the verb: positionals, the flags this verb allows, and `--config PATH`.
fn args(rest: &[String], allowed: &[&str], npos: usize) -> Result<Args, String> {
    let mut a = Args { pos: vec![], flags: vec![], config: config::DEFAULT_PATH.to_string() };
    let mut i = 0;
    while i < rest.len() {
        let x = &rest[i];
        if x == "--config" {
            a.config = rest.get(i + 1).cloned().ok_or("argument --config: expected one argument")?;
            i += 2;
            continue;
        }
        if let Some(v) = x.strip_prefix("--config=") {
            a.config = v.to_string();
        } else if allowed.contains(&x.as_str()) {
            a.flags.push(x.clone());
        } else if x.starts_with('-') || a.pos.len() >= npos {
            return Err(format!("unrecognized arguments: {x}"));
        } else {
            a.pos.push(x.clone());
        }
        i += 1;
    }
    if a.pos.len() < npos {
        return Err("the following arguments are required: name".into());
    }
    Ok(a)
}

/// `--config PATH` (or `--config=PATH`) from arguments that hold nothing else; the default otherwise.
fn config_path(rest: &[String]) -> Result<String, String> {
    args(rest, &[], 0).map(|a| a.config)
}

/// Load the declaration, then run f; an invalid declaration is a refusal (exit 2).
fn with_config(rest: &[String], npos: usize, f: impl Fn(&config::Config, &[String]) -> i32) -> i32 {
    let a = match args(rest, &[], npos) {
        Ok(a) => a,
        Err(m) => return usage_error(&m),
    };
    match config::load(&a.config) {
        Ok(cfg) => f(&cfg, &a.pos),
        Err(e) => {
            eprintln!("goatrope: refused: {e}");
            EXIT_REFUSED
        }
    }
}

fn usage_error(msg: &str) -> i32 {
    eprintln!("usage: goatrope [-h] [--version] COMMAND ...");
    eprintln!("goatrope: error: {msg}");
    EXIT_REFUSED
}

fn need_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("goatrope: run as root (sudo)");
        return false;
    }
    true
}

fn refused(e: tap::Refusal) -> i32 {
    eprintln!("goatrope: refused, nothing was changed: {}", e.0);
    EXIT_REFUSED
}

fn run(verb: &str, rest: &[String]) -> i32 {
    let (allowed, npos): (&[&str], usize) = match verb {
        "check" => (&["--json"], 0),
        "deploy" => (&["--dry-run"], 0),
        "uninstall" => (&["--purge"], 0),
        "run-send" => (&[], 1),
        "verify-component" => (&[], 2),
        _ => (&[], 0),
    };
    let a = match args(rest, allowed, npos) {
        Ok(a) => a,
        Err(m) => return usage_error(&m),
    };
    let flag = |f: &str| a.flags.iter().any(|x| x == f);
    if verb == "uninstall" {
        if !need_root() {
            return EXIT_REFUSED;
        }
        return match tap::uninstall(flag("--purge")) {
            Ok(()) => EXIT_OK,
            Err(e) => refused(e),
        };
    }
    if verb == "verify-component" && a.pos[0] != "decode" {
        return usage_error(&format!("argument kind: invalid choice: '{}' (choose from 'decode')", a.pos[0]));
    }
    let cfg = match config::load(&a.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("goatrope: refused: {e}");
            return EXIT_REFUSED;
        }
    };
    match verb {
        "validate" => {
            println!("{}: valid", a.config);
            if let Some(t) = &cfg.tap {
                println!("{}", tap::banner(t));
            }
            return EXIT_OK;
        }
        "run-send" => return send::run_send(&cfg, &a.pos[0]),
        "verify-component" => return send::verify_component(&cfg, &a.pos[0], &a.pos[1]),
        _ => {}
    }
    let Some(t) = &cfg.tap else {
        eprintln!("goatrope: this declaration has no [tap]; only `goatrope relay` applies");
        return EXIT_REFUSED;
    };
    match verb {
        "install" => {
            if !need_root() {
                return EXIT_REFUSED;
            }
            println!("{}", tap::banner(t));
            if let Err(e) = tap::install(&cfg) {
                return refused(e);
            }
            let bad = tap::check(&cfg).iter().any(|i| i.ok == Some(false));
            tap::status(&cfg);
            if bad {
                EXIT_DIFFERS
            } else {
                EXIT_OK
            }
        }
        "deploy" => {
            if !need_root() {
                return EXIT_REFUSED;
            }
            println!("{}", tap::banner(t));
            let outcome = match tap::deploy(&cfg, flag("--dry-run")) {
                Ok(o) => o,
                Err(e) => return refused(e),
            };
            let bad: Vec<tap::Item> =
                if outcome == "changed" { tap::check(&cfg).into_iter().filter(|i| i.ok == Some(false)).collect() } else { vec![] };
            for i in &bad {
                println!("  DIFF {}: {} (want {})", i.id, tap::show(&i.have), tap::show(&i.want));
            }
            println!("goatrope deploy: {outcome}");
            if bad.is_empty() {
                EXIT_OK
            } else {
                EXIT_DIFFERS
            }
        }
        "status" => tap::status(&cfg),
        "check" => {
            let items = tap::check(&cfg);
            let nbad = items.iter().filter(|i| i.ok == Some(false)).count();
            if flag("--json") {
                println!("{}", tap::check_json(&cfg, &items, nbad > 0));
            } else {
                println!("{}", tap::banner(t));
                for i in &items {
                    let mark = match i.ok {
                        Some(true) => "ok  ",
                        Some(false) => "DIFF",
                        None => "info",
                    };
                    let want = if i.ok == Some(false) { format!(" (want {})", tap::show(&i.want)) } else { String::new() };
                    println!("  {mark} {}: {}{want}", i.id, tap::show(&i.have));
                }
                if nbad > 0 {
                    println!("result: differs in {nbad} item(s)");
                } else {
                    println!("result: matches the declaration");
                }
            }
            if nbad > 0 {
                EXIT_DIFFERS
            } else {
                EXIT_OK
            }
        }
        "apply-ports" => {
            let problems = tap::apply_ports(&cfg, 120.0);
            for p in &problems {
                eprintln!("goatrope: {p}");
            }
            if problems.is_empty() {
                EXIT_OK
            } else {
                EXIT_ERROR
            }
        }
        _ => EXIT_ERROR,
    }
}

fn root_or_refuse() -> Result<(), i32> {
    if sys::is_root() {
        return Ok(());
    }
    eprintln!("goatrope: run as root (sudo)");
    Err(EXIT_REFUSED)
}

fn relay_cmd(rest: &[String]) -> i32 {
    // `relay` takes no positional argument: one is an unrecognized argument, as argparse says
    if let Err(m) = config_path(rest) {
        return usage_error(&m);
    }
    with_config(rest, 0, |cfg, _| match root_or_refuse() {
        Ok(()) => relay::run(cfg),
        Err(code) => code,
    })
}

const BOUNDARY_ACTIONS: [&str; 5] = ["key", "sheet", "up", "check", "down"];
const BOUNDARY_USAGE: &str = "usage: goatrope boundary [-h] [--config CONFIG] {key,sheet,up,check,down}";

fn boundary_cmd(rest: &[String]) -> i32 {
    // the one positional (the action) may come before or after --config, as argparse allows
    let mut action: Option<&str> = None;
    let mut opts: Vec<String> = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_str();
        if a == "-h" || a == "--help" {
            println!("{BOUNDARY_USAGE}");
            return EXIT_OK;
        }
        if a == "--config" {
            opts.extend(rest[i..(i + 2).min(rest.len())].iter().cloned());
            i += 2;
            continue;
        }
        if a.starts_with('-') || action.is_some() {
            opts.push(a.to_string());
        } else {
            if !BOUNDARY_ACTIONS.contains(&a) {
                eprintln!("{BOUNDARY_USAGE}");
                eprintln!(
                    "goatrope boundary: error: argument action: invalid choice: '{a}' (choose from 'key', 'sheet', 'up', 'check', 'down')"
                );
                return EXIT_REFUSED;
            }
            action = Some(a);
        }
        i += 1;
    }
    if let Err(m) = config_path(&opts) {
        return usage_error(&m);
    }
    let Some(action) = action else {
        eprintln!("{BOUNDARY_USAGE}");
        eprintln!("goatrope boundary: error: the following arguments are required: action");
        return EXIT_REFUSED;
    };
    with_config(&opts, 0, |cfg, _| boundary(cfg, action))
}

fn boundary(cfg: &config::Config, action: &str) -> i32 {
    let Some((b, ifname)) = cfg
        .relay
        .as_ref()
        .filter(|r| r.transport == "boundary")
        .and_then(|r| r.boundary.as_ref().map(|b| (b, r.remote_interface.as_str())))
    else {
        eprintln!("goatrope boundary: this declaration's [relay] does not use transport = \"boundary\"");
        return EXIT_REFUSED;
    };
    if action == "sheet" {
        println!("{}", boundary::sheet(b, ifname));
        return EXIT_OK;
    }
    if let Err(code) = root_or_refuse() {
        return code;
    }
    let refused = |e: boundary::BoundaryRefusal| {
        eprintln!("goatrope boundary: refused: {}", e.0);
        EXIT_REFUSED
    };
    match action {
        "key" => match boundary::make_key(&b.private_key_file) {
            Ok(Ok(public)) => {
                println!("wrote {} (mode 600); public key {public}", b.private_key_file);
                println!("{}", boundary::sheet(b, ifname));
            }
            Ok(Err(e)) => return refused(e),
            Err(e) => {
                eprintln!("goatrope boundary: {e}");
                return EXIT_ERROR;
            }
        },
        "up" => match boundary::up(b, ifname) {
            Ok(made) => println!("{ifname}: {}matches the declaration", if made { "made; " } else { "" }),
            Err(e) => return refused(e),
        },
        "check" => {
            let problems = boundary::check(b, ifname);
            for p in &problems {
                println!("  DIFF {p}");
            }
            if problems.is_empty() {
                println!("{ifname}: matches the declaration");
                return EXIT_OK;
            }
            println!("{ifname}: differs");
            return EXIT_DIFFERS;
        }
        _ => match boundary::down(ifname) {
            Ok(removed) => println!("{ifname}: {}", if removed { "removed" } else { "not present" }),
            Err(boundary::DownError::Refusal(e)) => return refused(e),
            Err(boundary::DownError::Failed(e)) => {
                eprintln!("goatrope boundary: {e}");
                return EXIT_ERROR;
            }
        },
    }
    EXIT_OK
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
        Some(
            v @ ("validate" | "install" | "deploy" | "status" | "check" | "uninstall" | "apply-ports" | "run-send" | "verify-component"),
        ) => run(v, &args[1..]),
        Some("relay") => relay_cmd(&args[1..]),
        Some("boundary") => boundary_cmd(&args[1..]),
        Some(other) => usage_error(&format!("argument cmd: invalid choice: '{other}'")),
    };
    std::process::exit(code);
}
