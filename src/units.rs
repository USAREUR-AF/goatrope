// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Cases that call the code directly rather than through the command line. The ones marked
//! `#[ignore]` change the machine (a tmpfs mount, dummy interfaces, /var/lib/goatrope): the
//! namespace tests run them as root inside their container, from the test binary that
//! tools/build-bin.sh builds beside goatrope (`goatrope-units --include-ignored`).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;

use crate::config;
use crate::send::{Fragments, Meta, Sink};
use crate::sysutil as su;
use crate::tap;

fn sh(cmd: &str) -> bool {
    Command::new("sh").args(["-c", cmd]).status().map(|s| s.success()).unwrap_or(false)
}

#[test]
#[ignore = "mounts a tmpfs; run as root by the namespace tests"]
fn a_full_disk_leaves_the_old_file_whole() {
    std::fs::create_dir_all("/mnt/small").unwrap();
    assert!(sh("mount -t tmpfs -o size=64k tmpfs /mnt/small"));
    let res = (|| {
        su::write_file("/mnt/small/f", "good", 0o644).map_err(|e| e.to_string())?;
        if su::write_file("/mnt/small/f", &"x".repeat(200_000), 0o644).is_ok() {
            return Err("no error".to_string());
        }
        let left: Vec<String> =
            std::fs::read_dir("/mnt/small").unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
        let text = std::fs::read_to_string("/mnt/small/f").unwrap_or_default();
        if text == "good" && left == ["f"] {
            Ok(())
        } else {
            Err(format!("{text:?} {left:?}"))
        }
    })();
    sh("umount /mnt/small");
    res.unwrap();
}

#[test]
fn an_http_redirect_is_refused() {
    let srv = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = srv.local_addr().unwrap().port();
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h2 = hits.clone();
    std::thread::spawn(move || {
        for s in srv.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            if req.starts_with("GET") {
                h2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            } else {
                let _ = s.write_all(
                    format!("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/x\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                );
            }
        }
    });
    let d = config::Destination {
        url: format!("http://127.0.0.1:{port}/in"),
        scheme: "http".into(),
        host: Some("127.0.0.1".into()),
        port: Some(port),
        path: Some("/in".into()),
        framing: None,
        format: None,
        max_mb: None,
    };
    let meta = Meta { feed: "f".into(), time: 0.0, src: String::new(), dst: String::new(), sport: 0, dport: 0 };
    let e = Sink::new(d, Default::default()).send(b"x", &meta).unwrap_err();
    assert!(e.contains("302") && e.contains("refused"), "{e}");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0, "the redirect was followed");
}

#[test]
fn fragment_reassembly_holds_at_most_4_mib() {
    let mut f = Fragments::new();
    for i in 0..250u16 {
        for j in 0..40usize {
            f.add(("a".into(), "b".into(), i), j * 1480, true, &[b'x'; 1480]);
        }
    }
    assert!(f.held() <= 4 << 20, "{} bytes held of {}", f.held(), 250 * 40 * 1480);
}

#[test]
#[ignore = "adds dummy interfaces and routes; run as root by the namespace tests"]
fn default_routes_in_other_tables_and_ecmp_next_hops_are_seen() {
    assert!(sh("ip link add dr0 type dummy && ip addr add 203.0.113.1/24 dev dr0 && ip link set dr0 up"));
    assert!(sh("ip link add dr1 type dummy && ip addr add 203.0.113.129/25 dev dr1 && ip link set dr1 up"));
    sh("ip route add default dev dr0 table 77");
    let a = crate::link::default_route_devs();
    sh("ip route add default table 78 nexthop dev dr0 nexthop dev dr1");
    let b = crate::link::default_route_devs();
    sh("ip link del dr0; ip link del dr1");
    assert!(a.contains(&"dr0".to_string()) && b.contains(&"dr1".to_string()), "{a:?} {b:?}");
}

#[test]
#[ignore = "writes /var/lib/goatrope; run as root by the namespace tests"]
fn an_empty_state_file_falls_back_to_the_previous_copy() {
    std::fs::create_dir_all(tap::STATE_DIR).unwrap();
    tap::save_state_for_test(&serde_json::json!({"ports": {"a": 1}}));
    tap::save_state_for_test(&serde_json::json!({"ports": {"a": 2}}));
    std::fs::File::create(tap::STATE).unwrap();
    let r = tap::load_state().ok().flatten();
    let _ = std::fs::remove_dir_all(tap::STATE_DIR);
    assert_eq!(r, Some(serde_json::json!({"ports": {"a": 1}})));
}

#[test]
fn a_filter_that_looks_like_an_option_reaches_tcpdump_as_a_filter() {
    let text = "schema = 1\n[tap]\nmode = \"inline\"\nports = [\"tp0\", \"tp1\"]\nmanagement = \"eth0\"\n[tap.record]\nports = [\"tp0\"]\nfilter = \"-c1\"\nfile_mb = 5\nfiles = 4\n";
    let c = config::parse(text, "x.toml").unwrap();
    let a = tap::recorder_argv(&c, "tp0");
    let i = a.iter().position(|x| x == "--").expect("the filter follows --");
    assert_eq!(&a[i + 1..], ["-c1"]);
    if su::have("tcpdump") {
        let mut cmd = vec!["tcpdump".to_string(), "-d".into(), "-i".into(), "lo".into()];
        cmd.extend(a[i..].iter().cloned());
        let out = Command::new(&cmd[0]).args(&cmd[1..]).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success() && err.contains("syntax error"), "{err}");
    }
}
