// SPDX-License-Identifier: GPL-3.0-or-later
//! End-to-end tests of the binary against fixture DNS.

use std::io::Write;
use std::process::{Command, Output, Stdio};

const ZONE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/zone.txt");

fn run(args: &[&str], stdin: Option<&str>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_spf-flatten"))
        .arg("--dns-file")
        .arg(ZONE)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut pipe = child.stdin.take().unwrap();
    // The child may exit without reading stdin; ignore a broken pipe.
    let _ = pipe.write_all(stdin.unwrap_or("").as_bytes());
    drop(pipe);
    child.wait_with_output().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn check_reports_lookups() {
    let o = run(&["check", "example.com"], None);
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("lookups:      6 of 10"), "{out}");
    assert!(out.contains("exists:%{i}._spf.crm.provider.test"));
}

#[test]
fn check_fails_on_missing_include() {
    let o = run(&["check", "broken.test"], None);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("no SPF record at missing.test"));
}

#[test]
fn import_then_flatten() {
    let o = run(&["import", "example.com"], None);
    assert!(o.status.success(), "{}", stderr(&o));
    let config = stdout(&o);
    assert!(config.contains("include = \"mail.provider.test\""));
    assert!(config.contains("policy = \"~all\""));

    let o = run(&["flatten", "-i", "-", "-f", "plain"], Some(&config));
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(
        stdout(&o),
        "example.com\tv=spf1 ip4:192.0.2.25 ip4:198.51.100.0/24 ip4:203.0.113.0/24 \
         ip6:2001:db8::25 ip6:2001:db8:100::/48 exists:%{i}._spf.crm.provider.test ~all\n"
    );
    assert!(stderr(&o).contains("1 of 10 lookups (unflattened: 6)"));
}

#[test]
fn flatten_json() {
    let config = r#"
        domain = "example.com"
        policy = "-all"
        [[source]]
        include = "mail.provider.test"
        keep = true
        [[source]]
        ip4 = "192.0.2.1"
    "#;
    let o = run(&["flatten", "-i", "-", "-f", "json"], Some(config));
    assert!(o.status.success(), "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["lookups"], 3);
    assert_eq!(
        v["records"][0]["value"],
        "v=spf1 ip4:192.0.2.1 include:mail.provider.test -all"
    );
}

#[test]
fn diff_detects_drift() {
    let config = r#"
        domain = "drift.test"
        policy = "~all"
        [[source]]
        include = "mail.provider.test"
    "#;
    let o = run(&["diff", "-i", "-"], Some(config));
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("+ ip6:2001:db8:100::/48"), "{out}");
    assert!(out.contains("- ip4:203.0.113.0/24"), "{out}");
}

#[test]
fn diff_in_sync() {
    let config = r#"
        domain = "drift.test"
        policy = "~all"
        [[source]]
        ip4 = ["198.51.100.0/25", "198.51.100.128/25", "203.0.113.0/24"]
    "#;
    let o = run(&["diff", "-i", "-"], Some(config));
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains("in sync"));
}

#[test]
fn bad_config_exits_2() {
    let o = run(&["flatten", "-i", "-"], Some("domain = \"example.com\"\n"));
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("policy"));
}
