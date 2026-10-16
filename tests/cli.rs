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

fn json_of(o: &Output) -> serde_json::Value {
    serde_json::from_str(&stdout(o)).unwrap_or_else(|e| panic!("{e}: {}", stdout(o)))
}

#[test]
fn check_suggests_flattened_records() {
    let o = run(&["check", "example.com"], None);
    let out = stdout(&o);
    assert!(
        out.contains("suggested flattened records (6 of 10 lookups, verified; not needed"),
        "{out}"
    );
    assert!(
        out.contains("[keep-own-host] mx: authorizes ip4:192.0.2.25"),
        "{out}"
    );
    assert!(out.contains("dmarc:        none published"), "{out}");
    assert!(
        out.contains("[softfail-unenforced] ~all: _dmarc.example.com has no DMARC record"),
        "{out}"
    );

    let o = run(&["--json", "check", "example.com"], None);
    let v = json_of(&o);
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["command"], "check");
    assert_eq!(v["ok"], true);
    assert_eq!(v["lookups"], 6);
    assert_eq!(v["recommendations"][0]["code"], "keep-own-host");
    // ~all with no DMARC record behind it.
    assert_eq!(v["dmarc"], serde_json::Value::Null);
    assert_eq!(v["recommendations"][1]["code"], "softfail-unenforced");
    assert_eq!(v["suggested"]["ok"], true);
    assert_eq!(v["suggested"]["needed"], false);
    assert_eq!(v["suggested"]["lookups"], 6);
    assert_eq!(v["suggested"]["strategy"], "minimal");
    assert_eq!(v["suggested"]["unflattened_lookups"], 6);
}

#[test]
fn check_reads_all_against_dmarc() {
    let v = json_of(&run(&["--json", "check", "strict.test"], None));
    assert_eq!(v["dmarc"]["policy"], "reject");
    assert_eq!(v["dmarc"]["name"], "_dmarc.strict.test");
    assert_eq!(v["recommendations"][0]["code"], "fail-preempts-dmarc");
}

#[test]
fn json_errors_are_documents() {
    let o = run(&["--json", "-q", "check", "nothing.test"], None);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).is_empty(), "{}", stderr(&o));
    let v = json_of(&o);
    assert_eq!(v["ok"], false);
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("no usable SPF record")
    );
    assert_eq!(v["problems"][0]["severity"], "error");
}

const CLOUD: &str = r#"
    domain = "widened.test"
    policy = "-all"
    [[source]]
    include = "cloud.provider.test"
"#;

#[test]
fn widening_absorbs_drift() {
    let o = run(&["--json", "diff", "-i", "-"], Some(CLOUD));
    assert_eq!(
        o.status.code(),
        Some(1),
        "exact flattening differs from the published /24"
    );
    let v = json_of(&o);
    assert_eq!(v["in_sync"], false);
    assert!(v["missing"].as_array().unwrap().is_empty());
    assert!(!v["extra"].as_array().unwrap().is_empty());

    let widened = format!("widen_ipv4 = 24\n{CLOUD}");
    let o = run(&["--json", "diff", "-i", "-"], Some(&widened));
    assert!(o.status.success(), "{}", stdout(&o));
    let v = json_of(&o);
    assert_eq!(v["in_sync"], true);
    assert_eq!(v["widening"]["ipv4_prefix"], 24);
    assert_eq!(v["widening"]["widened"], 4);
    assert_eq!(v["widening"]["extra_ipv4_addresses"], 251);
}

#[test]
fn risk_scores_and_records_history() {
    let dir = std::env::temp_dir().join(format!("spf-flatten-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.json");
    let state_arg = state.to_str().unwrap();

    let o = run(
        &[
            "--json",
            "risk",
            "-i",
            "-",
            "--state",
            state_arg,
            "--fail-on",
            "high",
        ],
        Some(CLOUD),
    );
    assert_eq!(o.status.code(), Some(1), "{}", stdout(&o));
    let v = json_of(&o);
    assert_eq!(v["worst"], "high");
    assert_eq!(v["sources"][0]["min_ttl"], 300);
    assert_eq!(v["sources"][0]["hosts"], 5);
    assert_eq!(v["sources"][0]["history"]["checks"], 1);
    assert!(
        v["suggestions"][0]["advice"]
            .as_str()
            .unwrap()
            .starts_with("set keep = true")
    );

    let o = run(
        &["--json", "risk", "-i", "-", "--state", state_arg],
        Some(CLOUD),
    );
    assert!(o.status.success());
    assert_eq!(json_of(&o)["sources"][0]["history"]["checks"], 2);
    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
    assert_eq!(
        saved["sources"]["include:cloud.provider.test"]["changes"],
        0
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn minimal_keeps_the_record_when_it_fits() {
    let o = run(&["--json", "--minimal", "flatten", "-i", "-"], Some(CLOUD));
    assert!(o.status.success(), "{}", stderr(&o));
    let v = json_of(&o);
    assert_eq!(v["strategy"], "minimal");
    assert_eq!(
        v["records"][0]["value"],
        "v=spf1 include:cloud.provider.test -all"
    );
    assert_eq!(v["minimal"]["choices"][0]["flattened"], false);
}

#[test]
fn minimal_flattens_only_what_the_target_needs() {
    // mail.provider.test costs 3 lookups, crm.provider.test 2 (include + exists).
    let config = r#"
        domain = "example.com"
        policy = "~all"
        [[source]]
        include = "mail.provider.test"
        [[source]]
        include = "crm.provider.test"
    "#;
    let o = run(
        &[
            "--json",
            "--minimal",
            "--headroom",
            "7",
            "flatten",
            "-i",
            "-",
        ],
        Some(config),
    );
    assert!(o.status.success(), "{}", stderr(&o));
    let v = json_of(&o);
    assert_eq!(v["unflattened_lookups"], 5);
    assert_eq!(v["minimal"]["target"], 3);
    assert_eq!(v["lookups"], 2);
    let choices = &v["minimal"]["choices"];
    assert_eq!(choices[0]["source"], "include:mail.provider.test");
    assert_eq!(choices[0]["flattened"], true);
    assert_eq!(choices[1]["flattened"], false);
    assert!(
        v["records"][0]["value"]
            .as_str()
            .unwrap()
            .contains("include:crm.provider.test")
    );
}
