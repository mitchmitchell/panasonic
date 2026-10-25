//! CLI tests (ported from #1 tests/sim/test_cli.py). Exit codes: 0 ok, 1 runtime/refused,
//! 2 usage.

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kxprov"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn test_version() {
    let o = run(&["version"]);
    assert_eq!(o.status.code(), Some(0));
    let s = stdout(&o);
    assert!(s.starts_with(&format!("kxprov {}\n", env!("CARGO_PKG_VERSION"))));
    assert!(s.contains("pbx -----PXXXXXXXXXX"));
    assert_eq!(run(&["--version"]).status.code(), Some(0));
}

#[test]
fn test_read() {
    let o = run(&["read", "cid_name", "--count", "2"]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(stdout(&o), "0\tTEST ONE\n1\t\n");
    let o = run(&["read", "cid_number", "--count", "1"]);
    assert_eq!(stdout(&o), "0\t123\n");
}

#[test]
fn test_plan_dry_run() {
    let o = run(&["plan", "cid_name", "3", "HI"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(
        stdout(&o).trim(),
        r#"{"table": 37, "writes": 1, "diff": ["T25 +0x0030: 00 -> 48", "T25 +0x0031: 00 -> 49"]}"#
    );
}

#[test]
fn test_plan_rejects_bad_value() {
    let o = run(&["plan", "cid_number", "1", "12a"]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn test_plan_refuses_ext_name_until_g6() {
    let o = run(&["plan", "ext_name", "1", "X"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("not on the editable list"));
}

#[test]
fn test_bad_ranges_are_usage_errors() {
    for argv in [
        &["read", "cid_name", "--first", "499", "--count", "2"][..],
        &["read", "cid_name", "--count", "0"],
        &["read", "ext_name", "--first", "128"],
        &["read", "cid_name", "--first", "-1"],
        &["plan", "cid_name", "500", "X"],
        &["plan", "nope", "1", "X"],
        &["read"],
        &["--transport", "serial", "version"],
    ] {
        let o = run(argv);
        assert_eq!(o.status.code(), Some(2), "{argv:?}: {}", stderr(&o));
        assert!(!stderr(&o).contains("panicked"));
    }
}

#[test]
fn test_last_cid_name_record_matches_sim() {
    let o = run(&["read", "cid_name", "--first", "499", "--count", "1"]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(stdout(&o), "499\t\n");
}

#[test]
fn test_invalid_value_uses_error_prefix() {
    for argv in [
        &["plan", "cid_name", "1", "ÄÖ"][..],
        &["plan", "ext_name", "1", "X"],
    ] {
        let e = stderr(&run(argv));
        assert!(e.starts_with("kxprov: error: "), "{e}");
        assert_eq!(e.lines().count(), 1, "one line: {e}");
    }
}

#[test]
fn test_clap_usage_errors_are_one_line() {
    for argv in [
        &["read"][..],
        &["--bogus"],
        &["read", "cid_name", "--first", "x"],
        &[],
    ] {
        let o = run(argv);
        assert_eq!(o.status.code(), Some(2), "{argv:?}");
        let e = stderr(&o);
        assert!(e.starts_with("kxprov: error: "), "{e}");
        assert_eq!(e.lines().count(), 1, "one line: {e}");
    }
}
