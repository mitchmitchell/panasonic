//! Scrubbed fixture checks (milestone A2). Exchange/upload fixtures live in `kxtd1232`; this
//! crate keeps only sim-specific `fault-timing.jsonl`.

#![allow(clippy::unwrap_used)]

use kxtd1232::Timing;
use kxtd1232_sim::{SimConfig, PLACEHOLDER_PASSWORD, PLACEHOLDER_ROM_ID};
use serde_json::Value;
use std::path::PathBuf;

fn sim_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn core_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../kxtd1232/tests/fixtures")
        .join(name)
}

fn lines(path: PathBuf) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn test_fault_timing_fixture_matches_sim_defaults() {
    let rows = lines(sim_fixture("fault-timing.jsonl"));
    assert_eq!(rows.len(), 5);
    let cfg = SimConfig::default();
    let lockup = &rows[0];
    assert_eq!(lockup["fault"].as_str(), Some("busy_lockup"));
    assert_eq!(
        lockup["busy_lockup_frames"].as_u64(),
        Some(u64::from(cfg.busy_lockup_frames))
    );
    assert_eq!(
        lockup["busy_lockup_interval_ms"].as_u64(),
        Some(cfg.busy_lockup_interval_ms)
    );
    let past = &rows[1];
    assert_eq!(past["frames_over"].as_u64(), Some(200));
    let unacked = &rows[2];
    assert_eq!(
        unacked["ack_timeout_ms"].as_u64(),
        Some(Timing::default().ack_timeout_ms)
    );
    let late = rows
        .iter()
        .find(|r| r["fault"].as_str() == Some("late_ack"))
        .unwrap();
    assert_eq!(late["delay_ms"].as_u64(), Some(2_300));
    // Same delay injected in `fault_suite::test_a2_late_ack_garbled_stale`.
}

#[test]
fn test_core_exchange_fixture_uses_signon_placeholder() {
    let rows = lines(core_fixture("exchanges.jsonl"));
    let banner = rows.iter().find(|r| r["step"].as_u64() == Some(1)).unwrap();
    assert!(banner["data"]
        .as_str()
        .unwrap()
        .starts_with("<SIGNON_BANNER>"));
}

#[test]
fn test_core_upload_headers_are_address_only() {
    let headers = lines(core_fixture("full-upload-headers.jsonl"));
    let write_rows: Vec<_> = headers
        .iter()
        .filter(|h| h.get("header_hex").is_some())
        .collect();
    assert_eq!(write_rows.len(), 288);
    for h in write_rows {
        assert!(h.get("payload").is_none());
        assert!(h.get("payload_hex").is_none());
    }
}

#[test]
fn test_sim_placeholders_are_scrubbed() {
    assert_eq!(PLACEHOLDER_PASSWORD, "0000");
    assert!(PLACEHOLDER_ROM_ID.contains('X'));
}
