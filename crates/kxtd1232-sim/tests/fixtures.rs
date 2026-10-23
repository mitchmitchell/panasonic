//! Scrubbed fixture checks for the simulator crate (milestone A2).

#![allow(clippy::unwrap_used)]

use kxtd1232::Timing;
use kxtd1232_sim::{BUSY_CADENCE_MS, PLACEHOLDER_PASSWORD, PLACEHOLDER_ROM_ID};
use serde_json::Value;

fn lines(name: &str) -> Vec<Value> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn test_fault_timing_fixture_matches_sim_defaults() {
    let rows = lines("fault-timing.jsonl");
    assert_eq!(rows.len(), 5);
    let busy = &rows[0];
    assert_eq!(busy["cadence_ms"].as_u64(), Some(BUSY_CADENCE_MS));
    let unacked = &rows[2];
    assert_eq!(
        unacked["ack_timeout_ms"].as_u64(),
        Some(Timing::default().ack_timeout_ms)
    );
    let late = &rows[3];
    assert_eq!(late["delay_ms"].as_u64(), Some(2_300));
}

#[test]
fn test_scrubbed_exchanges_use_password_placeholder() {
    let login = lines("exchanges.jsonl")
        .into_iter()
        .find(|r| r["step"].as_u64() == Some(2))
        .unwrap();
    assert_eq!(login["data"].as_str().unwrap(), "<PASSWORD>\\r\\n");
    assert!(
        lines("exchanges.jsonl")
            .iter()
            .all(|r| !r["data"].as_str().unwrap_or("").contains("mitch")),
        "no operator or site identifiers in exchange fixtures"
    );
}

#[test]
fn test_upload_headers_are_address_and_timing_only() {
    let headers = lines("full-upload-headers.jsonl");
    assert!(
        headers.len() >= 288,
        "full-upload header fixture must cover every write frame"
    );
    let write_rows: Vec<_> = headers
        .iter()
        .filter(|h| h.get("header_hex").is_some())
        .collect();
    assert_eq!(write_rows.len(), 288);
    for h in write_rows {
        assert!(h.get("payload").is_none());
        assert!(h.get("payload_hex").is_none());
        assert!(h["ack_hex"].as_str().is_some_and(|a| a == "03 00 00 03"));
    }
}

#[test]
fn test_sim_placeholders_are_scrubbed() {
    assert_eq!(PLACEHOLDER_PASSWORD, "0000");
    assert!(PLACEHOLDER_ROM_ID.contains('X'));
}
