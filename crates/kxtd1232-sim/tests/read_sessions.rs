//! Replays the `sessions/` timing fixtures against `SimPbx`. The fixtures hold no frame
//! bytes: every host frame is rebuilt from the read plan and every pbx reply comes from
//! the simulator, then checked against the recorded direction, type and length.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a malformed fixture or failed setup step should panic the test"
)]

use kxtd1232::frame::{checksum, classify, frame_length, Access, Encoder, ReplyKind};
use kxtd1232::{Client, Cmd, Timing, Transport};
use kxtd1232_sim::{SimPbx, SimTransport, PLACEHOLDER_PASSWORD};
use serde_json::Value;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn plan_frames() -> Vec<Vec<u8>> {
    let plan: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture("read-plan-headers.json")).unwrap())
            .unwrap();
    plan["requests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let table =
                u8::from_str_radix(r["table"].as_str().unwrap().trim_start_matches("0x"), 16)
                    .unwrap();
            let record = u16::try_from(r["record"].as_u64().unwrap()).unwrap();
            let offset = u16::try_from(r["offset"].as_u64().unwrap()).unwrap();
            let words = u8::try_from(r["length"].as_u64().unwrap() / 2).unwrap();
            let mut f = vec![0x08, 0x01, table];
            f.extend_from_slice(&record.to_be_bytes());
            f.extend_from_slice(&offset.to_be_bytes());
            f.push(words);
            f.push(checksum(&f));
            f
        })
        .collect()
}

fn session_rows(name: &str) -> Vec<Value> {
    std::fs::read_to_string(fixture(&format!("sessions/{name}")))
        .unwrap()
        .lines()
        .skip(1)
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn host_frame(row: &Value, plan: &[Vec<u8>], enc: &Encoder) -> Vec<u8> {
    match row["type"].as_str().unwrap() {
        "read_req" => plan[usize::try_from(row["plan"].as_u64().unwrap()).unwrap()].clone(),
        "probe" => match row["probe"].as_str().unwrap() {
            "version" => enc.version_probe(),
            "status" => enc.status_probe(),
            other => panic!("unknown probe kind {other}"),
        },
        "end_binary" => enc.end_binary(),
        other => panic!("unknown host frame type {other}"),
    }
}

fn recv_frame<T: Transport>(t: &mut T) -> Vec<u8> {
    let mut buf = Vec::new();
    loop {
        if let Some(n) = frame_length(&buf).unwrap() {
            if buf.len() >= n {
                assert_eq!(buf.len(), n, "trailing bytes after reply");
                return buf;
            }
        }
        buf.extend(t.recv(10_000).unwrap());
    }
}

fn reply_type(raw: &[u8]) -> &'static str {
    let r = classify(raw).unwrap();
    match (r.cmd, r.kind) {
        (cmd, _) if cmd == Cmd::Probe.byte() => "probe_reply",
        (cmd, ReplyKind::Ack) if cmd == Cmd::EndBinary.byte() => "end_binary_ack",
        (0x01, ReplyKind::Refused) => "refusal",
        (0x01, ReplyKind::Data(_)) => "read_reply",
        (cmd, kind) => panic!("unexpected reply cmd {cmd:02X}: {kind:?}"),
    }
}

fn replay(name: &str, frames: usize, refusals: usize) {
    let rows = session_rows(name);
    assert_eq!(rows.len(), frames);
    for r in &rows {
        assert!(r.get("frame").is_none(), "{name} stores frame bytes");
    }
    let plan = plan_frames();
    let enc = Encoder::new(Access::ReadOnly);
    let mut c = Client::with(
        SimTransport::new(SimPbx::default()),
        Access::ReadOnly,
        Timing::default(),
    );
    c.login(PLACEHOLDER_PASSWORD).unwrap();
    let t = c.transport_mut();
    let mut last_ms = 0;
    let mut seen_refusals = 0;
    for pair in rows.chunks(2) {
        let [host, pbx] = pair else {
            panic!("{name}: odd frame count")
        };
        assert_eq!(host["dir"], "host");
        assert_eq!(pbx["dir"], "pbx");
        for row in pair {
            let ms = row["t_ms"].as_u64().unwrap();
            assert!(ms >= last_ms, "{name}: t_ms goes backwards at {ms}");
            last_ms = ms;
        }
        let sent = host_frame(host, &plan, &enc);
        assert_eq!(sent.len() as u64, host["len"].as_u64().unwrap());
        t.send(&sent).unwrap();
        let reply = recv_frame(t);
        assert_eq!(
            reply.len() as u64,
            pbx["len"].as_u64().unwrap(),
            "{name}: reply length to {sent:02X?}"
        );
        let kind = reply_type(&reply);
        assert_eq!(
            kind,
            pbx["type"].as_str().unwrap(),
            "{name}: reply to {sent:02X?}"
        );
        if kind == "refusal" {
            seen_refusals += 1;
        }
    }
    assert_eq!(seen_refusals, refusals);
}

#[test]
fn live_full_backup_session_replays_against_the_sim() {
    replay("read-live-full-backup.jsonl", 760, 85);
}

#[test]
fn fullbridge_download_session_replays_against_the_sim() {
    replay("read-fullbridge-download.jsonl", 770, 85);
}

#[test]
fn every_plan_request_appears_in_both_sessions_in_order() {
    for name in [
        "read-live-full-backup.jsonl",
        "read-fullbridge-download.jsonl",
    ] {
        let idx: Vec<u64> = session_rows(name)
            .iter()
            .filter(|r| r["type"] == "read_req")
            .map(|r| r["plan"].as_u64().unwrap())
            .collect();
        assert!(idx.windows(2).all(|w| w[0] <= w[1]), "{name}");
        let mut uniq = idx.clone();
        uniq.dedup();
        assert_eq!(uniq, (0..305).collect::<Vec<u64>>(), "{name}");
    }
}
