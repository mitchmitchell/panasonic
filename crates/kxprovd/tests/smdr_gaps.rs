#![allow(
    clippy::unwrap_used,
    reason = "test setup failures should abort the test"
)]

use chrono::Utc;
use kxprov_api::{GapWindow, QueryLimit, SmdrPage, SmdrQueryParams, GAP_TRACKING};
use kxprovd::port::journal::{LeaseEvent, LeaseJournal};
use kxprovd::port::PortManager;
use kxprovd::smdr_api::{db_path, gap_windows, lease_journal_path, query};
use kxprovd::smdr_store::SmdrStore;
use kxtd1232::smdr::{DateOrder, SmdrLine};
use kxtd1232_sim::smdr::{BufferPolicy, LineEnding, SmdrEmitter, SyntheticCall};
use std::path::Path;
use std::time::Duration;

fn manager(dir: &Path) -> PortManager<()> {
    PortManager::new((), LeaseJournal::new(lease_journal_path(dir)), 4)
}

fn page(dir: &Path) -> SmdrPage {
    let now = Utc::now().timestamp_millis() + 60_000;
    let p = SmdrQueryParams {
        limit: QueryLimit::new(500).unwrap(),
        ..SmdrQueryParams::with_defaults(None, None, now)
    };
    query(&db_path(dir), &lease_journal_path(dir), &p).unwrap()
}

fn tick() {
    std::thread::sleep(Duration::from_millis(5));
}

fn call(number: &str) -> SyntheticCall {
    SyntheticCall {
        date: "10/23/26".into(),
        time: "01:05PM".into(),
        ext: "101".into(),
        co: "01".into(),
        number: number.into(),
        duration: "00:01'00".into(),
        ..SyntheticCall::default()
    }
}

fn ingest_output(store: &mut SmdrStore, emitter: &mut SmdrEmitter) {
    let out = String::from_utf8(emitter.take_output()).unwrap();
    for line in out.split("\r\n").filter(|l| !l.is_empty()) {
        store
            .ingest(SmdrLine::new(line.to_string()), Utc::now())
            .unwrap();
        tick();
    }
}

#[test]
fn one_gap_per_lease_not_per_attempt_and_open_lease_has_no_end() {
    let tmp = tempfile::tempdir().unwrap();
    drop(SmdrStore::open(tmp.path(), &[], DateOrder::Mdy).unwrap());
    let pm = manager(tmp.path());
    let lease = pm
        .request_lease("job-a", Duration::from_millis(50))
        .unwrap();
    for _ in 0..3 {
        assert!(pm.request_lease("job-b", Duration::from_millis(5)).is_err());
    }
    tick();
    lease.release().unwrap();
    let held = pm
        .request_lease("job-c", Duration::from_millis(50))
        .unwrap();
    let gaps = page(tmp.path()).gaps;
    let jobs: Vec<_> = gaps.iter().map(|g| g.job_id.as_str()).collect();
    assert_eq!(jobs, ["job-a", "job-c"]);
    assert!(gaps[0].to_utc.as_deref().unwrap() > gaps[0].from_utc.as_str());
    assert_eq!(gaps[1].to_utc, None);
    assert!(gaps.iter().all(|g| g.tracking == GAP_TRACKING));
    held.release().unwrap();
}

#[test]
fn gaps_outside_the_range_are_left_out_and_torn_lines_are_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let j = lease_journal_path(tmp.path());
    let line = |ts: &str, ev: &str, job: &str| {
        format!(
            "{{\"ts_utc\":\"{ts}\",\"event\":\"{ev}\",\"job_id\":\"{job}\",\"gap_tracking\":\"{GAP_TRACKING}\"}}\n"
        )
    };
    let text = [
        line("2026-11-01T10:00:00.000Z", "reader_paused", "old"),
        line("2026-11-01T10:05:00.000Z", "reader_resumed", "old"),
        line("2026-11-01T12:00:00.000Z", "reader_paused", "crashed"),
        line("2026-11-01T12:30:00.000Z", "reader_paused", "next"),
        line("2026-11-01T12:31:00.000Z", "reader_paused", "next"),
        line("2026-11-01T12:40:00.000Z", "reader_resumed", "next"),
        "{\"ts_utc\":\"2026-11-01T13".to_string(),
    ]
    .concat();
    std::fs::write(&j, text).unwrap();
    let gaps = gap_windows(&j, "2026-11-01T11:00:00.000Z", "2026-11-01T14:00:00.000Z").unwrap();
    let want = |from: &str, to: &str, job: &str| GapWindow {
        from_utc: from.into(),
        to_utc: Some(to.into()),
        job_id: job.into(),
        tracking: GAP_TRACKING.into(),
    };
    assert_eq!(
        gaps,
        [
            want(
                "2026-11-01T12:00:00.000Z",
                "2026-11-01T12:30:00.000Z",
                "crashed"
            ),
            want(
                "2026-11-01T12:30:00.000Z",
                "2026-11-01T12:40:00.000Z",
                "next"
            ),
        ]
    );
    assert!(gap_windows(&tmp.path().join("none.jsonl"), "a", "z")
        .unwrap()
        .is_empty());
    assert_eq!(
        LeaseEvent::ReaderPaused,
        serde_json::from_str("\"reader_paused\"").unwrap()
    );
}

#[test]
fn both_sim_buffer_policies_place_calls_relative_to_the_gap() {
    for policy in [BufferPolicy::ReplayAfterBye, BufferPolicy::Drop] {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = SmdrStore::open(tmp.path(), &[], DateOrder::Mdy).unwrap();
        let mut emitter = SmdrEmitter::new(policy, LineEnding::CrLf);
        let pm = manager(tmp.path());
        emitter.call_ended(&call("5550000001")).unwrap();
        ingest_output(&mut store, &mut emitter);
        let lease = pm
            .request_lease("job-p", Duration::from_millis(50))
            .unwrap();
        emitter.begin_programming();
        tick();
        emitter.call_ended(&call("5550000002")).unwrap();
        ingest_output(&mut store, &mut emitter);
        tick();
        lease.release().unwrap();
        emitter.end_programming();
        tick();
        ingest_output(&mut store, &mut emitter);
        let page = page(tmp.path());
        assert_eq!(page.gaps.len(), 1, "{policy:?}");
        let gap = &page.gaps[0];
        let to = gap.to_utc.clone().unwrap();
        let inside = |ts: &str| ts >= gap.from_utc.as_str() && ts < to.as_str();
        assert!(
            page.calls.iter().all(|c| !inside(&c.rx_ts_utc)),
            "{policy:?}"
        );
        let numbers: Vec<_> = page.calls.iter().map(|c| c.number.as_str()).collect();
        match policy {
            BufferPolicy::ReplayAfterBye => {
                assert_eq!(numbers, ["5550000002", "5550000001"]);
                assert!(page.calls[0].rx_ts_utc >= to);
                assert!(page.calls[1].rx_ts_utc < gap.from_utc);
            }
            BufferPolicy::Drop => {
                assert_eq!(numbers, ["5550000001"]);
                assert_eq!(emitter.dropped(), 1);
            }
        }
    }
}
