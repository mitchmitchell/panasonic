#![allow(
    clippy::unwrap_used,
    reason = "a failed test setup step should panic the test"
)]
use kxprovd::port::journal::{LeaseEvent, LeaseJournal, GAP_TRACKING_ISSUE};
use kxprovd::port::{LeaseError, PortManager, PortMode};
use kxprovd::smdr_reader::SmdrSource;
use kxtd1232::Transport;
use kxtd1232_sim::{SimPbx, SimTransport};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

fn manager(dir: &tempfile::TempDir, max: usize) -> PortManager<SimTransport> {
    PortManager::new(
        SimTransport::new(SimPbx::new(Default::default(), "1234")),
        LeaseJournal::new(dir.path().join("lease.jsonl")),
        max,
    )
}

fn events(dir: &tempfile::TempDir) -> Vec<(LeaseEvent, String)> {
    LeaseJournal::new(dir.path().join("lease.jsonl"))
        .read_all()
        .unwrap()
        .into_iter()
        .map(|r| (r.event, r.job_id))
        .collect()
}

#[test]
fn smdr_mode_is_the_default() {
    let dir = tempfile::tempdir().unwrap();
    let pm = manager(&dir, 1);
    assert_eq!(pm.mode(), PortMode::Smdr);
    assert_eq!(pm.holder(), None);
}

#[test]
fn lease_switches_mode_and_release_returns_to_smdr() {
    let dir = tempfile::tempdir().unwrap();
    let pm = manager(&dir, 1);
    let lease = pm
        .request_lease("job-1", Duration::from_millis(50))
        .unwrap();
    assert_eq!(pm.mode(), PortMode::Programming);
    assert_eq!(pm.holder().as_deref(), Some("job-1"));
    lease.release().unwrap();
    assert_eq!(pm.mode(), PortMode::Smdr);
    assert_eq!(pm.holder(), None);
}

#[test]
fn release_sends_bye_then_cycles_dtr_on_the_simulator() {
    let dir = tempfile::tempdir().unwrap();
    let pm = manager(&dir, 1);
    let mut handle = pm.smdr_handle();
    let greeting = handle.recv(100).unwrap();
    assert!(!greeting.is_empty());
    let mut lease = pm
        .request_lease("job-1", Duration::from_millis(50))
        .unwrap();
    lease.send(b"X").unwrap();
    lease.release().unwrap();
    let sent = pm.inspect_transport(|t| t.sent.clone()).unwrap();
    assert!(sent.ends_with(b"BYE\r\n"), "{sent:?}");
    assert_eq!(handle.recv(100).unwrap(), greeting);
}

#[test]
fn dropping_a_lease_releases_it() {
    let dir = tempfile::tempdir().unwrap();
    let pm = manager(&dir, 1);
    drop(
        pm.request_lease("job-1", Duration::from_millis(50))
            .unwrap(),
    );
    assert_eq!(pm.mode(), PortMode::Smdr);
    let sent = pm.inspect_transport(|t| t.sent.clone()).unwrap();
    assert!(sent.ends_with(b"BYE\r\n"));
}

#[test]
fn second_lease_times_out_with_a_typed_error() {
    let dir = tempfile::tempdir().unwrap();
    let pm = manager(&dir, 1);
    let _held = pm
        .request_lease("job-1", Duration::from_millis(50))
        .unwrap();
    match pm.request_lease("job-2", Duration::from_millis(30)) {
        Err(LeaseError::Timeout { waited_ms }) => assert!(waited_ms >= 30),
        other => panic!("{:?}", other.err()),
    }
}

#[test]
fn full_waiter_queue_refuses_immediately() {
    let dir = tempfile::tempdir().unwrap();
    let pm = Arc::new(manager(&dir, 1));
    let held = pm
        .request_lease("job-1", Duration::from_millis(50))
        .unwrap();
    let waiter = {
        let pm = Arc::clone(&pm);
        std::thread::spawn(move || {
            pm.request_lease("job-2", Duration::from_secs(5))
                .map(|l| l.job_id().to_string())
        })
    };
    while !events(&dir).contains(&(LeaseEvent::Requested, "job-2".into())) {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(20));
    match pm.request_lease("job-3", Duration::from_secs(5)) {
        Err(LeaseError::QueueFull { max }) => assert_eq!(max, 1),
        other => panic!("{:?}", other.err()),
    }
    held.release().unwrap();
    assert_eq!(waiter.join().unwrap().unwrap(), "job-2");
}

#[test]
fn smdr_handle_waits_while_a_lease_is_held() {
    let dir = tempfile::tempdir().unwrap();
    let pm = manager(&dir, 1);
    let mut handle = pm.smdr_handle();
    let _lease = pm
        .request_lease("job-1", Duration::from_millis(50))
        .unwrap();
    assert!(matches!(
        handle.recv(20),
        Err(kxtd1232::TransportError::Timeout)
    ));
}

#[test]
fn lease_events_are_journaled_with_utc_time_job_id_and_gap_link() {
    let dir = tempfile::tempdir().unwrap();
    let pm = manager(&dir, 1);
    let lease = pm
        .request_lease("job-7", Duration::from_millis(50))
        .unwrap();
    let _ = pm.request_lease("job-8", Duration::from_millis(10));
    lease.release().unwrap();
    let path = dir.path().join("lease.jsonl");
    let records = LeaseJournal::new(&path).read_all().unwrap();
    let got: Vec<_> = records
        .iter()
        .map(|r| (r.event, r.job_id.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            (LeaseEvent::Requested, "job-7"),
            (LeaseEvent::Granted, "job-7"),
            (LeaseEvent::ReaderPaused, "job-7"),
            (LeaseEvent::Requested, "job-8"),
            (LeaseEvent::TimedOut, "job-8"),
            (LeaseEvent::Released, "job-7"),
            (LeaseEvent::ReaderResumed, "job-7"),
        ]
    );
    for r in &records {
        assert!(r.ts_utc.ends_with('Z'), "{}", r.ts_utc);
        chrono::DateTime::parse_from_rfc3339(&r.ts_utc).unwrap();
        assert_eq!(r.gap_tracking, GAP_TRACKING_ISSUE);
    }
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}
