#![allow(
    clippy::unwrap_used,
    reason = "a failed test setup step should panic the test"
)]
use kxprovd::port::journal::{LeaseEvent, LeaseJournal, LeaseLog, GAP_TRACKING_ISSUE};
use kxprovd::port::{
    LeaseError, PortManager, PortMode, PortReleaseError, ProgrammingLease, SessionMode, BYE,
    ECS_OF, END_BINARY, PRG,
};
use kxprovd::smdr_reader::SmdrSource;
use kxtd1232::Transport;
use kxtd1232_sim::{SimPbx, SimTransport};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn manager(dir: &tempfile::TempDir, max: usize) -> PortManager<SimTransport> {
    PortManager::new(
        SimTransport::new(SimPbx::new(Default::default(), "1234")),
        LeaseJournal::new(dir.path().join("lease.jsonl")),
        max,
    )
}

fn read_until(lease: &mut ProgrammingLease<SimTransport>, want: &[u8]) {
    let mut got = Vec::new();
    while !got.windows(want.len()).any(|w| w == want) {
        got.extend(lease.recv(500).unwrap());
    }
}

fn login(lease: &mut ProgrammingLease<SimTransport>) {
    lease.send(b"\r\n").unwrap();
    let signon = kxtd1232::SignOn::default();
    read_until(lease, signon.password_prompt.as_bytes());
    lease.send(b"1234\r").unwrap();
    read_until(lease, signon.mode_start.as_bytes());
    lease.send(ECS_OF).unwrap();
    read_until(lease, b"OK");
    lease.send(PRG).unwrap();
    read_until(lease, b"OK");
    assert_eq!(lease.session_mode(), SessionMode::Binary);
}

fn position(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
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
fn release_ends_binary_then_bye_then_drops_dtr() {
    let dir = tempfile::tempdir().unwrap();
    let pm = manager(&dir, 1);
    let mut handle = pm.smdr_handle();
    let greeting = handle.recv(100).unwrap();
    assert!(!greeting.is_empty());
    let mut lease = pm
        .request_lease("job-1", Duration::from_millis(50))
        .unwrap();
    login(&mut lease);
    lease.release().unwrap();
    let sent = pm.inspect_transport(|t| t.sent.clone()).unwrap();
    let end = position(&sent, &END_BINARY).expect("end-binary sent");
    let bye = position(&sent, BYE).expect("BYE sent");
    assert!(end < bye, "BYE before end-binary: {sent:02X?}");
    assert!(sent.ends_with(BYE), "{sent:?}");
    assert_eq!(handle.recv(100).unwrap(), greeting);
}

#[test]
fn unacked_end_binary_never_sends_bye_and_still_drops_dtr() {
    let dir = tempfile::tempdir().unwrap();
    let pm = PortManager::with_release_step_timeout(
        SimTransport::new(SimPbx::new(Default::default(), "1234")),
        LeaseJournal::new(dir.path().join("lease.jsonl")),
        1,
        Duration::from_millis(200),
    );
    let mut handle = pm.smdr_handle();
    let greeting = handle.recv(100).unwrap();
    let mut lease = pm
        .request_lease("job-1", Duration::from_millis(50))
        .unwrap();
    lease.send(PRG).unwrap();
    assert_eq!(lease.session_mode(), SessionMode::Binary);
    assert!(matches!(
        lease.release(),
        Err(PortReleaseError::EndBinaryNotAcked { .. })
    ));
    let sent = pm.inspect_transport(|t| t.sent.clone()).unwrap();
    assert!(sent.ends_with(&END_BINARY), "{sent:02X?}");
    assert_eq!(position(&sent, BYE), None);
    assert_eq!(pm.mode(), PortMode::Smdr);
    assert_eq!(handle.recv(100).unwrap(), greeting);
}

#[test]
fn unconfirmed_bye_is_a_typed_error_and_still_drops_dtr() {
    let dir = tempfile::tempdir().unwrap();
    let mut pbx = SimPbx::new(Default::default(), "1234");
    pbx.silent_bye = true;
    let pm = PortManager::with_release_step_timeout(
        SimTransport::new(pbx),
        LeaseJournal::new(dir.path().join("lease.jsonl")),
        1,
        Duration::from_millis(200),
    );
    let mut handle = pm.smdr_handle();
    let greeting = handle.recv(100).unwrap();
    let mut lease = pm
        .request_lease("job-1", Duration::from_millis(50))
        .unwrap();
    login(&mut lease);
    assert!(matches!(
        lease.release(),
        Err(PortReleaseError::ByeNotAcked { .. })
    ));
    assert_eq!(pm.mode(), PortMode::Smdr);
    assert_eq!(handle.recv(100).unwrap(), greeting);
}

#[test]
fn a_signed_out_lease_only_drops_dtr() {
    let dir = tempfile::tempdir().unwrap();
    let pm = manager(&dir, 1);
    let mut lease = pm
        .request_lease("job-1", Duration::from_millis(50))
        .unwrap();
    lease.send(b"X").unwrap();
    lease.release().unwrap();
    let sent = pm.inspect_transport(|t| t.sent.clone()).unwrap();
    assert_eq!(sent, b"X");
}

#[test]
fn dropping_a_lease_releases_it() {
    let dir = tempfile::tempdir().unwrap();
    let pm = manager(&dir, 1);
    let mut lease = pm
        .request_lease("job-1", Duration::from_millis(50))
        .unwrap();
    login(&mut lease);
    drop(lease);
    assert_eq!(pm.mode(), PortMode::Smdr);
    let sent = pm.inspect_transport(|t| t.sent.clone()).unwrap();
    assert!(sent.ends_with(BYE));
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
    assert!(matches!(
        pm.request_lease("job-8", Duration::from_millis(10)),
        Err(LeaseError::Timeout { .. })
    ));
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

#[derive(Clone, Default)]
struct FailingLog {
    fail_on: Arc<Mutex<Vec<LeaseEvent>>>,
}

impl LeaseLog for FailingLog {
    fn append(&mut self, event: LeaseEvent, _job_id: &str) -> std::io::Result<()> {
        if self.fail_on.lock().unwrap().contains(&event) {
            Err(std::io::Error::other("injected journal failure"))
        } else {
            Ok(())
        }
    }
}

fn failing_manager(max: usize) -> (PortManager<SimTransport>, FailingLog) {
    let log = FailingLog::default();
    let pm = PortManager::new(
        SimTransport::new(SimPbx::new(Default::default(), "1234")),
        log.clone(),
        max,
    );
    (pm, log)
}

fn assert_port_restored(pm: &PortManager<SimTransport>, log: &FailingLog) {
    log.fail_on.lock().unwrap().clear();
    assert_eq!(pm.mode(), PortMode::Smdr);
    assert_eq!(pm.holder(), None);
    pm.request_lease("after", Duration::from_millis(50))
        .unwrap()
        .release()
        .unwrap();
}

#[test]
fn a_granted_journal_failure_fails_closed_and_restores_the_port() {
    for event in [LeaseEvent::Granted, LeaseEvent::ReaderPaused] {
        let (pm, log) = failing_manager(1);
        log.fail_on.lock().unwrap().push(event);
        assert!(matches!(
            pm.request_lease("job-1", Duration::from_millis(50)),
            Err(LeaseError::Journal(_))
        ));
        assert_port_restored(&pm, &log);
    }
}

#[test]
fn a_refusal_journal_failure_keeps_the_typed_timeout() {
    let (pm, log) = failing_manager(1);
    let held = pm
        .request_lease("job-1", Duration::from_millis(50))
        .unwrap();
    log.fail_on.lock().unwrap().push(LeaseEvent::TimedOut);
    assert!(matches!(
        pm.request_lease("job-2", Duration::from_millis(10)),
        Err(LeaseError::Timeout { .. })
    ));
    held.release().unwrap();
    assert_port_restored(&pm, &log);
}

#[test]
fn a_refusal_journal_failure_keeps_the_typed_queue_full() {
    let (pm, log) = failing_manager(0);
    let held = pm
        .request_lease("job-1", Duration::from_millis(50))
        .unwrap();
    log.fail_on.lock().unwrap().push(LeaseEvent::Refused);
    assert!(matches!(
        pm.request_lease("job-2", Duration::from_millis(10)),
        Err(LeaseError::QueueFull { max: 0 })
    ));
    held.release().unwrap();
    assert_port_restored(&pm, &log);
}

#[test]
fn a_timeout_racing_a_release_never_loses_the_port() {
    let (pm, log) = failing_manager(1);
    let pm = Arc::new(pm);
    for i in 0..200 {
        let held = pm
            .request_lease("holder", Duration::from_millis(50))
            .unwrap();
        let waiter = {
            let pm = Arc::clone(&pm);
            std::thread::spawn(move || {
                pm.request_lease("racer", Duration::from_millis(1))
                    .map(|l| l.release())
            })
        };
        if i % 2 == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        held.release().unwrap();
        let _racer_may_be_granted_or_time_out = waiter.join().unwrap();
        assert_eq!(pm.mode(), PortMode::Smdr, "iteration {i}");
    }
    assert_port_restored(&pm, &log);
}

#[test]
fn a_lease_request_is_not_held_up_by_a_long_smdr_read() {
    let dir = tempfile::tempdir().unwrap();
    let pm = Arc::new(manager(&dir, 1));
    let mut handle = pm.smdr_handle();
    let _warm_up_read_may_return_sim_banner_bytes = handle.recv(100);
    let reader = std::thread::spawn(move || handle.recv(5_000));
    std::thread::sleep(Duration::from_millis(20));
    let started = std::time::Instant::now();
    let lease = pm.request_lease("job-1", Duration::from_secs(1)).unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "{:?}",
        started.elapsed()
    );
    lease.release().unwrap();
    let _reader_outcome_is_not_what_this_test_measures = reader.join().unwrap();
}

#[test]
fn release_after_the_password_but_before_ecs_of_sends_no_bye_and_drops_dtr() {
    let dir = tempfile::tempdir().unwrap();
    let pm = manager(&dir, 1);
    let mut lease = pm
        .request_lease("job-1", Duration::from_millis(50))
        .unwrap();
    lease.send(b"\r\n").unwrap();
    let signon = kxtd1232::SignOn::default();
    read_until(&mut lease, signon.password_prompt.as_bytes());
    lease.send(b"1234\r").unwrap();
    read_until(&mut lease, signon.mode_start.as_bytes());
    assert_eq!(lease.session_mode(), SessionMode::SignedOut);
    lease.release().unwrap();
    assert_eq!(pm.mode(), PortMode::Smdr);
    let sent = pm.inspect_transport(|t| t.sent.clone()).unwrap();
    assert!(sent.ends_with(b"1234\r"), "{sent:?}");
    assert_eq!(position(&sent, BYE), None);
    assert_eq!(position(&sent, &END_BINARY), None);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortEvent {
    RecvStart,
    RecvEnd,
    Send,
    DropDtr,
}

struct TimedPort {
    log: Arc<Mutex<Vec<PortEvent>>>,
}

impl TimedPort {
    fn push(&self, e: PortEvent) {
        self.log.lock().unwrap().push(e);
    }
}

impl Transport for TimedPort {
    fn send(&mut self, _data: &[u8]) -> Result<(), kxtd1232::TransportError> {
        self.push(PortEvent::Send);
        Ok(())
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, kxtd1232::TransportError> {
        self.push(PortEvent::RecvStart);
        std::thread::sleep(Duration::from_millis(timeout_ms));
        self.push(PortEvent::RecvEnd);
        Err(kxtd1232::TransportError::Timeout)
    }

    fn now_ms(&mut self) -> u64 {
        0
    }
}

impl kxprovd::port::PortRelease for TimedPort {
    fn drop_dtr(&mut self) -> Result<(), kxprovd::port::DtrError> {
        self.push(PortEvent::DropDtr);
        Ok(())
    }
}

#[test]
fn an_smdr_read_slice_ends_before_any_programming_send() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let pm = PortManager::new(
        TimedPort {
            log: Arc::clone(&log),
        },
        LeaseJournal::new(dir.path().join("lease.jsonl")),
        1,
    );
    let mut smdr = pm.smdr_handle();
    let reader = std::thread::spawn(move || {
        for _ in 0..6 {
            assert!(smdr.recv(200).is_err(), "TimedPort never yields bytes");
        }
    });
    while !log.lock().unwrap().contains(&PortEvent::RecvStart) {
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut lease = pm.request_lease("job-1", Duration::from_secs(2)).unwrap();
    lease.send(b"X").unwrap();
    lease.release().unwrap();
    reader.join().unwrap();
    let log = log.lock().unwrap().clone();
    let send_at = log.iter().position(|e| *e == PortEvent::Send).unwrap();
    let mut open_slice = false;
    for e in &log[..send_at] {
        match e {
            PortEvent::RecvStart => open_slice = true,
            PortEvent::RecvEnd => open_slice = false,
            _ => {}
        }
    }
    assert!(
        !open_slice,
        "send landed inside an SMDR read slice: {log:?}"
    );
    let dtr_at = log.iter().position(|e| *e == PortEvent::DropDtr).unwrap();
    assert!(
        log[dtr_at..].contains(&PortEvent::RecvStart),
        "SMDR reads did not resume after release: {log:?}"
    );
}
