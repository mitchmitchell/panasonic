//! Whole-attempt read retry against the simulator (read-path spec v1 §6, issue #71).

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::attempts::{read_tables, Disposition, BACKOFF_MS, MAX_ATTEMPTS};
use kxtd1232::client::{Transport, TransportError};
use kxtd1232::frame::Access;
use kxtd1232::{Client, Timing};
use kxtd1232_sim::{Fault, SimPbx, SimTransport, PLACEHOLDER_PASSWORD};

/// The simulator with a DTR line: a DTR cycle drops the session and the PBX greets
/// again, as the unit does (serial-signon.md), so each attempt can sign on fresh.
struct DtrSim(SimTransport);

impl Transport for DtrSim {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.0.send(data)
    }
    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        self.0.recv(timeout_ms)
    }
    fn now_ms(&mut self) -> u64 {
        self.0.now_ms()
    }
    fn cycle_dtr(&mut self) -> Result<bool, TransportError> {
        self.0.reconnect();
        Ok(false)
    }
}

const TABLES: [u8; 2] = [0x24, 0x25];

fn client() -> Client<DtrSim> {
    Client::with(
        DtrSim(SimTransport::new(SimPbx::default())),
        Access::ReadOnly,
        Timing::default(),
    )
}

fn expected_tables() -> Vec<Vec<u8>> {
    let mut c = client();
    c.login(PLACEHOLDER_PASSWORD).unwrap();
    TABLES.iter().map(|&t| c.read_table(t).unwrap()).collect()
}

fn write_commands(c: &Client<DtrSim>) -> usize {
    c.transport()
        .0
        .sim()
        .commands
        .iter()
        .filter(|&&b| b == 0x00)
        .count()
}

#[test]
fn nak_then_success_reads_every_table_on_attempt_two() {
    let mut c = client();
    c.transport_mut().0.sim_mut().inject(Fault::Nak);
    let mut slept = Vec::new();
    let ok = read_tables(&mut c, PLACEHOLDER_PASSWORD, &TABLES, &mut |ms| {
        slept.push(ms)
    })
    .unwrap();
    assert_eq!(slept, vec![BACKOFF_MS[0]]);
    assert_eq!(ok.attempts.len(), 2);
    assert_eq!(
        ok.attempts[0].failure,
        Some((Disposition::Transient, "Nak"))
    );
    assert_eq!(ok.attempts[0].table, Some(0x24));
    assert_eq!(ok.attempts[0].release_error, None);
    assert_eq!(ok.attempts[1].failure, None);
    assert_eq!(ok.attempts[1].backoff_ms_before, BACKOFF_MS[0]);
    let got: Vec<Vec<u8>> = TABLES.iter().map(|t| ok.tables[t].clone()).collect();
    assert_eq!(got, expected_tables());
    assert_eq!(write_commands(&c), 0);
}

/// The simulator's NAK fault hits the next request of any kind, so the end-binary of
/// each failed attempt's release takes one too: five NAKs fail three reads and two
/// releases.
#[test]
fn three_transient_failures_surface_the_error() {
    let mut c = client();
    for _ in 0..(2 * MAX_ATTEMPTS - 1) {
        c.transport_mut().0.sim_mut().inject(Fault::Nak);
    }
    let mut slept = Vec::new();
    let err = read_tables(&mut c, PLACEHOLDER_PASSWORD, &TABLES, &mut |ms| {
        slept.push(ms)
    })
    .unwrap_err();
    assert_eq!(slept, BACKOFF_MS.to_vec());
    assert_eq!(err.attempts.len(), MAX_ATTEMPTS as usize);
    assert_eq!(err.disposition, Disposition::Transient);
    assert!(matches!(err.error, kxtd1232::Error::Nak { code: 0x02, .. }));
    assert!(err.tables.is_empty());
    let releases: Vec<_> = err.attempts.iter().map(|a| a.release_error).collect();
    assert_eq!(
        releases,
        vec![Some("UnexpectedReply"), Some("UnexpectedReply"), None]
    );
    assert_eq!(write_commands(&c), 0);
}

#[test]
fn wrong_password_is_definitive_and_sent_once() {
    let mut c = client();
    let mut slept = Vec::new();
    let err = read_tables(&mut c, "9999", &TABLES, &mut |ms| slept.push(ms)).unwrap_err();
    assert!(slept.is_empty());
    assert_eq!(err.attempts.len(), 1);
    assert_eq!(err.disposition, Disposition::Definitive);
    assert!(matches!(err.error, kxtd1232::Error::Login(_)));
    let sent = String::from_utf8_lossy(&c.transport().0.sent).into_owned();
    assert_eq!(sent.matches("9999").count(), 1, "password sent once");
    assert!(!sent.contains("BYE"), "no BYE before an EIA session");
}

#[test]
fn refused_in_range_read_is_definitive() {
    let mut c = client();
    c.transport_mut().0.sim_mut().inject(Fault::ReadRefused);
    let mut slept = Vec::new();
    let err = read_tables(&mut c, PLACEHOLDER_PASSWORD, &TABLES, &mut |ms| {
        slept.push(ms)
    })
    .unwrap_err();
    assert!(slept.is_empty());
    assert_eq!(err.attempts.len(), 1);
    assert_eq!(err.disposition, Disposition::Definitive);
    assert_eq!(err.attempts[0].table, Some(0x24));
}

#[test]
fn failed_attempt_in_binary_mode_ends_binary_before_the_next_sign_on() {
    let mut c = client();
    c.transport_mut().0.sim_mut().inject(Fault::Nak);
    read_tables(&mut c, PLACEHOLDER_PASSWORD, &TABLES, &mut |_| {}).unwrap();
    let sent = String::from_utf8_lossy(&c.transport().0.sent).into_owned();
    assert_eq!(
        sent.matches("BYE").count(),
        1,
        "one release after attempt 1"
    );
    assert_eq!(
        sent.matches(PLACEHOLDER_PASSWORD).count(),
        2,
        "one sign-on per attempt"
    );
}
