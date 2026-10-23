//! Tester / Security Analyst: a link failure during a write's send is "not sent" only when
//! the transport proves zero bytes left the host. A partial or complete frame followed by
//! a failure resumes in AwaitingVerify after re-login.

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::frame::Access;
use kxtd1232::{Client, Error, SessionState, Timing, VerifyOutcome};
use kxtd1232_sim::{SimPbx, SimTransport, PLACEHOLDER_PASSWORD};

fn client() -> Client<SimTransport> {
    let mut c = Client::with(
        SimTransport::new(SimPbx::default()),
        Access::ReadWrite,
        Timing::default(),
    );
    c.login(PLACEHOLDER_PASSWORD).unwrap();
    c
}

fn db(c: &Client<SimTransport>, r: usize) -> Vec<u8> {
    c.transport().sim().db[&0x25][r * 16..r * 16 + 16].to_vec()
}

fn relogin(c: &mut Client<SimTransport>) {
    c.transport_mut().reconnect();
    c.login(PLACEHOLDER_PASSWORD).unwrap();
}

fn fail_after(n: usize) -> (Client<SimTransport>, Vec<u8>, Vec<u8>) {
    let mut c = client();
    let base = db(&c, 3);
    let new = vec![0x6Au8; 16];
    c.transport_mut().fail_write_send_after = Some(n);
    assert!(matches!(c.write(0x25, 3, 0, &new), Err(Error::LinkDown(_))));
    assert_eq!(c.state(), &SessionState::Disconnected);
    relogin(&mut c);
    (c, base, new)
}

#[test]
fn test_partial_frame_send_resumes_awaiting_verify() {
    let (mut c, base, new) = fail_after(5);
    assert!(
        matches!(c.state(), SessionState::AwaitingVerify(_)),
        "{:?}",
        c.state()
    );
    assert!(matches!(
        c.write(0x25, 4, 0, &[0; 16]),
        Err(Error::VerifyPending)
    ));
    let got = c.verify_block(0x25, 3, 0, &new, &base).unwrap();
    assert_eq!(got, VerifyOutcome::NotApplied);
    assert_eq!(c.state(), &SessionState::Binary);
}

#[test]
fn test_full_frame_then_send_error_resumes_awaiting_verify() {
    let (mut c, base, new) = fail_after(usize::MAX);
    assert!(
        matches!(c.state(), SessionState::AwaitingVerify(_)),
        "{:?}",
        c.state()
    );
    let got = c.verify_block(0x25, 3, 0, &new, &base).unwrap();
    assert_eq!(got, VerifyOutcome::Applied);
    assert_eq!(db(&c, 3), new);
}

#[test]
fn test_nothing_written_is_presend_and_needs_no_verify() {
    let mut c = client();
    c.transport_mut().drop_link_now();
    let e = c.write(0x25, 3, 0, &[0x6A; 16]).unwrap_err();
    assert!(matches!(e, Error::PreSend(_)), "{e:?}");
    relogin(&mut c);
    assert_eq!(c.state(), &SessionState::Binary);
}
