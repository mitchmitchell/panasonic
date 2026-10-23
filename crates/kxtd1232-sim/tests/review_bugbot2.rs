//! Bugbot round 3 on #2: link loss in drains, rollback state, pending BYE.

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::frame::{Access, BUSY_FRAME};
use kxtd1232::{Client, Error, SessionState, Timing, VerifyOutcome};
use kxtd1232_sim::{Fault, SimPbx, SimTransport, PLACEHOLDER_PASSWORD};

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
    c.transport().sim.db[&0x25][r * 16..r * 16 + 16].to_vec()
}

fn pending(c: &mut Client<SimTransport>, r: u16) -> (Vec<u8>, Vec<u8>) {
    let base = db(c, r as usize);
    let new = vec![0x50u8 + r as u8; 16];
    c.transport_mut().sim.inject(Fault::NoAckApplied);
    assert!(matches!(c.write(0x25, r, 0, &new), Err(Error::Unacked(_))));
    (base, new)
}

fn relogin(c: &mut Client<SimTransport>) {
    c.transport_mut().reconnect();
    c.login(PLACEHOLDER_PASSWORD).unwrap();
}

#[test]
fn test_drain_link_down_saves_resume_before_disconnected() {
    let mut c = client();
    let (base, new) = pending(&mut c, 1);
    c.transport_mut().drop_link_now();
    assert!(matches!(
        c.verify_block(0x25, 1, 0, &new, &base),
        Err(Error::LinkDown(_))
    ));
    assert_eq!(c.state(), &SessionState::Disconnected);
    relogin(&mut c);
    assert!(matches!(c.state(), SessionState::AwaitingVerify(_)));
    assert_eq!(c.end_binary(), Err(Error::EndBinaryHeld));
    assert_eq!(
        c.verify_block(0x25, 1, 0, &new, &base),
        Ok(VerifyOutcome::Applied)
    );
    assert_eq!(c.end_binary(), Ok(()));
}

#[test]
fn test_rollback_presend_failure_keeps_prior_state() {
    let mut c = client();
    let (base, _new) = pending(&mut c, 4);
    let before = c.state().clone();
    for i in 0..200 {
        c.transport_mut()
            .inject_inbound_after(i * 80, BUSY_FRAME.to_vec());
    }
    let writes = c.transport().sim.writes.len();
    let e = c.rollback_block(0x25, 4, 0, &base).unwrap_err();
    assert!(matches!(e, Error::PreSend(_)), "{e:?}");
    assert_eq!(c.state(), &before, "not Locked: nothing was sent");
    assert_eq!(c.transport().sim.writes.len(), writes);
}

#[test]
fn test_rollback_presend_link_down_keeps_disconnected_and_resume() {
    let mut c = client();
    let (base, _new) = pending(&mut c, 5);
    c.transport_mut().drop_link_now();
    let e = c.rollback_block(0x25, 5, 0, &base).unwrap_err();
    assert!(matches!(e, Error::PreSend(_) | Error::LinkDown(_)), "{e:?}");
    assert_eq!(c.state(), &SessionState::Disconnected);
    relogin(&mut c);
    assert!(matches!(c.state(), SessionState::AwaitingVerify(_)));
    assert_eq!(c.end_binary(), Err(Error::EndBinaryHeld));
    assert_eq!(c.rollback_block(0x25, 5, 0, &base), Ok(()));
    assert_eq!(db(&c, 5), base);
}

#[test]
fn test_rollback_verify_link_down_keeps_disconnected_and_resume() {
    let mut c = client();
    let (base, _new) = pending(&mut c, 6);
    // The rollback write goes unacked and the link drops right after it.
    c.transport_mut().drop_link_after_write = true;
    assert!(matches!(
        c.rollback_block(0x25, 6, 0, &base),
        Err(Error::LinkDown(_))
    ));
    assert_eq!(c.state(), &SessionState::Disconnected);
    relogin(&mut c);
    assert!(matches!(c.state(), SessionState::AwaitingVerify(_)));
}

#[test]
fn test_bye_pending_persists_and_retry_resends_bye() {
    let mut c = client();
    c.transport_mut().sim.silent_bye = true;
    assert_eq!(
        c.end_binary(),
        Err(Error::ByeNotConfirmed("no reply".into()))
    );
    assert_eq!(c.state(), &SessionState::ByePending);
    assert!(matches!(c.read(0x24, 0, 0, 1), Err(Error::BadState { .. })));
    let byes = |c: &Client<SimTransport>| {
        c.transport()
            .sent
            .windows(5)
            .filter(|w| w == b"BYE\r\n")
            .count()
    };
    assert_eq!(byes(&c), 1);
    c.transport_mut().sim.silent_bye = false;
    assert_eq!(c.end_binary(), Ok(()));
    assert_eq!(byes(&c), 2, "retry re-sends BYE, not end-binary");
    assert_eq!(
        c.transport()
            .sent
            .windows(3)
            .filter(|w| w == &[0x02, 0x0B, 0x0D])
            .count(),
        1
    );
    assert_eq!(c.state(), &SessionState::Closed);
}

#[test]
fn test_second_drain_while_disconnected_keeps_resume() {
    let mut c = client();
    let (base, new) = pending(&mut c, 7);
    c.transport_mut().drop_link_now();
    assert!(c.verify_block(0x25, 7, 0, &new, &base).is_err());
    assert_eq!(c.state(), &SessionState::Disconnected);
    // A later drain on the dead link must not wipe the saved resume.
    assert!(matches!(c.drain_until_quiet(), Err(Error::LinkDown(_))));
    assert_eq!(c.state(), &SessionState::Disconnected);
    relogin(&mut c);
    assert!(matches!(c.state(), SessionState::AwaitingVerify(_)));
    assert_eq!(c.end_binary(), Err(Error::EndBinaryHeld));
}

#[test]
fn test_sim_plays_default_signon_placeholders() {
    let c = client();
    assert_eq!(c.state(), &SessionState::Binary);
    let prompt = kxtd1232::SignOn::default().password_prompt;
    assert!(kxtd1232_sim::banner().ends_with(format!("{prompt}\r\n").as_bytes()));
}
