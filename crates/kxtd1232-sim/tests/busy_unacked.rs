//! Busy runs, unacked writes, and Claude's review fixes on #1 (ported from
//! #1 tests/sim/test_busy_unacked.py).

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::error::UnackedReason;
use kxtd1232::frame::Access;
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

fn block(c: &mut Client<SimTransport>) -> (Vec<u8>, Vec<u8>) {
    let base = c.read(0x25, 10, 0, 80).unwrap();
    let mut new = base.clone();
    new[0] = b'Z';
    (base, new)
}

fn writes(c: &Client<SimTransport>) -> usize {
    c.transport()
        .sim()
        .commands
        .iter()
        .filter(|&&b| b == 0x00)
        .count()
}

#[test]
fn test_busy_past_bound_raises() {
    let mut c = client();
    c.transport_mut()
        .sim_mut()
        .inject(Fault::Busy { frames: 200 });
    assert_eq!(c.read(0x24, 0, 0, 3), Err(Error::BusyTimeout));
}

#[test]
fn test_short_busy_ok() {
    let mut c = client();
    c.transport_mut()
        .sim_mut()
        .inject(Fault::Busy { frames: 55 }); // ~7 s at 128 ms
    assert!(c.read(0x24, 0, 0, 3).is_ok());
}

#[test]
fn test_busy_past_bound_on_write_is_unacked_then_verify() {
    let mut c = client();
    let (base, new) = block(&mut c);
    c.transport_mut()
        .sim_mut()
        .inject(Fault::Busy { frames: 100 });
    let e = c.write(0x25, 10, 0, &new).unwrap_err();
    assert!(matches!(e, Error::Unacked(ref u) if u.reason == UnackedReason::BusyTimeout));
    assert_eq!(
        c.verify_block(0x25, 10, 0, &new, &base),
        Ok(VerifyOutcome::Applied)
    );
    assert_eq!(writes(&c), 1, "never resent");
}

#[test]
fn test_unacked_write_verified_by_reread_not_resent() {
    for (fault, outcome) in [
        (Fault::NoAckApplied, VerifyOutcome::Applied),
        (Fault::NoAckDropped, VerifyOutcome::NotApplied),
    ] {
        let mut c = client();
        let (base, new) = block(&mut c);
        c.transport_mut().sim_mut().inject(fault);
        let e = c.write(0x25, 10, 0, &new).unwrap_err();
        assert!(matches!(e, Error::Unacked(ref u) if u.reason == UnackedReason::Timeout));
        assert_eq!(c.verify_block(0x25, 10, 0, &new, &base), Ok(outcome));
        assert_eq!(writes(&c), 1);
        assert_eq!(c.state(), &SessionState::Binary);
    }
}

#[test]
fn test_write_fault_survives_intervening_reads() {
    let mut c = client();
    let (_base, new) = block(&mut c);
    c.transport_mut().sim_mut().inject(Fault::NoAckDropped);
    c.read(0x24, 0, 0, 3).unwrap();
    c.read(0x24, 0, 0, 3).unwrap();
    assert_eq!(c.transport().sim().pending_faults(), 1);
    assert!(matches!(c.write(0x25, 10, 0, &new), Err(Error::Unacked(_))));
}

#[test]
fn test_busy_forever_then_verify_block_starts_clean() {
    let mut c = client();
    let (base, new) = block(&mut c);
    c.transport_mut()
        .sim_mut()
        .inject(Fault::Busy { frames: 120 });
    assert!(matches!(c.write(0x25, 10, 0, &new), Err(Error::Unacked(_))));
    assert_eq!(
        c.verify_block(0x25, 10, 0, &new, &base),
        Ok(VerifyOutcome::Applied)
    );
    assert!(
        !c.drained().is_empty(),
        "leftover busy frames were drained, not parsed"
    );
}

#[test]
fn test_busy_never_ends_locks_on_verify() {
    let mut c = client();
    let (base, new) = block(&mut c);
    c.transport_mut()
        .sim_mut()
        .inject(Fault::Busy { frames: 400 }); // ~51 s, past any drain bound
    assert!(matches!(c.write(0x25, 10, 0, &new), Err(Error::Unacked(_))));
    assert_eq!(
        c.verify_block(0x25, 10, 0, &new, &base),
        Err(Error::LineNotQuiet)
    );
    assert_eq!(c.state(), &SessionState::Locked);
}

// --- Claude's review on #1 ----------------------------------------------------------

#[test]
fn test_garbled_write_ack_counts_as_unacked() {
    let mut c = client();
    let (base, new) = block(&mut c);
    c.transport_mut().sim_mut().inject(Fault::GarbledAck);
    let e = c.write(0x25, 10, 0, &new).unwrap_err();
    assert!(matches!(e, Error::Unacked(ref u) if matches!(u.reason, UnackedReason::Garbled(_))));
    assert!(matches!(c.state(), SessionState::AwaitingVerify(_)));
    assert_eq!(
        c.write(0x25, 10, 0, &new),
        Err(Error::VerifyPending),
        "no blind resend"
    );
    assert_eq!(
        c.verify_block(0x25, 10, 0, &new, &base),
        Ok(VerifyOutcome::Applied)
    );
    assert_eq!(writes(&c), 1);
}

#[test]
fn test_reply_must_match_request_cmd() {
    let mut c = client();
    let (base, new) = block(&mut c);
    c.transport_mut().sim_mut().inject(Fault::StaleReply);
    let e = c.write(0x25, 10, 0, &new).unwrap_err();
    assert!(matches!(
        e,
        Error::Unacked(ref u) if u.reason == UnackedReason::MismatchedReply { got: 0x01 }
    ));
    assert_eq!(
        c.verify_block(0x25, 10, 0, &new, &base),
        Ok(VerifyOutcome::Applied)
    );
}

#[test]
fn test_stray_write_ack_is_not_a_read_reply() {
    // A late write ack is consumed by the resync after the unacked write (or by the
    // pre-send flush), never returned as read data.
    let mut c = client();
    let (_base, new) = block(&mut c);
    c.transport_mut()
        .sim_mut()
        .inject(Fault::LateAck { delay_ms: 2_100 });
    assert!(matches!(c.write(0x25, 10, 0, &new), Err(Error::Unacked(_))));
    assert!(c
        .drained()
        .iter()
        .any(|d| d.bytes == [0x03, 0x00, 0x00, 0x03]));
    c.transport_mut().sim_mut().latency_ms = 500;
    assert_eq!(c.read(0x25, 10, 0, 80), Ok(new));
}
