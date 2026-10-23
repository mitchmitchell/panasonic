//! Milestone A2 fault-injection catalog: every hook in [`kxtd1232_sim::Fault`] is exercised
//! against the guarded client (no resend on writes).

#![allow(clippy::unwrap_used)]

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

fn cid_block(c: &mut Client<SimTransport>) -> (Vec<u8>, Vec<u8>) {
    let base = c.read(0x24, 0, 0, 75).unwrap();
    let mut new = base.clone();
    new[6..12].copy_from_slice(&kxtd1232::fields::encode_cid_number("5550199").unwrap());
    (base, new)
}

fn write_count(c: &Client<SimTransport>) -> usize {
    c.transport()
        .sim
        .commands
        .iter()
        .filter(|&&b| b == 0x00)
        .count()
}

#[test]
fn test_a2_busy_run_on_read() {
    let mut c = client();
    c.transport_mut().sim.inject(Fault::Busy { frames: 8 });
    assert!(c.read(0x24, 0, 0, 3).is_ok());
}

#[test]
fn test_a2_nak_on_read() {
    let mut c = client();
    c.transport_mut().sim.inject(Fault::Nak);
    assert!(matches!(
        c.read(0x24, 0, 0, 3),
        Err(Error::Nak { code: 0x02, .. })
    ));
}

#[test]
fn test_a2_unacked_applied_and_dropped() {
    for (fault, outcome) in [
        (Fault::NoAckApplied, VerifyOutcome::Applied),
        (Fault::NoAckDropped, VerifyOutcome::NotApplied),
    ] {
        let mut c = client();
        let (base, new) = cid_block(&mut c);
        c.transport_mut().sim.inject(fault);
        let e = c.write(0x24, 0, 0, &new).unwrap_err();
        assert!(matches!(
            e,
            Error::Unacked(ref u) if u.reason == UnackedReason::Timeout
        ));
        assert_eq!(c.verify_block(0x24, 0, 0, &new, &base), Ok(outcome));
        assert_eq!(write_count(&c), 1);
    }
}

#[test]
fn test_a2_late_ack_garbled_stale() {
    let mut c = client();
    let (base, new) = cid_block(&mut c);
    c.transport_mut()
        .sim
        .inject(Fault::LateAck { delay_ms: 2_100 });
    assert!(matches!(c.write(0x24, 0, 0, &new), Err(Error::Unacked(_))));
    assert_eq!(
        c.verify_block(0x24, 0, 0, &new, &base),
        Ok(VerifyOutcome::Applied)
    );

    let mut c = client();
    let (base, new) = cid_block(&mut c);
    c.transport_mut().sim.inject(Fault::GarbledAck);
    let e = c.write(0x24, 0, 0, &new).unwrap_err();
    assert!(matches!(
        e,
        Error::Unacked(ref u) if matches!(u.reason, UnackedReason::Garbled(_))
    ));
    assert_eq!(
        c.verify_block(0x24, 0, 0, &new, &base),
        Ok(VerifyOutcome::Applied)
    );

    let mut c = client();
    let (base, new) = cid_block(&mut c);
    c.transport_mut().sim.inject(Fault::StaleReply);
    let e = c.write(0x24, 0, 0, &new).unwrap_err();
    assert!(matches!(
        e,
        Error::Unacked(ref u)
            if u.reason == UnackedReason::MismatchedReply { got: 0x01 }
    ));
    assert_eq!(
        c.verify_block(0x24, 0, 0, &new, &base),
        Ok(VerifyOutcome::Applied)
    );
}

#[test]
fn test_a2_silent_write_and_link_drop() {
    let mut c = client();
    let base = c.read(0x25, 0, 0, 80).unwrap();
    let mut new = base.clone();
    new[0] = b'S';
    c.transport_mut().sim.inject(Fault::SilentWrite);
    c.write(0x25, 0, 0, &new).unwrap();
    assert_eq!(c.read(0x25, 0, 0, 80).unwrap(), base);

    let mut c = client();
    let (base, new) = cid_block(&mut c);
    c.transport_mut()
        .sim
        .inject(Fault::LinkDropMidChunk { partial_len: 2 });
    assert!(matches!(c.write(0x24, 0, 0, &new), Err(Error::LinkDown(_))));
    assert_eq!(c.state(), &SessionState::Binary);
    c.transport_mut().clear_link_down();
    assert_eq!(
        c.verify_block(0x24, 0, 0, &new, &base),
        Ok(VerifyOutcome::Applied)
    );
}
