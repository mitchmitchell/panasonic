//! The two mandatory rules from Architect's #1 review (design v2.2 §6, §9b):
//! (a) drain-until-quiet before the verify re-read, with a late-ack test;
//! (b) hold end_binary until verify and any rollback finish after an unacked write or a
//!     busy timeout.

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::frame::Access;
use kxtd1232::{Client, Error, SessionState, Timing, VerifyOutcome};
use kxtd1232_sim::{Fault, SimConfig, SimPbx, SimTransport, PLACEHOLDER_PASSWORD};

fn frames_over_busy_limit() -> u32 {
    let limit = Timing::default().busy_limit_ms;
    let iv = SimConfig::default().busy_lockup_interval_ms;
    u32::try_from(limit / iv + 2).unwrap_or(u32::MAX)
}

const ACK: [u8; 4] = [0x03, 0x00, 0x00, 0x03];

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
    let base = c.read(0x24, 0, 0, 75).unwrap();
    let mut new = base.clone();
    new[6..12].copy_from_slice(&kxtd1232::fields::encode_cid_number("5550100").unwrap());
    (base, new)
}

fn end_binary_sent(c: &Client<SimTransport>) -> bool {
    c.transport().sim().commands.contains(&0x0B)
}

#[test]
fn test_late_ack_drained_before_verify_reread() {
    let mut c = client();
    let (base, new) = block(&mut c);
    // Ack arrives 2.3 s after the write: after the 2 s ack timeout, inside the 0.5 s
    // quiet window that drain uses.
    c.transport_mut()
        .sim_mut()
        .inject(Fault::LateAck { delay_ms: 2_300 });
    let t0 = c.transport().now();
    assert!(matches!(c.write(0x24, 0, 0, &new), Err(Error::Unacked(_))));
    assert_eq!(
        c.verify_block(0x24, 0, 0, &new, &base),
        Ok(VerifyOutcome::Applied)
    );
    let d = c.drained();
    assert_eq!(d.len(), 1, "late ack consumed by the drain and logged");
    assert_eq!(d[0].bytes, ACK);
    assert!(d[0].at_ms >= t0 + 2_300);
    // The re-read went out only after the line was quiet for the window.
    assert!(c.transport().now() >= t0 + 2_300 + 500);
    assert_eq!(c.state(), &SessionState::Binary);
}

#[test]
fn test_drain_waits_out_busy_then_rereads() {
    let mut c = client();
    let (base, new) = block(&mut c);
    c.transport_mut().sim_mut().inject(Fault::Busy {
        frames: frames_over_busy_limit(),
    });
    assert!(matches!(c.write(0x24, 0, 0, &new), Err(Error::Unacked(_))));
    assert_eq!(
        c.verify_block(0x24, 0, 0, &new, &base),
        Ok(VerifyOutcome::Applied)
    );
    let all: Vec<u8> = c.drained().iter().flat_map(|d| d.bytes.clone()).collect();
    assert!(
        all.ends_with(&ACK),
        "the write's ack was drained, not matched to the re-read"
    );
}

#[test]
fn test_end_binary_held_after_unacked_write() {
    let mut c = client();
    let (base, new) = block(&mut c);
    c.transport_mut().sim_mut().inject(Fault::NoAckDropped);
    assert!(matches!(c.write(0x24, 0, 0, &new), Err(Error::Unacked(_))));
    assert_eq!(c.end_binary(), Err(Error::EndBinaryHeld));
    assert!(!end_binary_sent(&c), "nothing sent while held");
    assert_eq!(
        c.verify_block(0x24, 0, 0, &new, &base),
        Ok(VerifyOutcome::NotApplied)
    );
    c.end_binary().unwrap();
    assert!(end_binary_sent(&c));
}

#[test]
fn test_end_binary_held_after_busy_timeout_until_rollback() {
    let mut c = client();
    let (base, new) = block(&mut c);
    c.transport_mut().sim_mut().inject(Fault::Busy {
        frames: frames_over_busy_limit(),
    });
    assert!(matches!(c.write(0x24, 0, 0, &new), Err(Error::Unacked(_))));
    assert_eq!(c.end_binary(), Err(Error::EndBinaryHeld));
    // Something else changed the block meanwhile: verify says neither.
    c.transport_mut().sim_mut().db.get_mut(&0x24).unwrap()[0] ^= 0x01;
    assert_eq!(
        c.verify_block(0x24, 0, 0, &new, &base),
        Ok(VerifyOutcome::Neither)
    );
    assert!(matches!(c.state(), SessionState::NeedsRollback(_)));
    assert_eq!(c.end_binary(), Err(Error::EndBinaryHeld));
    assert!(!end_binary_sent(&c));
    c.rollback_block(0x24, 0, 0, &base).unwrap();
    assert_eq!(c.transport().sim().db[&0x24][..150], base[..]);
    assert_eq!(c.state(), &SessionState::Binary);
    c.end_binary().unwrap();
    assert!(end_binary_sent(&c));
}

#[test]
fn test_failed_rollback_locks_and_allows_end() {
    let mut c = client();
    let (base, new) = block(&mut c);
    c.transport_mut().sim_mut().inject(Fault::NoAckApplied);
    assert!(matches!(c.write(0x24, 0, 0, &new), Err(Error::Unacked(_))));
    c.transport_mut().sim_mut().db.get_mut(&0x24).unwrap()[0] ^= 0x01;
    assert_eq!(
        c.verify_block(0x24, 0, 0, &new, &base),
        Ok(VerifyOutcome::Neither)
    );
    c.transport_mut().sim_mut().inject(Fault::SilentWrite);
    assert_eq!(c.rollback_block(0x24, 0, 0, &base), Err(Error::Locked));
    assert_eq!(c.state(), &SessionState::Locked);
    assert_eq!(c.write(0x24, 0, 0, &base), Err(Error::Locked));
    c.end_binary().unwrap();
}
