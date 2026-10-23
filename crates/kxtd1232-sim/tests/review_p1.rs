//! Codex P1s and Claude should-fixes on #2 (round 2).

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::error::{Op, PlanError};
use kxtd1232::frame::Access;
use kxtd1232::{
    build_plan, Client, Error, Granularity, SessionState, Timing, Transport, TransportError,
    VerifyOutcome,
};
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

fn db(c: &Client<SimTransport>, t: u8, off: usize, n: usize) -> Vec<u8> {
    c.transport().sim().db[&t][off..off + n].to_vec()
}

/// Unacked (but applied) 16-byte write to 0x25 record `r`; returns (base, new).
fn pending(c: &mut Client<SimTransport>, r: u16) -> (Vec<u8>, Vec<u8>) {
    let base = db(c, 0x25, r as usize * 16, 16);
    let new = vec![0x41u8 + r as u8; 16];
    c.transport_mut().sim_mut().inject(Fault::NoAckApplied);
    assert!(matches!(c.write(0x25, r, 0, &new), Err(Error::Unacked(_))));
    (base, new)
}

#[test]
fn test_verify_prefix_does_not_clear_awaiting_verify() {
    let mut c = client();
    let (base, new) = pending(&mut c, 1);
    assert_eq!(
        c.verify_block(0x25, 1, 0, &new[..2], &base[..2]),
        Err(Error::NotPendingBlock)
    );
    assert!(matches!(c.state(), SessionState::AwaitingVerify(_)));
    assert_eq!(c.end_binary(), Err(Error::EndBinaryHeld));
    // Same length, different bytes: also refused.
    let mut other = new.clone();
    other[15] ^= 1;
    assert_eq!(
        c.verify_block(0x25, 1, 0, &other, &base),
        Err(Error::NotPendingBlock)
    );
    assert_eq!(
        c.verify_block(0x25, 1, 0, &new, &base),
        Ok(VerifyOutcome::Applied)
    );
    assert_eq!(c.state(), &SessionState::Binary);
}

#[test]
fn test_rollback_refuses_other_blocks() {
    let mut c = client();
    let (base, _new) = pending(&mut c, 2);
    let writes = c.transport().sim().writes.len();
    let other = db(&c, 0x25, 3 * 16, 16);
    assert_eq!(
        c.rollback_block(0x25, 3, 0, &other),
        Err(Error::NotPendingBlock)
    );
    assert_eq!(
        c.rollback_block(0x25, 2, 0, &base[..8]),
        Err(Error::NotPendingBlock)
    );
    assert_eq!(
        c.rollback_block(0x24, 2, 0, &base),
        Err(Error::NotPendingBlock)
    );
    assert_eq!(c.transport().sim().writes.len(), writes, "nothing written");
    assert!(matches!(c.state(), SessionState::AwaitingVerify(_)));
    assert_eq!(c.rollback_block(0x25, 2, 0, &base), Ok(()));
    assert_eq!(db(&c, 0x25, 32, 16), base);
}

#[test]
fn test_rollback_refuses_other_block_from_needs_rollback() {
    let mut c = client();
    let (base, new) = pending(&mut c, 4);
    // Make the PBX hold something that is neither plan nor base.
    c.transport_mut().sim_mut().db.get_mut(&0x25).unwrap()[64] = 0x7E;
    assert_eq!(
        c.verify_block(0x25, 4, 0, &new, &base),
        Ok(VerifyOutcome::Neither)
    );
    assert!(matches!(c.state(), SessionState::NeedsRollback(_)));
    let b5 = db(&c, 0x25, 80, 16);
    assert_eq!(
        c.rollback_block(0x25, 5, 0, &b5),
        Err(Error::NotPendingBlock)
    );
    assert!(matches!(c.state(), SessionState::NeedsRollback(_)));
    assert_eq!(c.rollback_block(0x25, 4, 0, &base), Ok(()));
}

#[test]
fn test_end_binary_sends_bye_and_waits_for_ok() {
    let mut c = client();
    assert_eq!(c.end_binary(), Ok(()));
    assert_eq!(c.state(), &SessionState::Closed);
    let sent = &c.transport().sent;
    let eb = sent
        .windows(3)
        .position(|w| w == [0x02, 0x0B, 0x0D])
        .unwrap();
    assert!(
        sent[eb..].ends_with(b"BYE\r\n"),
        "BYE follows the end-binary frame"
    );
}

#[test]
fn test_end_binary_unconfirmed_bye_is_not_closed() {
    let mut c = client();
    c.transport_mut().sim_mut().silent_bye = true;
    assert_eq!(
        c.end_binary(),
        Err(Error::ByeNotConfirmed("no reply".into()))
    );
    assert_ne!(c.state(), &SessionState::Closed);
}

#[test]
fn test_bad_state_is_typed() {
    let mut c = Client::with(
        SimTransport::new(SimPbx::default()),
        Access::ReadWrite,
        Timing::default(),
    );
    assert_eq!(
        c.read(0x24, 0, 0, 1),
        Err(Error::BadState {
            op: Op::Request,
            state: SessionState::Text
        })
    );
    assert_eq!(
        c.write(0x25, 0, 0, &[0, 0]),
        Err(Error::BadState {
            op: Op::Write,
            state: SessionState::Text
        })
    );
    c.login(PLACEHOLDER_PASSWORD).unwrap();
    assert_eq!(
        c.rollback_block(0x25, 0, 0, &[0; 16]),
        Err(Error::BadState {
            op: Op::Rollback,
            state: SessionState::Binary
        })
    );
}

#[test]
fn test_plan_errors_are_typed() {
    assert_eq!(
        build_plan(0x25, &[0u8; 3], &[], Granularity::Chunk).unwrap_err(),
        Error::Plan(PlanError::BaseSize {
            table: 0x25,
            expected: SimPbx::default().db[&0x25].len(),
            got: 3
        })
    );
}

/// Violates the trait: returns Ok(empty) forever.
struct EmptyReads(u64);

impl Transport for EmptyReads {
    fn send(&mut self, _: &[u8]) -> Result<(), TransportError> {
        Ok(())
    }
    fn recv(&mut self, _: u64) -> Result<Vec<u8>, TransportError> {
        self.0 += 1;
        assert!(self.0 < 1_000, "client spun on empty reads");
        Ok(Vec::new())
    }
    fn now_ms(&mut self) -> u64 {
        0
    }
}

#[test]
fn test_empty_recv_is_link_down_not_a_spin() {
    let mut c = Client::new(EmptyReads(0));
    assert!(matches!(
        c.login(PLACEHOLDER_PASSWORD),
        Err(Error::LinkDown(_))
    ));
}
