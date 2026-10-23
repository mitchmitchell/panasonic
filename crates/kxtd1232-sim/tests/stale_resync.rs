//! Stale frames, resync after errors, link drops and login limits (#2 review: Bugbot,
//! Tester, Architect). Same-command stale frames must never be taken as the reply.

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::error::{LoginFailure, UnackedReason};
use kxtd1232::frame::{Access, Cmd, BUSY_FRAME};
use kxtd1232::{
    Client, Error, SendError, SessionState, Timing, Transport, TransportError, VerifyOutcome,
};
use kxtd1232_sim::{reply_frame, Fault, SimPbx, SimTransport, PLACEHOLDER_PASSWORD};

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

fn db(c: &Client<SimTransport>, t: u8, off: usize, n: usize) -> Vec<u8> {
    c.transport().sim().db[&t][off..off + n].to_vec()
}

fn stale_read(n: usize) -> Vec<u8> {
    let mut b = vec![0x00];
    b.resize(1 + n, 0xEE);
    reply_frame(Cmd::Read.byte(), &b)
}

fn end_binary_sent(c: &Client<SimTransport>) -> bool {
    c.transport().sim().commands.contains(&0x0B)
}

#[test]
fn test_stale_same_cmd_read_waiting_before_send_is_discarded() {
    let mut c = client();
    c.transport_mut().inject_inbound(stale_read(6));
    assert_eq!(c.read(0x24, 0, 0, 3), Ok(db(&c, 0x24, 0, 6)));
    // No off-by-one afterwards.
    assert_eq!(c.read(0x24, 1, 0, 3), Ok(db(&c, 0x24, 6, 6)));
    assert!(c.drained().iter().any(|d| d.bytes == stale_read(6)));
}

#[test]
fn test_stale_same_cmd_read_after_send_is_extra_frame() {
    let mut c = client();
    c.transport_mut().sim_mut().inject(Fault::DuplicateReply);
    assert_eq!(c.read(0x24, 0, 0, 3), Err(Error::ExtraFrame));
    assert_eq!(c.read(0x24, 1, 0, 3), Ok(db(&c, 0x24, 6, 6)));
    assert_eq!(c.end_binary(), Ok(()));
}

#[test]
fn test_stale_write_ack_before_dropped_write_is_unacked() {
    let mut c = client();
    let p = [0x11u8; 16];
    c.transport_mut().inject_inbound(ACK.to_vec());
    c.transport_mut().sim_mut().inject(Fault::NoAckDropped);
    let e = c.write(0x25, 2, 0, &p).unwrap_err();
    assert!(matches!(e, Error::Unacked(ref u) if u.reason == UnackedReason::Timeout));
    assert_ne!(db(&c, 0x25, 32, 16), p);
    assert!(matches!(c.state(), SessionState::AwaitingVerify(_)));
    let base = db(&c, 0x25, 32, 16);
    assert_eq!(
        c.verify_block(0x25, 2, 0, &p, &base),
        Ok(VerifyOutcome::NotApplied)
    );
}

#[test]
fn test_timed_stale_ack_at_10ms_then_dropped_write_never_succeeds() {
    let mut c = client();
    let p = [0x22u8; 16];
    // The stale ack lands 10 ms from now: inside the pre-send quiet interval.
    c.transport_mut().inject_inbound_after(10, ACK.to_vec());
    c.transport_mut().sim_mut().inject(Fault::NoAckDropped);
    let t0 = c.transport().now();
    let r = c.write(0x25, 3, 0, &p);
    assert!(matches!(r, Err(Error::Unacked(_))), "{r:?}");
    let d = c.drained().iter().find(|d| d.bytes == ACK).unwrap();
    assert_eq!(
        d.at_ms,
        t0 + 10,
        "drained before the send, not taken as the ack"
    );
}

#[test]
fn test_stale_same_cmd_ack_after_send_is_unacked() {
    let mut c = client();
    c.transport_mut().sim_mut().inject(Fault::DuplicateReply);
    let e = c.write(0x25, 4, 0, &[0x33; 16]).unwrap_err();
    assert!(matches!(e, Error::Unacked(ref u) if u.reason == UnackedReason::ExtraFrame));
    assert_eq!(c.end_binary(), Err(Error::EndBinaryHeld));
}

#[test]
fn test_garbled_reply_resyncs_so_next_read_and_close_work() {
    let mut c = client();
    let mut g = reply_frame(Cmd::Read.byte(), &[0, 1, 2, 3, 4, 5, 6]);
    *g.last_mut().unwrap() ^= 0xFF;
    // After the 100 ms pre-send quiet and the post-send cutoff, before the real reply.
    let cutoff = Timing::default().reply_cutoff_ms(8);
    c.transport_mut().inject_inbound_after(100 + cutoff + 2, g);
    assert!(matches!(c.read(0x24, 0, 0, 3), Err(Error::Garbled(_))));
    assert_eq!(c.read(0x24, 0, 0, 3), Ok(db(&c, 0x24, 0, 6)));
    assert_eq!(c.end_binary(), Ok(()));
    assert_eq!(c.state(), &SessionState::Closed);
}

#[test]
fn test_late_reply_after_timeout_is_never_data() {
    let mut c = client();
    c.transport_mut().sim_mut().latency_ms = 6_000;
    assert_eq!(c.read(0x24, 0, 0, 3), Err(Error::Timeout));
    c.transport_mut().sim_mut().latency_ms = 30;
    let real = db(&c, 0x24, 6, 6);
    match c.read(0x24, 1, 0, 3) {
        Ok(d) => assert_eq!(d, real),
        Err(e) => assert_eq!(e, Error::ExtraFrame),
    }
    assert_eq!(c.read(0x24, 1, 0, 3), Ok(real));
    assert_eq!(c.end_binary(), Ok(()));
}

#[test]
fn test_busy_frame_right_after_reply_is_ignored() {
    let mut c = client();
    c.transport_mut().sim_mut().inject(Fault::BusyAfterReply);
    assert_eq!(c.read(0x24, 0, 0, 3), Ok(db(&c, 0x24, 0, 6)));
    c.transport_mut().sim_mut().inject(Fault::BusyAfterReply);
    assert_eq!(c.write(0x25, 5, 0, &[0x41; 16]), Ok(()));
}

#[test]
fn test_late_ack_after_unacked_rollback_write_is_drained() {
    let mut c = client();
    let base = db(&c, 0x25, 6 * 16, 16);
    let new = [0x5Au8; 16];
    c.transport_mut().sim_mut().inject(Fault::NoAckApplied);
    assert!(matches!(c.write(0x25, 6, 0, &new), Err(Error::Unacked(_))));
    // The rollback write's ack arrives after the 2 s ack timeout.
    c.transport_mut()
        .sim_mut()
        .inject(Fault::LateAck { delay_ms: 2_300 });
    let before = c.drained().len();
    assert_eq!(c.rollback_block(0x25, 6, 0, &base), Ok(()));
    assert!(c.drained()[before..].iter().any(|d| d.bytes == ACK));
    assert_eq!(db(&c, 0x25, 96, 16), base);
    assert_eq!(c.state(), &SessionState::Binary);
    assert_eq!(c.end_binary(), Ok(()));
}

#[test]
fn test_unacked_rollback_that_fails_verify_still_holds_close_until_drained() {
    let mut c = client();
    let new = [0x5Bu8; 16];
    let base = db(&c, 0x25, 7 * 16, 16);
    c.transport_mut().sim_mut().inject(Fault::NoAckApplied);
    assert!(c.write(0x25, 7, 0, &new).is_err());
    // Rollback write dropped and unacked: verify finds the new bytes, so LOCKED.
    c.transport_mut().sim_mut().inject(Fault::NoAckDropped);
    assert_eq!(c.rollback_block(0x25, 7, 0, &base), Err(Error::Locked));
    assert_eq!(c.state(), &SessionState::Locked);
    assert_eq!(c.end_binary(), Ok(()));
}

#[test]
fn test_link_drop_during_write_recv_disconnects_then_resumes_awaiting_verify() {
    let mut c = client();
    let base = db(&c, 0x25, 8 * 16, 16);
    let new = [0x44u8; 16];
    c.transport_mut().drop_link_after_write = true;
    let e = c.write(0x25, 8, 0, &new).unwrap_err();
    assert!(matches!(e, Error::LinkDown(_)), "{e:?}");
    assert_eq!(c.state(), &SessionState::Disconnected);
    // Nothing goes out until a fresh login.
    assert_eq!(c.end_binary(), Err(Error::SessionLost));
    assert_eq!(c.read(0x25, 8, 0, 8), Err(Error::SessionLost));
    assert_eq!(
        c.verify_block(0x25, 8, 0, &new, &base),
        Err(Error::SessionLost)
    );
    assert!(!end_binary_sent(&c));
    // Reconnect: the session resumes in AwaitingVerify, and end_binary stays held.
    c.transport_mut().reconnect();
    c.login(PLACEHOLDER_PASSWORD).unwrap();
    assert!(matches!(
        c.state(),
        SessionState::AwaitingVerify(ref u) if matches!(u.reason, UnackedReason::LinkDown(_))
    ));
    assert_eq!(c.end_binary(), Err(Error::EndBinaryHeld));
    assert_eq!(
        c.verify_block(0x25, 8, 0, &new, &base),
        Ok(VerifyOutcome::Applied)
    );
    assert_eq!(c.end_binary(), Ok(()));
}

#[test]
fn test_link_drop_during_rollback_write_resumes_awaiting_verify() {
    let mut c = client();
    let base = db(&c, 0x25, 11 * 16, 16);
    c.transport_mut().sim_mut().inject(Fault::NoAckApplied);
    assert!(c.write(0x25, 11, 0, &[0x46; 16]).is_err());
    c.transport_mut().drop_link_after_write = true;
    assert!(matches!(
        c.rollback_block(0x25, 11, 0, &base),
        Err(Error::LinkDown(_))
    ));
    assert_eq!(c.state(), &SessionState::Disconnected);
    assert_eq!(c.end_binary(), Err(Error::SessionLost));
    c.transport_mut().reconnect();
    c.login(PLACEHOLDER_PASSWORD).unwrap();
    assert!(matches!(c.state(), SessionState::AwaitingVerify(_)));
    assert_eq!(
        c.verify_block(0x25, 11, 0, &base, &base),
        Ok(VerifyOutcome::Applied)
    );
    assert_eq!(c.end_binary(), Ok(()));
}

#[test]
fn test_presend_drain_failure_is_distinct_and_sends_nothing() {
    let mut c = client();
    for i in 0..200 {
        c.transport_mut()
            .inject_inbound_after(i * 80, BUSY_FRAME.to_vec());
    }
    let writes = c.transport().sim().writes.len();
    let e = c.write(0x25, 9, 0, &[0x45; 16]).unwrap_err();
    assert_eq!(e, Error::PreSend(Box::new(Error::LineNotQuiet)));
    assert_eq!(c.transport().sim().writes.len(), writes);
    assert_eq!(c.state(), &SessionState::Binary);
}

/// Text that never finishes the login.
struct Noise {
    now: u64,
    line: bool,
}

impl Transport for Noise {
    fn send(&mut self, data: &[u8]) -> Result<usize, SendError> {
        Ok(data.len())
    }
    fn recv(&mut self, _: u64) -> Result<Vec<u8>, TransportError> {
        let first = self.now == 0;
        self.now += if self.line { 10 } else { 1_000 };
        Ok(if first {
            vec![0x11]
        } else if self.line {
            b"x\r\n".to_vec()
        } else {
            b"x".to_vec()
        })
    }
    fn now_ms(&mut self) -> u64 {
        self.now
    }
}

#[test]
fn test_login_line_count_cap() {
    let mut c = Client::new(Noise { now: 0, line: true });
    assert_eq!(
        c.login(PLACEHOLDER_PASSWORD),
        Err(Error::Login(LoginFailure::TooManyLines {
            max: kxtd1232::session::MAX_LINES
        }))
    );
}

#[test]
fn test_login_overall_time_limit() {
    let mut c = Client::new(Noise {
        now: 0,
        line: false,
    });
    assert_eq!(
        c.login(PLACEHOLDER_PASSWORD),
        Err(Error::Login(LoginFailure::TimedOut { ms: 30_000 }))
    );
    assert!(c.transport().now <= 31_000);
}
