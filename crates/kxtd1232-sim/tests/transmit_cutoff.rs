//! Post-send cutoff (Tester defect 3 at e5866ba): a frame that arrives before the
//! request could have been transmitted (9600 baud, 10 bits per byte) plus the shortest
//! reply and the turnaround margin is stale and dropped.

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::error::UnackedReason;
use kxtd1232::frame::Access;
use kxtd1232::{Client, Error, Timing};
use kxtd1232_sim::{Fault, SimPbx, SimTransport, PLACEHOLDER_PASSWORD};

const ACK: [u8; 4] = [0x03, 0x00, 0x00, 0x03];
/// A 16-byte write frame: LEN CMD table rec(2) word(2) 00 payload(16) SUM.
const WRITE_LEN: usize = 25;
/// The pre-send quiet wait on an idle line, before the write goes out.
const PRESEND: u64 = 100;

fn client() -> Client<SimTransport> {
    let mut c = Client::with(
        SimTransport::new(SimPbx::default()),
        Access::ReadWrite,
        Timing::default(),
    );
    c.login(PLACEHOLDER_PASSWORD).unwrap();
    c
}

fn stored(c: &Client<SimTransport>) -> bool {
    c.transport().sim.db[&0x25][32..48] == [0x11; 16]
}

#[test]
fn test_cutoff_value() {
    let t = Timing::default();
    // 25 bytes = 26.04 ms -> 27; 4-byte ack = 4.17 ms -> 5; margin 20.
    assert_eq!(t.reply_cutoff_ms(WRITE_LEN), 27 + 5 + 20);
}

#[test]
fn test_dropped_write_with_stale_ack_before_cutoff_is_unacked() {
    let cut = Timing::default().reply_cutoff_ms(WRITE_LEN);
    for off in [0, 1, 5, 10, 20, 49, cut - 1] {
        let mut c = client();
        c.transport_mut().sim.inject(Fault::NoAckDropped);
        c.transport_mut()
            .inject_inbound_after(PRESEND + off, ACK.to_vec());
        let e = c.write(0x25, 2, 0, &[0x11; 16]).unwrap_err();
        assert!(
            matches!(e, Error::Unacked(ref u) if u.reason == UnackedReason::Timeout),
            "+{off}: {e:?}"
        );
        assert!(!stored(&c));
        assert!(!c.drained().is_empty(), "stale ack logged as drained");
    }
}

#[test]
fn test_ack_at_cutoff_is_taken_as_the_reply() {
    // Other side of the boundary: a frame at the cutoff could be genuine.
    let cut = Timing::default().reply_cutoff_ms(WRITE_LEN);
    let mut c = client();
    c.transport_mut().sim.inject(Fault::NoAckApplied);
    c.transport_mut()
        .inject_inbound_after(PRESEND + cut, ACK.to_vec());
    assert_eq!(c.write(0x25, 2, 0, &[0x11; 16]), Ok(()));
    assert!(stored(&c));
}

#[test]
fn test_sim_default_reply_lands_after_cutoff() {
    // The sim models transmit time (request in, reply out) plus its turnaround, so its
    // default replies clear the cutoff.
    let mut c = client();
    assert_eq!(c.write(0x25, 0, 0, &[0x22; 16]), Ok(()));
    assert!(c.read(0x24, 0, 0, 3).is_ok());
}
