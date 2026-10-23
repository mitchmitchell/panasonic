//! Malformed LEN / junk busy lockup and checksum NAK (protocol facts).

#![allow(clippy::unwrap_used)]

use kxtd1232::frame::{Access, Encoder, BUSY_FRAME};
use kxtd1232::{Client, Timing, Transport};
use kxtd1232_sim::{SimPbx, SimTransport, PLACEHOLDER_PASSWORD};

const READ_BAD_CHECKSUM_NAK: [u8; 5] = [0x04, 0x01, 0x01, 0x02, 0x08];
const WRITE_BAD_CHECKSUM_NAK: [u8; 5] = [0x04, 0x00, 0x01, 0x02, 0x07];

fn client_read() -> Client<SimTransport> {
    let mut c = Client::with(
        SimTransport::new(SimPbx::default()),
        Access::ReadOnly,
        Timing::default(),
    );
    c.login(PLACEHOLDER_PASSWORD).unwrap();
    c
}

fn client_write() -> Client<SimTransport> {
    let mut c = Client::with(
        SimTransport::new(SimPbx::default()),
        Access::ReadWrite,
        Timing::default(),
    );
    c.login(PLACEHOLDER_PASSWORD).unwrap();
    c
}

fn read_probe() -> Vec<u8> {
    Encoder::new(Access::ReadOnly).read(0x24, 0, 0, 3).unwrap()
}

fn corrupt_checksum(frame: &mut [u8]) {
    let last = frame.len() - 1;
    frame[last] = frame[last].wrapping_add(1);
}

fn recover_after_junk(c: &mut Client<SimTransport>, junk: &[u8]) {
    Transport::send(c.transport_mut(), junk).unwrap();
    assert!(
        c.drain_until_quiet().is_ok(),
        "busy train must end and the line go quiet"
    );
    let busy_drained = c
        .drained()
        .iter()
        .filter(|d| d.bytes.as_slice() == BUSY_FRAME)
        .count();
    assert!(
        busy_drained >= 1,
        "expected at least one unsolicited busy frame in the drain log, got {busy_drained}"
    );
    let cmds_before = c.transport().sim.commands.len();
    let sent_before = c.transport().sent.len();
    assert!(c.read(0x24, 0, 0, 3).is_ok(), "resend after recovery");
    assert_eq!(
        c.transport().sim.commands.len(),
        cmds_before + 1,
        "only the good frame may commit"
    );
    assert_eq!(
        c.transport().sent.len() - sent_before,
        read_probe().len(),
        "exactly one read frame resent"
    );
}

#[test]
fn test_bad_checksum_read_nak_link_stays_up() {
    let mut c = client_read();
    let mut bad = read_probe();
    corrupt_checksum(&mut bad);
    Transport::send(c.transport_mut(), &bad).unwrap();
    let nak = c.transport_mut().recv(5_000).unwrap();
    assert_eq!(nak.as_slice(), READ_BAD_CHECKSUM_NAK);
    assert!(
        !c.drained().iter().any(|d| d.bytes.as_slice() == BUSY_FRAME),
        "checksum NAK must not start busy lockup"
    );
    assert!(c.read(0x24, 0, 0, 3).is_ok());
}

#[test]
fn test_bad_checksum_write_nak_link_stays_up() {
    let mut c = client_write();
    let base = c.read(0x25, 0, 0, 80).unwrap();
    let mut new = base.clone();
    new[0] = b'N';
    let mut bad = Encoder::new(Access::ReadWrite)
        .write(0x25, 0, 0, &new)
        .unwrap();
    corrupt_checksum(&mut bad);
    Transport::send(c.transport_mut(), &bad).unwrap();
    let nak = c.transport_mut().recv(5_000).unwrap();
    assert_eq!(nak.as_slice(), WRITE_BAD_CHECKSUM_NAK);
    assert!(
        !c.drained().iter().any(|d| d.bytes.as_slice() == BUSY_FRAME),
        "checksum NAK must not start busy lockup"
    );
    assert!(c.write(0x25, 0, 0, &new).is_ok());
}

#[test]
fn test_busy_lockup_recovery_bad_len() {
    let mut c = client_read();
    recover_after_junk(&mut c, &[0x01]);
}
