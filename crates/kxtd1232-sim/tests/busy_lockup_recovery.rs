//! Malformed LEN / junk busy lockup, checksum NAK + junk recovery (protocol facts).

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

fn bad_read_header() -> Vec<u8> {
    let mut bad = read_probe();
    corrupt_checksum(&mut bad);
    bad
}

fn prng_junk(seed: u64, len: usize) -> Vec<u8> {
    let mut s = seed;
    (0..len)
        .map(|_| {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            (s >> 33) as u8
        })
        .collect()
}

fn recover_after_bad_header_and_junk(c: &mut Client<SimTransport>, junk: &[u8]) {
    let mut wire = bad_read_header();
    wire.extend_from_slice(junk);
    Transport::send(c.transport_mut(), &wire).unwrap();
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
        "expected at least one unsolicited busy frame, got {busy_drained}"
    );
    assert!(c.read(0x24, 0, 0, 3).is_ok(), "read after recovery");
}

#[test]
fn test_bad_checksum_read_nak_then_lockup_on_trailing_junk() {
    let mut c = client_read();
    let mut wire = bad_read_header();
    wire.extend_from_slice(&[0x55; 200]);
    Transport::send(c.transport_mut(), &wire).unwrap();
    let first = c.transport_mut().recv(5_000).unwrap();
    assert!(
        first.starts_with(&READ_BAD_CHECKSUM_NAK),
        "expected read bad-checksum NAK before busy, got {first:?}"
    );
    assert!(c.drain_until_quiet().is_ok());
    assert!(c.read(0x24, 0, 0, 3).is_ok());
}

#[test]
fn test_lone_bad_checksum_read_nak_only_no_lockup() {
    let mut c = client_read();
    Transport::send(c.transport_mut(), &bad_read_header()).unwrap();
    let first = c.transport_mut().recv(5_000).unwrap();
    assert_eq!(
        first.as_slice(),
        READ_BAD_CHECKSUM_NAK,
        "lone bad-checksum read must get only the NAK fixture"
    );
    assert!(c.read(0x24, 0, 0, 3).is_ok(), "link stays up after NAK");
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
    let first = c.transport_mut().recv(5_000).unwrap();
    assert_eq!(
        first.as_slice(),
        WRITE_BAD_CHECKSUM_NAK,
        "lone bad-checksum write must get only the NAK fixture"
    );
    assert!(c.write(0x25, 0, 0, &new).is_ok());
}

#[test]
fn test_junk_after_bad_read_header_byte_0x00() {
    recover_after_bad_header_and_junk(&mut client_read(), &vec![0x00; 200]);
}

#[test]
fn test_junk_after_bad_read_header_byte_0x55() {
    recover_after_bad_header_and_junk(&mut client_read(), &vec![0x55; 200]);
}

#[test]
fn test_junk_after_bad_read_header_byte_0xff() {
    recover_after_bad_header_and_junk(&mut client_read(), &vec![0xFF; 200]);
}

#[test]
fn test_junk_after_bad_read_header_prng() {
    recover_after_bad_header_and_junk(&mut client_read(), &prng_junk(0xA2_00_01, 200));
}

#[test]
fn test_busy_lockup_recovery_bad_len() {
    let mut c = client_read();
    Transport::send(c.transport_mut(), &[0x01]).unwrap();
    assert!(c.drain_until_quiet().is_ok());
    assert!(c.drained().iter().any(|d| d.bytes.as_slice() == BUSY_FRAME));
    assert!(c.read(0x24, 0, 0, 3).is_ok());
}
