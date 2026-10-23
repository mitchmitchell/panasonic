//! Malformed-frame busy lockup and recovery (behavior spec / design §9b).

#![allow(clippy::unwrap_used)]

use kxtd1232::frame::{Access, Encoder, BUSY_FRAME};
use kxtd1232::{Client, Timing, Transport};
use kxtd1232_sim::{SimPbx, SimTransport, BUSY_LOCKUP_FRAMES, PLACEHOLDER_PASSWORD};

fn client() -> Client<SimTransport> {
    let mut c = Client::with(
        SimTransport::new(SimPbx::default()),
        Access::ReadOnly,
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

fn recover_after_bad_bytes(c: &mut Client<SimTransport>, bad: &[u8]) {
    Transport::send(c.transport_mut(), bad).unwrap();
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
        busy_drained >= BUSY_LOCKUP_FRAMES as usize / 2,
        "expected unsolicited busy frames in the drain log, got {busy_drained}"
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
fn test_busy_lockup_recovery_bad_checksum() {
    let mut c = client();
    let mut bad = read_probe();
    corrupt_checksum(&mut bad);
    recover_after_bad_bytes(&mut c, &bad);
}

#[test]
fn test_busy_lockup_recovery_bad_len() {
    let mut c = client();
    recover_after_bad_bytes(&mut c, &[0x01]);
}
