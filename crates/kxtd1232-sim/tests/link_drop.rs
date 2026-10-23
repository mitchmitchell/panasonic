//! Link drop mid-chunk (design §6, milestone A2).

#![allow(clippy::unwrap_used)]

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
    new[0] = b'L';
    (base, new)
}

fn write_cmds(c: &Client<SimTransport>) -> usize {
    c.transport()
        .sim
        .commands
        .iter()
        .filter(|&&b| b == 0x00)
        .count()
}

#[test]
fn test_link_drop_mid_chunk_surfaces_link_down_not_unacked() {
    let mut c = client();
    let (base, new) = block(&mut c);
    c.transport_mut()
        .sim
        .inject(Fault::LinkDropMidChunk { partial_len: 2 });
    let e = c.write(0x25, 10, 0, &new).unwrap_err();
    assert!(
        matches!(e, Error::LinkDown(_)),
        "partial ack is not a clean write ack"
    );
    assert_eq!(c.state(), &SessionState::Binary);
    assert_eq!(write_cmds(&c), 1, "never resent");
    c.transport_mut().clear_link_down();
    assert_eq!(
        c.verify_block(0x25, 10, 0, &new, &base),
        Ok(VerifyOutcome::Applied),
        "write reached the sim before the cable drop"
    );
}

#[test]
fn test_link_drop_blocks_io_until_cleared() {
    let mut c = client();
    let (_base, new) = block(&mut c);
    c.transport_mut()
        .sim
        .inject(Fault::LinkDropMidChunk { partial_len: 1 });
    assert!(matches!(
        c.write(0x25, 10, 0, &new),
        Err(Error::LinkDown(_))
    ));
    assert!(matches!(c.read(0x24, 0, 0, 3), Err(Error::LinkDown(_))));
    c.transport_mut().clear_link_down();
    assert!(c.read(0x24, 0, 0, 3).is_ok());
}
