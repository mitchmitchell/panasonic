//! Link drop mid-chunk / mid-send / post-send (design §6, milestone A2).

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

fn relogin(c: &mut Client<SimTransport>) {
    c.transport_mut().reconnect();
    c.login(PLACEHOLDER_PASSWORD).unwrap();
}

fn block(c: &mut Client<SimTransport>) -> (Vec<u8>, Vec<u8>) {
    let base = c.read(0x25, 10, 0, 80).unwrap();
    let mut new = base.clone();
    new[0] = b'L';
    (base, new)
}

fn write_cmds(c: &Client<SimTransport>) -> usize {
    c.transport()
        .sim()
        .commands
        .iter()
        .filter(|&&b| b == 0x00)
        .count()
}

#[test]
fn test_link_drop_mid_chunk_disconnects_then_relogin_verify() {
    let mut c = client();
    let (base, new) = block(&mut c);
    c.transport_mut()
        .sim()
        .inject(Fault::LinkDropMidChunk { partial_len: 2 });
    assert!(matches!(
        c.write(0x25, 10, 0, &new),
        Err(Error::LinkDown(_))
    ));
    assert_eq!(c.state(), &SessionState::Disconnected);
    assert_eq!(write_cmds(&c), 1, "never resent");
    assert_eq!(
        c.verify_block(0x25, 10, 0, &new, &base),
        Err(Error::SessionLost),
        "transport reconnect alone must not restore binary I/O"
    );
    relogin(&mut c);
    assert!(matches!(c.state(), SessionState::AwaitingVerify(_)));
    assert_eq!(
        c.verify_block(0x25, 10, 0, &new, &base),
        Ok(VerifyOutcome::Applied)
    );
}

/// Partial bytes on the wire: possibly applied — resume verify after reconnect (Tester t4).
#[test]
fn test_link_drop_partial_frame_send_verify_after_relogin() {
    let mut c = client();
    let (base, new) = block(&mut c);
    c.transport_mut()
        .sim()
        .inject(Fault::LinkDropMidSend { after_bytes: 6 });
    assert!(matches!(
        c.write(0x25, 10, 0, &new),
        Err(Error::LinkDown(_))
    ));
    assert_eq!(c.state(), &SessionState::Disconnected);
    assert_eq!(write_cmds(&c), 0, "partial frame must not commit on PBX");
    relogin(&mut c);
    assert!(matches!(c.state(), SessionState::AwaitingVerify(_)));
    assert_eq!(
        c.verify_block(0x25, 10, 0, &new, &base),
        Ok(VerifyOutcome::NotApplied)
    );
}

/// Full write frame sent, link drops before ack: verify after reconnect (Tester probe t4).
#[test]
fn test_link_drop_after_full_write_send_verify_after_relogin() {
    let mut c = client();
    let (base, new) = block(&mut c);
    c.transport_mut().drop_link_after_write = true;
    assert!(matches!(
        c.write(0x25, 10, 0, &new),
        Err(Error::LinkDown(_))
    ));
    assert_eq!(c.state(), &SessionState::Disconnected);
    assert_eq!(write_cmds(&c), 1, "full frame reached the PBX");
    relogin(&mut c);
    assert!(matches!(c.state(), SessionState::AwaitingVerify(_)));
    assert_eq!(
        c.verify_block(0x25, 10, 0, &new, &base),
        Ok(VerifyOutcome::Applied)
    );
}

#[test]
fn test_link_drop_blocks_until_relogin() {
    let mut c = client();
    let (_base, new) = block(&mut c);
    c.transport_mut()
        .sim()
        .inject(Fault::LinkDropMidChunk { partial_len: 1 });
    assert!(matches!(
        c.write(0x25, 10, 0, &new),
        Err(Error::LinkDown(_))
    ));
    assert!(matches!(c.read(0x24, 0, 0, 3), Err(Error::SessionLost)));
    relogin(&mut c);
    assert!(c.read(0x24, 0, 0, 3).is_ok());
}
