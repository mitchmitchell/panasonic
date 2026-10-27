//! Client against the simulator (ported from #1 tests/sim/test_sim_client.py).

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::error::{LoginFailure, UnackedReason};
use kxtd1232::fields::encode_cid_name;
use kxtd1232::frame::Access;
use kxtd1232::{
    build_plan, field_patch, Client, Error, FieldKind, Granularity, SessionState, Timing,
};
use kxtd1232_sim::{Fault, SimPbx, SimTransport, PLACEHOLDER_PASSWORD, PLACEHOLDER_ROM_ID};

fn client(access: Access) -> Client<SimTransport> {
    let mut c = Client::with(
        SimTransport::new(SimPbx::default()),
        access,
        Timing::default(),
    );
    c.login(PLACEHOLDER_PASSWORD).unwrap();
    c
}

#[test]
fn test_login_and_version() {
    let mut c = client(Access::ReadOnly);
    assert_eq!(c.state(), &SessionState::Binary);
    assert_eq!(c.version().unwrap(), PLACEHOLDER_ROM_ID);
}

#[test]
fn test_login_sends_crlf_once_after_xon() {
    let c = client(Access::ReadOnly);
    let sent = &c.transport().sent;
    assert!(sent.starts_with(b"\r\n0000\r"));
    assert_eq!(sent.windows(2).filter(|w| w == b"\r\n").count(), 3); // CRLF, ECS OF, PRG
}

#[test]
fn test_wrong_password() {
    let mut c = Client::new(SimTransport::new(SimPbx::default()));
    assert_eq!(
        c.login("9999"),
        Err(Error::Login(LoginFailure::PasswordRejected))
    );
}

#[test]
fn test_read_records_blocks_match_db() {
    let mut c = client(Access::ReadOnly);
    let img = c.read_table(0x25).unwrap();
    assert_eq!(img, c.transport().sim().db[&0x25]);
    assert_eq!(&img[..16], encode_cid_name("TEST ONE").unwrap().as_slice());
    let part = c.read_records(0x24, 3, 30).unwrap();
    assert_eq!(part, c.transport().sim().db[&0x24][18..198]);
    // 0x24 reads in 25-record (150-byte) frames, per the spec.
    let reads = c
        .transport()
        .sim()
        .commands
        .iter()
        .filter(|&&b| b == 0x01)
        .count();
    assert_eq!(reads, 50 + 2);
}

#[test]
fn test_refusal_past_end() {
    let mut c = client(Access::ReadOnly);
    // The encoder refuses reads past the table; the client never sends them.
    assert!(matches!(c.read(0x24, 500, 0, 3), Err(Error::NotAllowed(_))));
    assert!(matches!(
        c.read_records(0x24, 499, 2),
        Err(Error::NotAllowed(_))
    ));
}

#[test]
fn test_nak_fault_surfaces() {
    let mut c = client(Access::ReadOnly);
    c.transport_mut().sim_mut().inject(Fault::Nak);
    assert_eq!(
        c.read(0x24, 0, 0, 3),
        Err(Error::Nak {
            cmd: 0x01,
            code: 0x02
        })
    );
    assert!(c.read(0x24, 0, 0, 3).is_ok());
}

#[test]
fn test_busy_run_waited_out_without_resend() {
    let mut c = client(Access::ReadOnly);
    c.transport_mut()
        .sim_mut()
        .inject(Fault::Busy { frames: 10 });
    let before = c.transport().sent.len();
    assert!(c.read(0x24, 0, 0, 3).is_ok());
    assert_eq!(
        c.transport().sent.len() - before,
        9,
        "exactly one read frame sent"
    );
}

#[test]
fn test_plan_apply_readback_in_sim() {
    let mut c = client(Access::ReadWrite);
    let base = c.read_table(0x25).unwrap();
    let p = field_patch(FieldKind::CidName, 7, "SIM WRITE").unwrap();
    let plan = build_plan(0x25, &base, &[p], Granularity::Chunk).unwrap();
    for w in &plan.writes {
        c.write(w.table, w.record, w.word, &w.new).unwrap();
        assert_eq!(
            c.read(w.table, w.record, w.word, (w.new.len() / 2) as u8)
                .unwrap(),
            w.new
        );
    }
    assert_eq!(
        FieldKind::CidName
            .decode(&c.read_records(0x25, 7, 1).unwrap())
            .unwrap(),
        "SIM WRITE"
    );
}

#[test]
fn test_silent_write_detected_by_readback() {
    let mut c = client(Access::ReadWrite);
    let base = c.read(0x25, 0, 0, 80).unwrap();
    let mut new = base.clone();
    new[0] = b'X';
    c.transport_mut().sim_mut().inject(Fault::SilentWrite);
    c.write(0x25, 0, 0, &new).unwrap();
    assert_eq!(c.read(0x25, 0, 0, 80).unwrap(), base);
}

#[test]
fn test_end_binary_then_bye() {
    let mut c = client(Access::ReadOnly);
    c.end_binary().unwrap();
    assert_eq!(c.state(), &SessionState::Closed);
    assert_eq!(c.transport().sim().commands.last(), Some(&0x0B));
}

#[test]
fn test_write_nak_counts_as_unacked() {
    let mut c = client(Access::ReadWrite);
    let base = c.read(0x24, 0, 0, 75).unwrap();
    c.transport_mut().sim_mut().inject(Fault::Nak);
    let e = c.write(0x24, 0, 0, &base).unwrap_err();
    assert!(matches!(e, Error::Unacked(ref u) if u.reason == UnackedReason::Nak(2)));
    assert!(matches!(c.state(), SessionState::AwaitingVerify(_)));
}
