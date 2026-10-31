#![allow(
    clippy::unwrap_used,
    reason = "a failed test setup step should panic the test"
)]
#![cfg(target_os = "linux")]

use kxprovd::port::device::SmdrLineOptions;
use kxprovd::port::journal::LeaseJournal;
use kxprovd::port::{DeviceLine, LeaseError, LeasedOpenError, PortManager, PortMode};
use kxprovd::smdr_reader::SmdrSource;
use kxtd1232::{Transport, TransportError};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

struct Pty {
    master: std::fs::File,
    _slave: std::os::fd::OwnedFd,
    path: PathBuf,
}

fn pty() -> Pty {
    let p = nix::pty::openpty(None, None).unwrap();
    let path = nix::unistd::ttyname(&p.slave).unwrap();
    Pty {
        master: std::fs::File::from(p.master),
        _slave: p.slave,
        path,
    }
}

fn manager(dir: &tempfile::TempDir) -> PortManager<DeviceLine> {
    PortManager::new(
        DeviceLine,
        LeaseJournal::new(dir.path().join("lease.jsonl")),
        1,
    )
}

fn read_until(src: &mut impl SmdrSource, needle: &[u8], within: Duration) -> Vec<u8> {
    let deadline = Instant::now() + within;
    let mut got = Vec::new();
    while Instant::now() < deadline && !got.windows(needle.len()).any(|w| w == needle) {
        match src.recv(100) {
            Ok(b) => got.extend(b),
            Err(TransportError::Timeout) => {}
            Err(e) => panic!("SMDR recv failed: {e:?}"),
        }
    }
    got
}

fn smdr_bytes_for(src: &mut impl SmdrSource, window: Duration) -> Vec<u8> {
    let deadline = Instant::now() + window;
    let mut got = Vec::new();
    while Instant::now() < deadline {
        match src.recv(50) {
            Ok(b) => got.extend(b),
            Err(TransportError::Timeout) => {}
            Err(e) => panic!("SMDR recv failed: {e:?}"),
        }
    }
    got
}

fn device_recv_until(dev: &mut impl Transport, needle: &[u8]) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut got = Vec::new();
    while Instant::now() < deadline && !got.windows(needle.len()).any(|w| w == needle) {
        match dev.recv(100) {
            Ok(b) => got.extend(b),
            Err(TransportError::Timeout) => {}
            Err(e) => panic!("programming recv failed: {e:?}"),
        }
    }
    got
}

#[test]
fn smdr_pauses_for_the_leased_dtr_cycle_and_resumes_after_without_programming_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let mut pty = pty();
    let pm = manager(&dir);
    let mut smdr = pm
        .open_smdr_device(&pty.path, SmdrLineOptions::default())
        .unwrap();
    pty.master.write_all(b"10/30/26 before\r\n").unwrap();
    let before = read_until(&mut smdr, b"before\r\n", Duration::from_secs(2));
    assert!(before.ends_with(b"10/30/26 before\r\n"), "{before:?}");

    let mut dev = pm
        .open_leased_device(
            "job-1",
            Duration::from_secs(2),
            &pty.path,
            SmdrLineOptions::default(),
            2_000,
        )
        .unwrap();
    assert_eq!(pm.mode(), PortMode::Programming);

    let watcher = std::thread::spawn(move || {
        let seen = smdr_bytes_for(&mut smdr, Duration::from_millis(900));
        (smdr, seen)
    });
    pty.master.write_all(b"STALE-BEFORE-RISE").unwrap();
    assert!(dev.cycle_dtr().unwrap());
    pty.master.write_all(b"\x13\x11PROMPT>").unwrap();
    let reply = device_recv_until(&mut dev, b"PROMPT>");
    assert_eq!(reply, b"\x13\x11PROMPT>");
    pty.master.write_all(b"UNREAD-PROGRAMMING-REPLY").unwrap();
    let (mut smdr, seen_while_leased) = watcher.join().unwrap();
    assert!(
        seen_while_leased.is_empty(),
        "SMDR read {seen_while_leased:?} while the programming lease was held"
    );

    drop(dev);
    assert_eq!(pm.mode(), PortMode::Smdr);
    pty.master.write_all(b"10/30/26 after\r\n").unwrap();
    let after = read_until(&mut smdr, b"after\r\n", Duration::from_secs(2));
    assert_eq!(after, b"10/30/26 after\r\n");
}

#[test]
fn a_second_programming_open_waits_for_the_held_lease_and_gets_it_after_drop() {
    let dir = tempfile::tempdir().unwrap();
    let pty = pty();
    let pm = manager(&dir);
    let open = |timeout| {
        pm.open_leased_device("job", timeout, &pty.path, SmdrLineOptions::default(), 2_000)
    };
    let held = open(Duration::from_millis(50)).unwrap();
    assert!(held.holds_own_flock());
    assert!(matches!(
        open(Duration::from_millis(100)),
        Err(LeasedOpenError::Lease(LeaseError::Timeout { .. }))
    ));
    drop(held);
    assert_eq!(pm.mode(), PortMode::Smdr);
    let again = open(Duration::from_millis(100)).unwrap();
    again.end(Duration::from_millis(100)).unwrap();
}
