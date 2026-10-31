#![allow(
    clippy::unwrap_used,
    reason = "a failed test setup step should panic the test"
)]
#![cfg(target_os = "linux")]

use kxprovd::port::device::{LeasedDevice, SmdrLineOptions};
use kxprovd::port::journal::LeaseJournal;
use kxprovd::port::{DeviceLine, PortManager, PortMode};
use kxprovd::smdr_reader::SmdrSource;
use kxtd1232::{Transport, TransportError};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TAIL: &[u8] = b"PROGRAMMING-TAIL";

enum Release {
    Drop,
    End,
}

fn release_keeps_smdr_paused_until_dtr_drop_and_flush(how: Release) {
    let dir = tempfile::tempdir().unwrap();
    let p = nix::pty::openpty(None, None).unwrap();
    let path = nix::unistd::ttyname(&p.slave).unwrap();
    let mut master = std::fs::File::from(p.master);
    let _slave = p.slave;
    let pm = Arc::new(PortManager::new(
        DeviceLine,
        LeaseJournal::new(dir.path().join("lease.jsonl")),
        1,
    ));
    let mut smdr = pm
        .open_smdr_device(&path, SmdrLineOptions::default())
        .unwrap();
    let mut dev: LeasedDevice<DeviceLine> = pm
        .open_leased_device(
            "job-order",
            Duration::from_secs(2),
            &path,
            SmdrLineOptions::default(),
            2_000,
        )
        .unwrap();
    let mode_at_restore = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&mode_at_restore);
    let watched = Arc::clone(&pm);
    dev.set_restore_readback_hook(Box::new(move |_| {
        seen.lock().unwrap().push(watched.mode());
    }));
    assert!(matches!(dev.recv(50), Err(TransportError::Timeout)));
    master.write_all(TAIL).unwrap();
    std::thread::sleep(Duration::from_millis(50));

    let reader = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(1_200);
        let mut got = Vec::new();
        while Instant::now() < deadline {
            match smdr.recv(20) {
                Ok(b) => got.extend(b),
                Err(TransportError::Timeout) => {}
                Err(e) => panic!("SMDR recv failed: {e:?}"),
            }
        }
        got
    });
    match how {
        Release::Drop => drop(dev),
        Release::End => dev.end(Duration::from_millis(200)).unwrap(),
    }
    assert_eq!(pm.mode(), PortMode::Smdr);
    let smdr_read = reader.join().unwrap();
    assert!(
        !smdr_read.windows(TAIL.len()).any(|w| w == TAIL),
        "SMDR read programming bytes before the DTR drop and input flush: {smdr_read:?}"
    );
    assert_eq!(
        *mode_at_restore.lock().unwrap(),
        [PortMode::Programming],
        "lease released before the DTR drop, flush and restore finished"
    );
}

#[test]
fn drop_keeps_smdr_paused_until_the_dtr_drop_and_flush_finish() {
    release_keeps_smdr_paused_until_dtr_drop_and_flush(Release::Drop);
}

#[test]
fn end_keeps_smdr_paused_until_the_dtr_drop_and_flush_finish() {
    release_keeps_smdr_paused_until_dtr_drop_and_flush(Release::End);
}
