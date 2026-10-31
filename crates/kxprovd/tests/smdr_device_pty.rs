#![allow(
    clippy::unwrap_used,
    reason = "a failed test setup step should panic the test"
)]
#![cfg(target_os = "linux")]

use kxprovd::port::device::{
    DeviceError, SmdrDeviceHandle, SmdrLineOptions, CLEARED_INPUT_FLAGS, CLEARED_LOCAL_FLAGS,
};
use kxprovd::port::journal::LeaseJournal;
use kxprovd::port::PortManager;
use kxprovd::smdr_reader::SmdrSource;
use kxtd1232_sim::{SimPbx, SimTransport};
use nix::sys::termios::{self, BaudRate, ControlFlags, InputFlags, LocalFlags, SetArg};
use std::io::Write;
use std::path::PathBuf;

fn manager() -> PortManager<SimTransport> {
    PortManager::new(
        SimTransport::new(SimPbx::new(Default::default(), "1234")),
        LeaseJournal::new(
            std::env::temp_dir().join(format!("kxprovd-pty-{}.jsonl", std::process::id())),
        ),
        1,
    )
}

fn open_smdr_device(
    path: &std::path::Path,
    options: SmdrLineOptions,
) -> Result<SmdrDeviceHandle, DeviceError> {
    manager().open_smdr_device(path, options)
}

const CHILD_ENV: &str = "KXPROVD_SMDR_LOCK_CHILD_PATH";

struct Pty {
    master: std::fs::File,
    slave: std::os::fd::OwnedFd,
    path: PathBuf,
}

fn pty() -> Pty {
    let p = nix::pty::openpty(None, None).unwrap();
    let path = nix::unistd::ttyname(&p.slave).unwrap();
    let mut t = termios::tcgetattr(&p.slave).unwrap();
    t.input_flags |= InputFlags::IXON | InputFlags::IXOFF | InputFlags::IXANY;
    t.local_flags |= LocalFlags::ECHO | LocalFlags::ICANON | LocalFlags::ECHOE;
    termios::tcsetattr(&p.slave, SetArg::TCSANOW, &t).unwrap();
    Pty {
        master: std::fs::File::from(p.master),
        slave: p.slave,
        path,
    }
}

#[test]
fn open_clears_raw_mode_flags_and_reads_them_back() {
    let pty = pty();
    let _dev = open_smdr_device(&pty.path, SmdrLineOptions::default()).unwrap();
    let t = termios::tcgetattr(&pty.slave).unwrap();
    for (name, flag) in CLEARED_INPUT_FLAGS {
        assert!(!t.input_flags.contains(flag), "{name} still set");
    }
    for (name, flag) in CLEARED_LOCAL_FLAGS {
        assert!(!t.local_flags.contains(flag), "{name} still set");
    }
    assert!(!t.control_flags.contains(ControlFlags::CRTSCTS));
    assert!(t
        .control_flags
        .contains(ControlFlags::CS8 | ControlFlags::CREAD | ControlFlags::CLOCAL));
    assert_eq!(termios::cfgetispeed(&t), BaudRate::B9600);
}

#[test]
fn handle_is_opened_read_only_and_receives_bytes() {
    let mut pty = pty();
    let mut dev = open_smdr_device(&pty.path, SmdrLineOptions::default()).unwrap();
    assert!(dev.access_mode_is_read_only().unwrap());
    pty.master.write_all(b"10/30/26 05:48PM 101\r\n").unwrap();
    let got = dev.recv(1000).unwrap();
    assert!(got.starts_with(b"10/30/26"), "{got:?}");
}

#[test]
fn a_regular_file_is_refused_as_not_a_tty() {
    let f = tempfile::NamedTempFile::new().unwrap();
    assert!(matches!(
        open_smdr_device(f.path(), SmdrLineOptions::default()),
        Err(DeviceError::NotATty)
    ));
}

#[test]
fn lock_child_probe() {
    if let Ok(path) = std::env::var(CHILD_ENV) {
        let code = match open_smdr_device(path.as_ref(), SmdrLineOptions::default()) {
            Err(DeviceError::Locked) => 0,
            Ok(_) => 10,
            Err(_) => 11,
        };
        std::process::exit(code);
    }
}

#[test]
fn a_second_process_cannot_open_a_locked_device() {
    let pty = pty();
    let _dev = open_smdr_device(&pty.path, SmdrLineOptions::default()).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "lock_child_probe", "--nocapture"])
        .env(CHILD_ENV, &pty.path)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(0));
}

#[test]
fn one_manager_refuses_a_second_open() {
    let pty = pty();
    let pm = manager();
    let _dev = pm
        .open_smdr_device(&pty.path, SmdrLineOptions::default())
        .unwrap();
    assert!(matches!(
        pm.open_smdr_device(&pty.path, SmdrLineOptions::default()),
        Err(DeviceError::AlreadyOpen)
    ));
}

const PROGRAMMING_CHILD_ENV: &str = "KXPROVD_PROGRAMMING_LOCK_CHILD_PATH";

#[test]
fn programming_lock_child_probe() {
    if let Ok(path) = std::env::var(PROGRAMMING_CHILD_ENV) {
        let pm = manager();
        let lease = pm
            .request_lease("child-job", std::time::Duration::from_millis(50))
            .unwrap();
        let code =
            match pm.open_programming_device(&lease, path.as_ref(), SmdrLineOptions::default()) {
                Err(DeviceError::Locked) => 0,
                Ok(_) => 10,
                Err(_) => 11,
            };
        std::process::exit(code);
    }
}

#[test]
fn a_programming_open_fails_closed_while_another_process_holds_the_port() {
    let pty = pty();
    let _smdr = open_smdr_device(&pty.path, SmdrLineOptions::default()).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "programming_lock_child_probe", "--nocapture"])
        .env(PROGRAMMING_CHILD_ENV, &pty.path)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(0));
}

#[test]
fn a_programming_open_fails_closed_while_another_open_file_holds_the_flock() {
    let pty = pty();
    let other = nix::fcntl::Flock::lock(
        std::fs::File::open(&pty.path).unwrap(),
        nix::fcntl::FlockArg::LockExclusiveNonblock,
    )
    .map_err(|(_, e)| e)
    .unwrap();
    let pm = manager();
    let lease = pm
        .request_lease("job-1", std::time::Duration::from_millis(50))
        .unwrap();
    assert!(matches!(
        pm.open_programming_device(&lease, &pty.path, SmdrLineOptions::default()),
        Err(DeviceError::Locked)
    ));
    drop(other);
    let dev = pm
        .open_programming_device(&lease, &pty.path, SmdrLineOptions::default())
        .unwrap();
    assert!(dev.holds_own_flock());
}

#[test]
fn a_programming_open_needs_this_managers_lease() {
    let pty = pty();
    let pm = manager();
    let other = manager();
    let foreign = other
        .request_lease("job-other", std::time::Duration::from_millis(50))
        .unwrap();
    assert!(matches!(
        pm.open_programming_device(&foreign, &pty.path, SmdrLineOptions::default()),
        Err(DeviceError::NoLease)
    ));
}

#[test]
fn a_programming_open_under_the_smdr_flock_pauses_smdr_reads_and_writes_to_the_port() {
    use kxtd1232::Transport;
    use std::io::Read;

    let mut pty = pty();
    let pm = manager();
    let mut smdr = pm
        .open_smdr_device(&pty.path, SmdrLineOptions::default())
        .unwrap();
    let lease = pm
        .request_lease("job-1", std::time::Duration::from_millis(50))
        .unwrap();
    let mut dev = pm
        .open_programming_device(&lease, &pty.path, SmdrLineOptions::default())
        .unwrap();
    assert!(!dev.holds_own_flock());
    pty.master.write_all(b"OK\r\n").unwrap();
    assert!(matches!(
        smdr.recv(100),
        Err(kxtd1232::TransportError::Timeout)
    ));
    assert_eq!(dev.recv(1000).unwrap(), b"OK\r\n");
    dev.send(b"PRG\r\n").unwrap();
    let mut buf = [0u8; 16];
    let n = pty.master.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"PRG\r\n");
    let started = std::time::Instant::now();
    assert!(matches!(
        dev.end(std::time::Duration::from_millis(100)),
        Err(kxprovd::port::PortReleaseError::EndBinaryNotAcked { .. })
    ));
    assert!(started.elapsed() >= kxprovd::port::DTR_LOW_PERIOD);
    let t = termios::tcgetattr(&pty.slave).unwrap();
    assert_eq!(termios::cfgetispeed(&t), BaudRate::B9600);
    assert_eq!(termios::cfgetospeed(&t), BaudRate::B9600);
    lease.release().unwrap();
    pty.master.write_all(b"10/30/26\r\n").unwrap();
    assert!(smdr.recv(1000).unwrap().starts_with(b"10/30/26"));
    assert!(matches!(
        std::fs::File::open(&pty.path),
        Err(e) if e.raw_os_error() == Some(nix::libc::EBUSY)
    ));
}

#[test]
fn an_smdr_open_sets_tiocexcl_so_a_plain_open_is_refused() {
    let pty = pty();
    let _smdr = open_smdr_device(&pty.path, SmdrLineOptions::default()).unwrap();
    assert!(matches!(
        std::fs::File::open(&pty.path),
        Err(e) if e.raw_os_error() == Some(nix::libc::EBUSY)
    ));
}

#[test]
fn a_tiocexcl_holder_without_flock_excludes_smdr_and_programming_opens() {
    let pty = pty();
    let other = std::fs::File::open(&pty.path).unwrap();
    rustix::termios::ioctl_tiocexcl(&other).unwrap();
    assert!(matches!(
        open_smdr_device(&pty.path, SmdrLineOptions::default()),
        Err(DeviceError::Locked)
    ));
    let pm = manager();
    let lease = pm
        .request_lease("job-1", std::time::Duration::from_millis(50))
        .unwrap();
    assert!(matches!(
        pm.open_programming_device(&lease, &pty.path, SmdrLineOptions::default()),
        Err(DeviceError::Locked)
    ));
    rustix::termios::ioctl_tiocnxcl(&other).unwrap();
}

#[test]
fn a_programming_device_ends_binary_before_bye_then_drops_dtr() {
    use kxprovd::port::{SessionMode, END_BINARY, END_BINARY_ACK, PRG};
    use kxtd1232::Transport;
    use std::io::Read;

    let mut pty = pty();
    let pm = manager();
    let lease = pm
        .request_lease("job-1", std::time::Duration::from_millis(50))
        .unwrap();
    let mut dev = pm
        .open_programming_device(&lease, &pty.path, SmdrLineOptions::default())
        .unwrap();
    dev.send(PRG).unwrap();
    assert_eq!(dev.session_mode(), SessionMode::Binary);
    let mut buf = [0u8; 16];
    let n = pty.master.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], PRG);
    let pbx = std::thread::spawn(move || {
        let mut seen = Vec::new();
        let mut buf = [0u8; 16];
        while !seen.ends_with(&END_BINARY) {
            let n = pty.master.read(&mut buf).unwrap();
            seen.extend_from_slice(&buf[..n]);
        }
        pty.master.write_all(&END_BINARY_ACK).unwrap();
        while !seen.ends_with(b"BYE\r\n") {
            let n = pty.master.read(&mut buf).unwrap();
            seen.extend_from_slice(&buf[..n]);
        }
        pty.master.write_all(b"OK\r\n").unwrap();
        (seen, pty)
    });
    dev.end(std::time::Duration::from_secs(2)).unwrap();
    let (seen, _pty) = pbx.join().unwrap();
    assert_eq!(seen, [&END_BINARY[..], b"BYE\r\n"].concat());
}

#[test]
fn smdr_resume_after_a_lease_reapplies_raw_termios() {
    use kxtd1232::Transport;

    let mut pty = pty();
    let pm = manager();
    let mut smdr = pm
        .open_smdr_device(&pty.path, SmdrLineOptions::default())
        .unwrap();
    let lease = pm
        .request_lease("job-1", std::time::Duration::from_millis(50))
        .unwrap();
    let mut dev = pm
        .open_programming_device(&lease, &pty.path, SmdrLineOptions::default())
        .unwrap();
    dev.send(b"X").unwrap();
    let mut t = termios::tcgetattr(&pty.slave).unwrap();
    t.input_flags |= InputFlags::IXOFF;
    t.local_flags |= LocalFlags::ECHO;
    termios::tcsetattr(&pty.slave, SetArg::TCSANOW, &t).unwrap();
    drop(dev);
    lease.release().unwrap();
    let dirty = termios::tcgetattr(&pty.slave).unwrap();
    assert!(dirty.input_flags.contains(InputFlags::IXOFF));
    assert!(dirty.local_flags.contains(LocalFlags::ECHO));
    let mut sent_by_programming = [0u8; 64];
    let n = std::io::Read::read(&mut pty.master, &mut sent_by_programming).unwrap();
    assert_eq!(&sent_by_programming[..n], b"X");
    pty.master.write_all(b"10/30/26\r\n").unwrap();
    assert!(smdr.recv(1000).unwrap().starts_with(b"10/30/26"));
    let t = termios::tcgetattr(&pty.slave).unwrap();
    for (name, flag) in CLEARED_INPUT_FLAGS {
        assert!(
            !t.input_flags.contains(flag),
            "{name} still set after resume"
        );
    }
    for (name, flag) in CLEARED_LOCAL_FLAGS {
        assert!(
            !t.local_flags.contains(flag),
            "{name} still set after resume"
        );
    }
    assert!(!t.control_flags.contains(ControlFlags::CRTSCTS));
    assert!(t
        .control_flags
        .contains(ControlFlags::CS8 | ControlFlags::CREAD | ControlFlags::CLOCAL));
    assert_eq!(termios::cfgetispeed(&t), BaudRate::B9600);
    assert_eq!(termios::cfgetospeed(&t), BaudRate::B9600);
}

#[cfg(feature = "test-util")]
fn cycle_a_lease(pm: &PortManager<SimTransport>) {
    pm.request_lease("job-1", std::time::Duration::from_millis(50))
        .unwrap()
        .release()
        .unwrap();
}

#[cfg(feature = "test-util")]
#[test]
fn a_lease_request_during_smdr_resume_waits_until_resume_finishes() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let mut pty = pty();
    let pm = manager();
    let mut smdr = pm
        .open_smdr_device(&pty.path, SmdrLineOptions::default())
        .unwrap();
    cycle_a_lease(&pm);
    let finished = Arc::new(AtomicBool::new(false));
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let hook_finished = Arc::clone(&finished);
    smdr.set_resume_readback_hook(Box::new(move |_| {
        let _test_side_only_listens_for_the_first_resume = entered_tx.send(());
        std::thread::sleep(std::time::Duration::from_millis(300));
        hook_finished.store(true, Ordering::SeqCst);
    }));
    pty.master.write_all(b"10/30/26\r\n").unwrap();
    let reader = std::thread::spawn(move || smdr.recv(1000));
    entered_rx.recv().unwrap();
    let lease = pm
        .request_lease("job-2", std::time::Duration::from_secs(2))
        .unwrap();
    assert!(
        finished.load(Ordering::SeqCst),
        "lease granted before SMDR resume finished"
    );
    let smdr_got = reader.join().unwrap();
    assert!(
        matches!(&smdr_got, Ok(b) if b.starts_with(b"10/30/26"))
            || matches!(smdr_got, Err(kxtd1232::TransportError::Timeout)),
        "SMDR must either read the pre-lease line or wait out the lease: {smdr_got:?}"
    );
    lease.release().unwrap();
}

#[cfg(feature = "test-util")]
#[test]
fn a_termios_readback_mismatch_on_resume_fails_closed_without_reading() {
    let mut pty = pty();
    let pm = manager();
    let mut smdr = pm
        .open_smdr_device(&pty.path, SmdrLineOptions::default())
        .unwrap();
    cycle_a_lease(&pm);
    smdr.set_resume_readback_hook(Box::new(|t| t.input_flags |= InputFlags::IXOFF));
    pty.master.write_all(b"10/30/26\r\n").unwrap();
    assert!(matches!(
        smdr.resume_after_lease(),
        Err(DeviceError::TermiosNotApplied { .. })
    ));
    assert!(matches!(
        smdr.recv(200),
        Err(kxtd1232::TransportError::LinkDown(_))
    ));
    smdr.set_resume_readback_hook(Box::new(|_| {}));
    assert!(smdr.recv(1000).unwrap().starts_with(b"10/30/26"));
}

#[cfg(feature = "test-util")]
#[test]
fn a_wrong_speed_readback_after_the_dtr_drop_is_a_speed_mismatch() {
    use kxprovd::port::{DtrError, PortReleaseError};

    let pty = pty();
    let pm = manager();
    let lease = pm
        .request_lease("job-1", std::time::Duration::from_millis(50))
        .unwrap();
    let mut dev = pm
        .open_programming_device(&lease, &pty.path, SmdrLineOptions::default())
        .unwrap();
    dev.set_restore_readback_hook(Box::new(|t| {
        termios::cfsetospeed(t, BaudRate::B4800).unwrap();
    }));
    let result = dev.end(std::time::Duration::from_millis(100));
    assert!(
        matches!(
            result,
            Err(PortReleaseError::DropDtr(DtrError::SpeedMismatch { .. }))
        ),
        "{result:?}"
    );
}

#[cfg(feature = "test-util")]
fn resume_fails_closed_with(hook: kxprovd::port::device::ReadbackHook, expected: &'static str) {
    let mut pty = pty();
    let pm = manager();
    let mut smdr = pm
        .open_smdr_device(&pty.path, SmdrLineOptions::default())
        .unwrap();
    cycle_a_lease(&pm);
    smdr.set_resume_readback_hook(hook);
    pty.master.write_all(b"10/30/26\r\n").unwrap();
    let result = smdr.resume_after_lease();
    assert!(
        matches!(&result, Err(DeviceError::TermiosNotApplied(m)) if m.name() == expected),
        "{result:?}"
    );
    assert!(matches!(
        smdr.recv(200),
        Err(kxtd1232::TransportError::LinkDown(_))
    ));
}

#[cfg(feature = "test-util")]
#[test]
fn a_wrong_speed_readback_on_resume_fails_closed() {
    resume_fails_closed_with(
        Box::new(|t| termios::cfsetspeed(t, BaudRate::B4800).unwrap()),
        "ospeed",
    );
}

#[cfg(feature = "test-util")]
#[test]
fn a_missing_cs8_readback_on_resume_fails_closed() {
    resume_fails_closed_with(
        Box::new(|t| {
            t.control_flags.remove(ControlFlags::CSIZE);
            t.control_flags.insert(ControlFlags::CS7);
        }),
        "CS8",
    );
}

#[cfg(feature = "test-util")]
#[test]
fn no_programming_reply_reaches_smdr_when_a_lease_lands_between_resume_and_read() {
    use kxtd1232::Transport;

    for run in 0..20 {
        let mut pty = pty();
        let pm = manager();
        let mut smdr = pm
            .open_smdr_device(&pty.path, SmdrLineOptions::default())
            .unwrap();
        cycle_a_lease(&pm);
        let (gap_tx, gap_rx) = std::sync::mpsc::channel();
        smdr.set_pre_read_hook(Box::new(move || {
            let _receiver_gone_after_the_first_read = gap_tx.send(());
            std::thread::sleep(std::time::Duration::from_millis(150));
        }));
        let reader = std::thread::spawn(move || smdr.recv(400));
        gap_rx.recv().unwrap();
        let lease = pm
            .request_lease("job-1", std::time::Duration::from_secs(2))
            .unwrap();
        let mut dev = pm
            .open_programming_device(&lease, &pty.path, SmdrLineOptions::default())
            .unwrap();
        pty.master.write_all(b"PROGREPLY\r\n").unwrap();
        let smdr_got = reader.join().unwrap();
        assert!(
            !matches!(&smdr_got, Ok(b) if b.windows(4).any(|w| w == b"PROG")),
            "run {run}: SMDR read programming bytes: {smdr_got:?}"
        );
        assert_eq!(dev.recv(1000).unwrap(), b"PROGREPLY\r\n", "run {run}");
        dev.end(std::time::Duration::from_millis(20)).unwrap();
        lease.release().unwrap();
    }
}

#[test]
fn smdr_recv_under_a_held_lease_waits_out_its_timeout() {
    let pty = pty();
    let pm = manager();
    let mut smdr = pm
        .open_smdr_device(&pty.path, SmdrLineOptions::default())
        .unwrap();
    let lease = pm
        .request_lease("job-1", std::time::Duration::from_millis(50))
        .unwrap();
    let started = std::time::Instant::now();
    let got = smdr.recv(200);
    let waited = started.elapsed();
    assert!(
        matches!(got, Err(kxtd1232::TransportError::Timeout)),
        "{got:?}"
    );
    assert!(
        waited >= std::time::Duration::from_millis(180)
            && waited <= std::time::Duration::from_millis(600),
        "{waited:?}"
    );
    lease.release().unwrap();
}

#[test]
fn smdr_recv_in_smdr_mode_returns_within_one_read_slice() {
    let pty = pty();
    let mut smdr = open_smdr_device(&pty.path, SmdrLineOptions::default()).unwrap();
    let started = std::time::Instant::now();
    let got = smdr.recv(5_000);
    let waited = started.elapsed();
    assert!(
        matches!(got, Err(kxtd1232::TransportError::Timeout)),
        "{got:?}"
    );
    assert!(
        waited <= std::time::Duration::from_millis(400),
        "{waited:?}"
    );
}

#[cfg(feature = "test-util")]
#[test]
fn smdr_never_reads_with_a_lease_dirtied_line_after_a_lease_lands_between_resume_and_read() {
    for run in 0..10 {
        let mut pty = pty();
        let pm = manager();
        let mut smdr = pm
            .open_smdr_device(&pty.path, SmdrLineOptions::default())
            .unwrap();
        let (gap_tx, gap_rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let mut first = true;
        smdr.set_pre_read_hook(Box::new(move || {
            if std::mem::take(&mut first) {
                gap_tx.send(()).unwrap();
                go_rx.recv().unwrap();
            }
        }));
        let reader = std::thread::spawn(move || smdr.recv(2000));
        gap_rx.recv().unwrap();
        let lease = pm
            .request_lease("job-1", std::time::Duration::from_secs(2))
            .unwrap();
        let dev = pm
            .open_programming_device(&lease, &pty.path, SmdrLineOptions::default())
            .unwrap();
        let mut t = termios::tcgetattr(&pty.slave).unwrap();
        t.local_flags |= LocalFlags::ECHO;
        t.input_flags |= InputFlags::IXOFF;
        termios::tcsetattr(&pty.slave, SetArg::TCSANOW, &t).unwrap();
        dev.end(std::time::Duration::from_millis(20)).unwrap();
        lease.release().unwrap();
        pty.master.write_all(b"10/30/26\r\n").unwrap();
        go_tx.send(()).unwrap();
        let smdr_got = reader.join().unwrap();
        let after = termios::tcgetattr(&pty.slave).unwrap();
        assert!(
            !after.local_flags.contains(LocalFlags::ECHO)
                && !after.input_flags.contains(InputFlags::IXOFF),
            "run {run}: SMDR read without re-applying termios after the lease: {smdr_got:?}"
        );
        assert!(
            smdr_got.as_ref().is_ok_and(|b| b.starts_with(b"10/30/26")),
            "run {run}: {smdr_got:?}"
        );
    }
}
