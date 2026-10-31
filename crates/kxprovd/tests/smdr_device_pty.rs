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
    _slave: std::os::fd::OwnedFd,
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
        _slave: p.slave,
        path,
    }
}

#[test]
fn open_clears_raw_mode_flags_and_reads_them_back() {
    let pty = pty();
    let _dev = open_smdr_device(&pty.path, SmdrLineOptions::default()).unwrap();
    let probe = std::fs::File::open(&pty.path).unwrap();
    let t = termios::tcgetattr(&probe).unwrap();
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
