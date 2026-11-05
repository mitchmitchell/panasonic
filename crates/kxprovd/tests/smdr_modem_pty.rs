#![allow(
    clippy::unwrap_used,
    reason = "a failed test setup step should panic the test"
)]
#![cfg(target_os = "linux")]

use kxprovd::port::device::{SmdrDeviceHandle, SmdrLineOptions};
use kxprovd::port::journal::LeaseJournal;
use kxprovd::port::PortManager;
use kxtd1232_sim::{SimPbx, SimTransport};
use nix::sys::termios::{self, InputFlags, LocalFlags, SetArg};
use std::path::PathBuf;
use std::process::Command;

const STRACE_CHILD_ENV: &str = "KXPROVD_SMDR_MODEM_STRACE_CHILD";

fn manager() -> PortManager<SimTransport> {
    PortManager::new(
        SimTransport::new(SimPbx::new(Default::default(), "1234")),
        LeaseJournal::new(
            std::env::temp_dir().join(format!("kxprovd-modem-{}.jsonl", std::process::id())),
        ),
        1,
    )
}

fn open_handle(path: &std::path::Path) -> SmdrDeviceHandle {
    manager()
        .open_smdr_device(path, SmdrLineOptions::default())
        .unwrap()
}

struct Pty {
    _master: std::fs::File,
    path: PathBuf,
}

fn pty() -> Pty {
    let p = nix::pty::openpty(None, None).unwrap();
    let path = nix::unistd::ttyname(&p.slave).unwrap();
    let mut t = termios::tcgetattr(&p.slave).unwrap();
    t.input_flags |= InputFlags::IXON | InputFlags::IXOFF;
    t.local_flags |= LocalFlags::ECHO | LocalFlags::ICANON;
    termios::tcsetattr(&p.slave, SetArg::TCSANOW, &t).unwrap();
    Pty {
        _master: std::fs::File::from(p.master),
        path,
    }
}

fn strace_child_probe() {
    let path = std::env::var(STRACE_CHILD_ENV).expect("child path");
    let dev = open_handle(path.as_ref());
    for _ in 0..32 {
        let _ = dev.read_modem_cts();
    }
}

fn forbidden_ioctl(line: &str) -> bool {
    const FORBIDDEN: [&str; 3] = ["TIOCMSET", "TIOCMBIS", "TIOCMBIC"];
    line.contains("ioctl(") && FORBIDDEN.iter().any(|name| line.contains(name))
}

#[test]
fn modem_status_read_never_writes_or_sets_modem_bits() {
    if std::env::var(STRACE_CHILD_ENV).is_ok() {
        strace_child_probe();
        return;
    }
    let pty = pty();
    let trace = tempfile::NamedTempFile::new().unwrap();
    let exe = std::env::current_exe().unwrap();
    let status = Command::new("strace")
        .args([
            "-f",
            "-e",
            "trace=write,ioctl",
            "-o",
            trace.path().to_str().unwrap(),
            "--",
        ])
        .env(STRACE_CHILD_ENV, pty.path.as_os_str())
        .arg(exe)
        .args([
            "--exact",
            "modem_status_read_never_writes_or_sets_modem_bits",
            "--nocapture",
            "--quiet",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "strace child failed: {status:?}");
    let log = std::fs::read_to_string(trace.path()).unwrap();
    for line in log.lines() {
        assert!(
            !line.starts_with("write("),
            "modem status read must not write: {line}"
        );
        assert!(
            !forbidden_ioctl(line),
            "modem status read must not set modem bits: {line}"
        );
    }
}
