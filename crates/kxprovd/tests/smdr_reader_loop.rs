#![allow(
    clippy::unwrap_used,
    reason = "test setup failures should abort the test"
)]

use kxprov_api::{SmdrAlertKind, SmdrAlertState};
use kxprovd::config::Config;
use kxprovd::smdr_bus::{LiveSnapshot, SmdrLive};
use kxprovd::smdr_health::HealthConfig;
use kxprovd::smdr_loop::SmdrReaderTask;
use kxprovd::transport::device_arbiter;
use kxtd1232_sim::SimTransport;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn wait_for(
    live: &SmdrLive,
    timeout: Duration,
    mut pred: impl FnMut(&LiveSnapshot) -> bool,
) -> LiveSnapshot {
    let deadline = Instant::now() + timeout;
    loop {
        let snap = live.snapshot();
        if pred(&snap) {
            return snap;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting on smdr live snapshot: {snap:?}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn silence_active(snap: &LiveSnapshot) -> bool {
    snap.alerts.iter().any(|a| {
        a.kind == SmdrAlertKind::LineSilence && matches!(a.state, SmdrAlertState::Raised { .. })
    })
}

struct SimHarness {
    _tmp: tempfile::TempDir,
    _task: SmdrReaderTask,
    live: Arc<SmdrLive>,
    port: Arc<kxprovd::port::DeviceArbiter>,
    transport: Arc<Mutex<SimTransport>>,
}

fn sim_harness(silence_after: Duration) -> SimHarness {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("smdr-loop.sock");
    let mut cfg = Config::sim_test(tmp.path().to_path_buf(), socket, 1000);
    std::fs::create_dir_all(cfg.data_dir.join("backups")).unwrap();
    cfg.smdr_health = HealthConfig {
        silence_after,
        ..HealthConfig::default()
    };
    let pbx = cfg.sim_pbx.clone().expect("sim pbx");
    let transport = Arc::new(Mutex::new(SimTransport::with_shared(Arc::clone(&pbx))));
    cfg.sim_smdr_transport = Some(Arc::clone(&transport));
    let live = Arc::new(SmdrLive::new());
    let port = device_arbiter(&cfg);
    let task = SmdrReaderTask::spawn(cfg, Arc::clone(&port), Arc::clone(&live));
    SimHarness {
        _tmp: tmp,
        _task: task,
        live,
        port,
        transport,
    }
}

#[test]
fn sim_smdr_reader_loop_updates_live() {
    let h = sim_harness(Duration::from_secs(2));
    wait_for(&h.live, Duration::from_secs(3), |s| s.running);

    let bytes = kxprovd::test_util::smdr_fixture("mixed_stream.txt");
    h.transport.lock().unwrap().inject_inbound(bytes);

    wait_for(&h.live, Duration::from_secs(3), |s| {
        s.last_byte_at.is_some()
    });
    assert!(
        !h.live.snapshot().link_down,
        "bytes received should clear link_down"
    );

    h.transport.lock().unwrap().drop_link_now();
    wait_for(&h.live, Duration::from_secs(3), |s| s.link_down);

    h.transport.lock().unwrap().reconnect();
    h.transport
        .lock()
        .unwrap()
        .inject_inbound(kxprovd::test_util::synthetic_smdr_bytes(42, 1));
    wait_for(&h.live, Duration::from_secs(3), |s| !s.link_down);

    let lease = h
        .port
        .request_lease("loop-prog", Duration::from_secs(30))
        .expect("lease");
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        !silence_active(&h.live.snapshot()),
        "programming mode should suppress line-silence evaluation"
    );
    lease.release().expect("release");

    wait_for(&h.live, Duration::from_secs(5), silence_active);
}

#[test]
fn smdr_reader_not_started_when_disabled() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("smdr-off.sock");
    let mut cfg = Config::sim_test(tmp.path().to_path_buf(), socket, 1001);
    std::fs::create_dir_all(cfg.data_dir.join("backups")).unwrap();
    cfg.smdr.enabled = false;
    let live = Arc::new(SmdrLive::new());
    let port = device_arbiter(&cfg);
    let _task = SmdrReaderTask::spawn(cfg, port, Arc::clone(&live));
    std::thread::sleep(Duration::from_millis(200));
    assert!(!live.snapshot().running);
}

#[test]
fn daemon_holds_smdr_reader_task_while_running() {
    let tmp = tempfile::tempdir().unwrap();
    let (daemon, _sock) = kxprovd::Daemon::sim_for_tests(tmp.path(), 1002);
    wait_for(&daemon.smdr_live(), Duration::from_secs(3), |s| s.running);
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use kxprovd::port::device::SmdrLineOptions;
    use kxprovd::port::journal::LeaseJournal;
    use kxprovd::port::PortManager;
    use nix::sys::termios::{self, InputFlags, LocalFlags, SetArg};

    fn pty() -> (std::fs::File, std::os::fd::OwnedFd, std::path::PathBuf) {
        let p = nix::pty::openpty(None, None).unwrap();
        let path = nix::unistd::ttyname(&p.slave).unwrap();
        let mut t = termios::tcgetattr(&p.slave).unwrap();
        t.input_flags |= InputFlags::IXON | InputFlags::IXOFF | InputFlags::IXANY;
        t.local_flags |= LocalFlags::ECHO | LocalFlags::ICANON | LocalFlags::ECHOE;
        termios::tcsetattr(&p.slave, SetArg::TCSANOW, &t).unwrap();
        (std::fs::File::from(p.master), p.slave, path)
    }

    #[test]
    fn read_smdr_modem_cts_skipped_while_programming_lease_held() {
        let journal = LeaseJournal::new(std::env::temp_dir().join(format!(
            "kxprovd-smdr-cts-lease-{}.jsonl",
            std::process::id()
        )));
        let port = PortManager::new((), journal, 1);
        let pty = pty();
        let _handle = port
            .open_smdr_device(&pty.2, SmdrLineOptions::default())
            .expect("open smdr device");
        assert!(
            port.read_smdr_modem_cts().is_some(),
            "CTS read available while SMDR device is open and not leased"
        );
        let lease = port
            .request_lease("cts-skip", Duration::from_secs(5))
            .expect("lease");
        assert!(
            port.read_smdr_modem_cts().is_none(),
            "CTS must not be read while programming lease is held"
        );
        lease.release().expect("release");
        assert!(port.read_smdr_modem_cts().is_some());
    }
}
