#![allow(
    clippy::unwrap_used,
    reason = "test setup failures should abort the test"
)]

use kxprov_api::{SmdrAlertKind, SmdrAlertState};
use kxprovd::config::{Config, TransportKind};
use kxprovd::smdr_bus::{LiveSnapshot, SmdrLive};
use kxprovd::smdr_health::HealthConfig;
use kxprovd::smdr_loop::SmdrReaderTask;
use kxprovd::transport::device_arbiter;
use kxtd1232::smdr::SPEC_HEADER;
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

fn header_mismatch_active(snap: &LiveSnapshot) -> bool {
    snap.alerts.iter().any(|a| {
        a.kind == SmdrAlertKind::HeaderMismatch && matches!(a.state, SmdrAlertState::Raised { .. })
    })
}

#[cfg(any(test, feature = "test-util"))]
fn block_smdr_raw_journals(smdr_dir: &std::path::Path) {
    use kxprovd::smdr_store::{RAW_JOURNAL_PREFIX, RAW_JOURNAL_SUFFIX};

    for entry in std::fs::read_dir(smdr_dir).expect("smdr dir") {
        let path = entry.expect("entry").path();
        let name = path.file_name().expect("name").to_string_lossy();
        if !name.starts_with(RAW_JOURNAL_PREFIX) || !name.ends_with(RAW_JOURNAL_SUFFIX) {
            continue;
        }
        if path.is_file() {
            std::fs::remove_file(&path).expect("remove journal file");
        }
        if !path.exists() {
            std::fs::create_dir(&path).expect("journal path is a directory so append fails");
        }
    }
    let today = smdr_dir.join(format!(
        "{RAW_JOURNAL_PREFIX}{}{RAW_JOURNAL_SUFFIX}",
        chrono::Utc::now().date_naive()
    ));
    if today.is_file() {
        std::fs::remove_file(&today).expect("remove today's journal file");
    }
    if !today.exists() {
        std::fs::create_dir(&today).expect("block today's journal path");
    }
}

fn wait_for_stable_call_count(db: &std::path::Path, timeout: Duration) -> i64 {
    let deadline = Instant::now() + timeout;
    let mut last = -1i64;
    let mut stable_reads = 0u32;
    loop {
        let count: i64 = rusqlite::Connection::open(db)
            .expect("db")
            .query_row("SELECT COUNT(*) FROM smdr_call", [], |row| row.get(0))
            .expect("count");
        if count == last {
            stable_reads += 1;
            if stable_reads >= 4 && count >= 1 {
                return count;
            }
        } else {
            last = count;
            stable_reads = 0;
        }
        assert!(
            Instant::now() < deadline,
            "call count never stabilized; last={last}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(target_os = "linux")]
fn task_cpu_time(tid: u64) -> Duration {
    let clk_tck = rustix::param::clock_ticks_per_second();
    let stat = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")).expect("task stat");
    let after = stat.rfind(')').expect("comm") + 2;
    let fields: Vec<&str> = stat[after..].split_whitespace().collect();
    let utime: u64 = fields[11].parse().expect("utime");
    let stime: u64 = fields[12].parse().expect("stime");
    Duration::from_nanos((utime + stime).saturating_mul(1_000_000_000 / clk_tck))
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
fn sim_link_down_clears_on_idle_after_reconnect_without_new_bytes() {
    let h = sim_harness(Duration::from_secs(86_400));
    wait_for(&h.live, Duration::from_secs(3), |s| s.running);
    h.transport.lock().unwrap().drop_link_now();
    wait_for(&h.live, Duration::from_secs(3), |s| s.link_down);
    h.transport.lock().unwrap().reconnect();
    wait_for(&h.live, Duration::from_secs(3), |s| !s.link_down);
}

#[cfg(target_os = "linux")]
#[test]
fn sim_store_ingest_failure_does_not_spin_cpu() {
    use kxprovd::smdr_store::{SMDR_DB_NAME, SMDR_DIR_NAME};

    let h = sim_harness(Duration::from_secs(86_400));
    wait_for(&h.live, Duration::from_secs(3), |s| s.running);
    h.transport
        .lock()
        .unwrap()
        .inject_inbound(kxprovd::test_util::smdr_fixture("outgoing.txt"));
    wait_for(&h.live, Duration::from_secs(3), |s| {
        s.last_byte_at.is_some()
    });

    let smdr_dir = h._tmp.path().join("sim").join(SMDR_DIR_NAME);
    let db = smdr_dir.join(SMDR_DB_NAME);
    let count_before = wait_for_stable_call_count(&db, Duration::from_secs(3));
    assert_eq!(count_before, 1, "outgoing fixture should store one call");

    block_smdr_raw_journals(&smdr_dir);

    h.transport
        .lock()
        .unwrap()
        .inject_inbound(kxprovd::test_util::synthetic_smdr_bytes(43, 1));
    std::thread::sleep(Duration::from_millis(400));
    let count_after: i64 = rusqlite::Connection::open(&db)
        .expect("db")
        .query_row("SELECT COUNT(*) FROM smdr_call", [], |row| row.get(0))
        .expect("count");
    assert_eq!(
        count_after, count_before,
        "store ingest should fail while the journal path is blocked"
    );

    let tid = h._task.reader_linux_tid();
    assert_ne!(tid, 0, "reader thread id not published");
    let cpu0 = task_cpu_time(tid);
    let wall0 = Instant::now();
    std::thread::sleep(Duration::from_millis(800));
    let cpu1 = task_cpu_time(tid);
    let wall = wall0.elapsed();
    let cpu_delta = cpu1.saturating_sub(cpu0);
    assert!(
        cpu_delta < wall / 3,
        "store failure retry used {cpu_delta:?} CPU in {wall:?} wall"
    );
}

#[test]
fn sim_attach_listen_only_leaves_programming_client_logged_in() {
    use kxprovd::transport::SimTransportBridge;
    use kxtd1232::frame::Access;
    use kxtd1232::{Client, Timing};
    use kxtd1232_sim::{SimPbx, SimTransport, PLACEHOLDER_PASSWORD};

    let pbx = Arc::new(Mutex::new(SimPbx::default()));
    let programming = SimTransport::with_shared(Arc::clone(&pbx));
    let mut client = Client::with(programming, Access::ReadWrite, Timing::default());
    client.login(PLACEHOLDER_PASSWORD).expect("login");
    let _smdr = SimTransportBridge::attach_listen_only(Arc::clone(&pbx));
    client
        .read(0x01, 0, 0, 1)
        .expect("programming session survives listen-only SMDR attach");
}

#[cfg(target_os = "linux")]
#[test]
fn serial_missing_device_keeps_link_down_while_reattach_fails() {
    let tmp = tempfile::tempdir().expect("tmp");
    let socket = tmp.path().join("smdr-serial-down.sock");
    let mut cfg = Config::sim_test(tmp.path().to_path_buf(), socket, 1003);
    std::fs::create_dir_all(cfg.data_dir.join("backups")).expect("backups");
    cfg.transport = TransportKind::Serial;
    cfg.sim_pbx = None;
    cfg.serial_device = tmp.path().join("missing-smdr-device");
    let live = Arc::new(SmdrLive::new());
    let port = device_arbiter(&cfg);
    let _task = SmdrReaderTask::spawn(cfg, Arc::clone(&port), Arc::clone(&live));
    wait_for(&live, Duration::from_secs(3), |s| s.running);
    wait_for(&live, Duration::from_secs(3), |s| s.link_down);
    for _ in 0..24 {
        assert!(
            live.snapshot().link_down,
            "link_down must stay true while the serial device is missing"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn sim_idle_loop_does_not_spin_cpu() {
    let h = sim_harness(Duration::from_secs(86_400));
    wait_for(&h.live, Duration::from_secs(3), |s| s.running);
    let tid = h._task.reader_linux_tid();
    assert_ne!(tid, 0, "reader thread id not published");
    let cpu0 = task_cpu_time(tid);
    let wall0 = Instant::now();
    std::thread::sleep(Duration::from_millis(800));
    let cpu1 = task_cpu_time(tid);
    let wall = wall0.elapsed();
    let cpu_delta = cpu1.saturating_sub(cpu0);
    assert!(
        cpu_delta < wall / 3,
        "idle sim reader used {cpu_delta:?} CPU in {wall:?} wall without inbound data"
    );
}

#[test]
fn sim_reader_header_mismatch_observations_reach_live() {
    let h = sim_harness(Duration::from_secs(86_400));
    wait_for(&h.live, Duration::from_secs(3), |s| s.running);

    let changed = SPEC_HEADER.replace("Acc code", "Cost    ");
    assert_eq!(changed.len(), SPEC_HEADER.len());
    let mismatch = format!("{SPEC_HEADER}\r\n{changed}\r\n");
    h.transport
        .lock()
        .unwrap()
        .inject_inbound(mismatch.into_bytes());

    wait_for(&h.live, Duration::from_secs(3), |s| {
        s.header_mismatch_count >= 1 && header_mismatch_active(s)
    });

    h.transport
        .lock()
        .unwrap()
        .inject_inbound(format!("{SPEC_HEADER}\r\n").into_bytes());
    wait_for(&h.live, Duration::from_secs(3), |s| {
        !header_mismatch_active(s)
    });
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
