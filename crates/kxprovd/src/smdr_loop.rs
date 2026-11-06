//! Daemon SMDR reader: S4 ingest, S6 publish, and S7 health under the port arbiter.

use crate::config::{Config, TransportKind};
use crate::port::device::{self, SmdrLineOptions};
use crate::port::{DeviceArbiter, PortMode};
use crate::smdr_bus::{PublishingSink, SmdrLive};
use crate::smdr_health::{
    observations_from_reader, ByteCounter, ByteTap, HealthBoard, ModemStatusError, Observation,
    PortState,
};
use crate::smdr_reader::{ReaderError, ReaderEvent, ReceiveOnly, SmdrReader};
use crate::smdr_store::{backup_sets, SmdrStore};
use crate::transport::SimTransportBridge;
use chrono::Utc;
use kxtd1232::smdr::DateOrder;
#[cfg(feature = "test-util")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const HEALTH_TICK: Duration = Duration::from_secs(1);
const POLL_MS: u64 = 50;

pub struct SmdrReaderTask {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    #[cfg(feature = "test-util")]
    reader_linux_tid: Arc<AtomicU64>,
}

impl SmdrReaderTask {
    pub fn spawn(config: Config, port: Arc<DeviceArbiter>, live: Arc<SmdrLive>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        #[cfg(feature = "test-util")]
        let reader_linux_tid = Arc::new(AtomicU64::new(0));
        #[cfg(feature = "test-util")]
        let tid_slot = Arc::clone(&reader_linux_tid);
        let thread = std::thread::Builder::new()
            .name("smdr-reader".into())
            .spawn(move || {
                #[cfg(all(feature = "test-util", target_os = "linux"))]
                tid_slot.store(linux_thread_id(), Ordering::Relaxed);
                run(config, port, live, stop_flag)
            })
            .expect("smdr reader thread");
        Self {
            stop,
            thread: Some(thread),
            #[cfg(feature = "test-util")]
            reader_linux_tid,
        }
    }

    #[cfg(all(feature = "test-util", target_os = "linux"))]
    pub fn reader_linux_tid(&self) -> u64 {
        self.reader_linux_tid.load(Ordering::Relaxed)
    }
}

#[cfg(all(feature = "test-util", target_os = "linux"))]
fn linux_thread_id() -> u64 {
    std::fs::read_link("/proc/thread-self")
        .ok()
        .and_then(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(0)
}

impl Drop for SmdrReaderTask {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                tracing::warn!("smdr reader thread panicked on shutdown");
            }
        }
    }
}

fn run(config: Config, port: Arc<DeviceArbiter>, live: Arc<SmdrLive>, stop: Arc<AtomicBool>) {
    if !config.smdr.enabled {
        return;
    }
    let backup_paths = backup_sets(&config);
    let backups: Vec<_> = backup_paths.iter().map(|p| p.as_path()).collect();
    let store = match SmdrStore::open(&config.data_dir, &backups, DateOrder::Mdy) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "smdr store open failed; reader not started");
            return;
        }
    };
    let mut sink = PublishingSink::new(store, Arc::clone(&live));
    let health_cfg = config.smdr_health;

    enum Source {
        #[cfg(target_os = "linux")]
        Device(Option<SmdrReader<ByteTap<device::SmdrDeviceHandle>>>),
        Sim(SmdrReader<ByteTap<ReceiveOnly<SimTransportBridge>>>),
    }

    let (mut reader, mut board) = match config.transport {
        TransportKind::Serial => {
            #[cfg(not(target_os = "linux"))]
            {
                tracing::error!("serial smdr reader requires Linux");
                return;
            }
            #[cfg(target_os = "linux")]
            {
                let (device, board) = match open_serial_reader(&port, &config.serial_device) {
                    Some((reader, bytes)) => (
                        Some(reader),
                        HealthBoard::new(health_cfg, Arc::clone(&live), bytes),
                    ),
                    None => (
                        None,
                        HealthBoard::new(health_cfg, Arc::clone(&live), ByteCounter::default()),
                    ),
                };
                (Source::Device(device), board)
            }
        }
        TransportKind::Sim => {
            #[cfg(feature = "test-util")]
            let bridge = if let Some(shared) = &config.sim_smdr_transport {
                SimTransportBridge::with_shared_transport(Arc::clone(shared))
            } else {
                let Some(pbx) = config.sim_pbx.clone() else {
                    tracing::error!("sim transport missing sim_pbx; smdr reader not started");
                    return;
                };
                SimTransportBridge::attach_listen_only(pbx)
            };
            #[cfg(not(feature = "test-util"))]
            let bridge = {
                let Some(pbx) = config.sim_pbx.clone() else {
                    tracing::error!("sim transport missing sim_pbx; smdr reader not started");
                    return;
                };
                SimTransportBridge::attach_listen_only(pbx)
            };
            let (tap, bytes) = ByteTap::new(ReceiveOnly::new(bridge));
            let board = HealthBoard::new(health_cfg, Arc::clone(&live), bytes);
            (Source::Sim(SmdrReader::new(tap)), board)
        }
    };

    live.set_running(true);
    live.set_link_down(false);
    let started = Instant::now();
    let wall = Utc::now;
    let mut current_port = arbiter_port_state(&port);
    board.observe(Observation::Port(current_port), started, wall());
    let mut next_health = started + HEALTH_TICK;

    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        let timeout_ms = if now >= next_health {
            0
        } else {
            let until_health = next_health.saturating_duration_since(now);
            let poll = Duration::from_millis(POLL_MS);
            u64::try_from(poll.min(until_health).as_millis())
                .unwrap_or(POLL_MS)
                .max(1)
        };

        let poll_result = match &mut reader {
            #[cfg(target_os = "linux")]
            Source::Device(slot) => match slot {
                Some(r) => r.poll_once(&mut sink, timeout_ms, wall),
                None => try_attach_serial_reader(
                    &port,
                    &config.serial_device,
                    health_cfg,
                    Arc::clone(&live),
                    slot,
                    &mut board,
                    timeout_ms,
                ),
            },
            Source::Sim(r) => r.poll_once(&mut sink, timeout_ms, wall),
        };

        match poll_result {
            Ok(events) => {
                live.set_link_down(false);
                if board.byte_tap_has_pending() {
                    live.note_bytes(wall());
                }
                live.note_events(&events);
                for obs in observations_from_reader(&events) {
                    board.observe(obs, Instant::now(), wall());
                }
                if config.transport == TransportKind::Sim && events == [ReaderEvent::Idle] {
                    std::thread::sleep(Duration::from_millis(timeout_ms));
                }
            }
            Err(ReaderError::LinkDown(_)) => {
                live.set_link_down(true);
                #[cfg(target_os = "linux")]
                if let Source::Device(slot) = &mut reader {
                    if let Some(r) = slot.take() {
                        detach_serial_reader(&port, r);
                    }
                }
            }
            Err(ReaderError::Store(e)) => {
                tracing::warn!(error = %e, "smdr store ingest failed; retrying");
                std::thread::sleep(Duration::from_millis(timeout_ms));
            }
        }

        let mode = arbiter_port_state(&port);
        if mode != current_port {
            current_port = mode;
            board.observe(Observation::Port(current_port), Instant::now(), wall());
        }

        if Instant::now() >= next_health {
            if config.transport == TransportKind::Serial {
                #[cfg(target_os = "linux")]
                if let Some(reading) = port.read_smdr_modem_cts() {
                    board.observe(modem_status_observation(reading), Instant::now(), wall());
                }
            }
            board.tick(Instant::now(), wall());
            next_health = Instant::now() + HEALTH_TICK;
        }
    }

    live.set_running(false);
}

#[cfg(target_os = "linux")]
fn open_serial_reader(
    port: &DeviceArbiter,
    path: &std::path::Path,
) -> Option<(SmdrReader<ByteTap<device::SmdrDeviceHandle>>, ByteCounter)> {
    let handle = port
        .open_smdr_device(path, SmdrLineOptions::default())
        .map_err(|e| {
            tracing::warn!(
                device = %path.display(),
                error = %e,
                "smdr device open failed; will retry"
            );
        })
        .ok()?;
    let (tap, bytes) = ByteTap::new(handle);
    Some((SmdrReader::new(tap), bytes))
}

#[cfg(target_os = "linux")]
fn detach_serial_reader(
    port: &DeviceArbiter,
    reader: SmdrReader<ByteTap<device::SmdrDeviceHandle>>,
) {
    drop(reader.into_source().into_inner());
    port.clear_smdr_device();
}

#[cfg(target_os = "linux")]
fn try_attach_serial_reader(
    port: &DeviceArbiter,
    path: &std::path::Path,
    health_cfg: crate::smdr_health::HealthConfig,
    live: Arc<SmdrLive>,
    slot: &mut Option<SmdrReader<ByteTap<device::SmdrDeviceHandle>>>,
    board: &mut HealthBoard,
    wait_ms: u64,
) -> Result<Vec<ReaderEvent>, ReaderError> {
    if let Some((reader, bytes)) = open_serial_reader(port, path) {
        *board = HealthBoard::new(health_cfg, live, bytes);
        *slot = Some(reader);
        Ok(vec![ReaderEvent::Idle])
    } else {
        std::thread::sleep(Duration::from_millis(wait_ms));
        Ok(vec![ReaderEvent::Idle])
    }
}

fn arbiter_port_state(port: &DeviceArbiter) -> PortState {
    match port.mode() {
        PortMode::Smdr => PortState::Smdr,
        PortMode::Programming => PortState::Programming,
    }
}

fn modem_status_observation(reading: Result<bool, std::io::Error>) -> Observation {
    match reading {
        Ok(high) => Observation::ModemStatus(Ok(high)),
        Err(e) => Observation::ModemStatus(Err(ModemStatusError::from(&e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smdr_health::Observation;

    #[test]
    fn modem_status_observation_passes_cts_polarity_through() {
        assert_eq!(
            modem_status_observation(Ok(true)),
            Observation::ModemStatus(Ok(true))
        );
        assert_eq!(
            modem_status_observation(Ok(false)),
            Observation::ModemStatus(Ok(false))
        );
    }

    #[test]
    fn modem_status_observation_maps_io_error() {
        let err = std::io::Error::other("probe");
        match modem_status_observation(Err(err)) {
            Observation::ModemStatus(Err(e)) => assert_eq!(e.kind, std::io::ErrorKind::Other),
            other => panic!("expected modem error observation, got {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    mod serial_reopen {
        use super::*;
        use crate::port::device::SmdrLineOptions;
        use crate::port::journal::LeaseJournal;
        use crate::port::DeviceArbiter;
        use crate::smdr_reader::{SmdrReader, SmdrSource};
        use nix::pty::openpty;
        use nix::sys::termios::{self, InputFlags, LocalFlags, SetArg};
        use nix::unistd::ttyname;
        use std::io::Write;

        fn pty() -> Result<(std::fs::File, std::path::PathBuf), nix::errno::Errno> {
            let p = openpty(None, None)?;
            let path = ttyname(&p.slave)?;
            let mut t = termios::tcgetattr(&p.slave)?;
            t.input_flags |= InputFlags::IXON | InputFlags::IXOFF | InputFlags::IXANY;
            t.local_flags |= LocalFlags::ECHO | LocalFlags::ICANON | LocalFlags::ECHOE;
            termios::tcsetattr(&p.slave, SetArg::TCSANOW, &t)?;
            Ok((std::fs::File::from(p.master), path))
        }

        #[test]
        fn detach_clears_the_arbiter_slot_for_listen_only_reopen() {
            let (mut master, path) = pty().expect("serial reopen regression PTY fixture");
            let journal = LeaseJournal::new(
                std::env::temp_dir()
                    .join(format!("kxprovd-smdr-reopen-{}.jsonl", std::process::id())),
            );
            let port = DeviceArbiter::new((), journal, 1);
            let (tap, _bytes) = ByteTap::new(
                port.open_smdr_device(&path, SmdrLineOptions::default())
                    .expect("first open"),
            );
            let reader = SmdrReader::new(tap);
            detach_serial_reader(&port, reader);
            let mut reopened = port
                .open_smdr_device(&path, SmdrLineOptions::default())
                .expect("reopen after detach");
            master
                .write_all(b"10/30/26 05:48PM 101\r\n")
                .expect("write");
            let got = reopened.recv(1000).expect("read after reopen");
            assert!(got.starts_with(b"10/30/26"), "{got:?}");
        }
    }
}
