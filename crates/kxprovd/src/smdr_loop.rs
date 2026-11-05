//! Daemon SMDR reader: S4 ingest, S6 publish, and S7 health under the port arbiter.

use crate::config::{Config, TransportKind};
use crate::port::device::{self, SmdrLineOptions};
use crate::port::{DeviceArbiter, PortMode};
use crate::smdr_bus::{PublishingSink, SmdrLive};
use crate::smdr_health::{
    observations_from_reader, ByteTap, HealthBoard, ModemStatusError, Observation, PortState,
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
        Device(SmdrReader<ByteTap<device::SmdrDeviceHandle>>),
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
                let handle = match port
                    .open_smdr_device(&config.serial_device, SmdrLineOptions::default())
                {
                    Ok(h) => h,
                    Err(e) => {
                        tracing::error!(
                            device = %config.serial_device.display(),
                            error = %e,
                            "smdr device open failed; reader not started"
                        );
                        return;
                    }
                };
                let (tap, bytes) = ByteTap::new(handle);
                let board = HealthBoard::new(health_cfg, Arc::clone(&live), bytes);
                (Source::Device(SmdrReader::new(tap)), board)
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
                SimTransportBridge::new(pbx)
            };
            #[cfg(not(feature = "test-util"))]
            let bridge = {
                let Some(pbx) = config.sim_pbx.clone() else {
                    tracing::error!("sim transport missing sim_pbx; smdr reader not started");
                    return;
                };
                SimTransportBridge::new(pbx)
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
            Source::Device(r) => r.poll_once(&mut sink, timeout_ms, wall),
            Source::Sim(r) => r.poll_once(&mut sink, timeout_ms, wall),
        };

        match poll_result {
            Ok(events) => {
                if events != [ReaderEvent::Idle] {
                    live.set_link_down(false);
                }
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
            Err(ReaderError::LinkDown(_)) => live.set_link_down(true),
            Err(ReaderError::Store(e)) => {
                tracing::warn!(error = %e, "smdr store ingest failed; retrying");
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
}
