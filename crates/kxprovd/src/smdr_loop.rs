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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const HEALTH_TICK: Duration = Duration::from_secs(1);
const POLL_MS: u64 = 50;

pub struct SmdrReaderTask {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl SmdrReaderTask {
    pub fn spawn(config: Config, port: Arc<DeviceArbiter>, live: Arc<SmdrLive>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("smdr-reader".into())
            .spawn(move || run(config, port, live, stop_flag))
            .expect("smdr reader thread");
        Self {
            stop,
            thread: Some(thread),
        }
    }
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
            let Some(pbx) = config.sim_pbx.clone() else {
                tracing::error!("sim transport missing sim_pbx; smdr reader not started");
                return;
            };
            let bridge = SimTransportBridge::new(pbx);
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
                    live.note_bytes(wall());
                    live.note_events(&events);
                    for obs in observations_from_reader(&events) {
                        board.observe(obs, Instant::now(), wall());
                    }
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
                    let obs = match reading {
                        Ok(high) => Observation::ModemStatus(Ok(high)),
                        Err(e) => Observation::ModemStatus(Err(ModemStatusError::from(&e))),
                    };
                    board.observe(obs, Instant::now(), wall());
                }
            }
            board.tick(Instant::now(), wall());
            next_health += HEALTH_TICK;
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
