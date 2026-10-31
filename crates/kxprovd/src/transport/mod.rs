#[cfg(target_os = "linux")]
mod serial;
#[cfg(not(target_os = "linux"))]
mod serial_stub;
#[cfg(feature = "inprocess-sim")]
mod sim;

#[cfg(feature = "inprocess-sim")]
pub use sim::SimTransportBridge;

#[cfg(target_os = "linux")]
pub use serial::{open_leased, port_manager, SerialTransport, SHARED_PORT_BAUD};
#[cfg(target_os = "linux")]
pub(crate) use serial::{recv_with_poll, send_all_port};

#[cfg(not(target_os = "linux"))]
pub use serial_stub::SerialTransport;

use crate::config::{Config, TransportKind};
use kxtd1232::frame::Access;
use kxtd1232::{Client, Transport};

pub enum AnyTransport {
    #[cfg(feature = "inprocess-sim")]
    Sim(Box<SimTransportBridge>),
    Serial(Box<SerialTransport>),
}

impl Transport for AnyTransport {
    fn send(&mut self, data: &[u8]) -> Result<(), kxtd1232::TransportError> {
        match self {
            #[cfg(feature = "inprocess-sim")]
            Self::Sim(t) => t.as_mut().send(data),
            Self::Serial(t) => t.send(data),
        }
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, kxtd1232::TransportError> {
        match self {
            #[cfg(feature = "inprocess-sim")]
            Self::Sim(t) => t.as_mut().recv(timeout_ms),
            Self::Serial(t) => t.recv(timeout_ms),
        }
    }

    fn now_ms(&mut self) -> u64 {
        match self {
            #[cfg(feature = "inprocess-sim")]
            Self::Sim(t) => t.as_mut().now_ms(),
            Self::Serial(t) => t.now_ms(),
        }
    }

    fn cycle_dtr(&mut self) -> Result<bool, kxtd1232::TransportError> {
        match self {
            #[cfg(feature = "inprocess-sim")]
            Self::Sim(t) => t.as_mut().cycle_dtr(),
            Self::Serial(t) => t.cycle_dtr(),
        }
    }

    fn modem_lines(&mut self) -> kxtd1232::ModemLines {
        match self {
            #[cfg(feature = "inprocess-sim")]
            Self::Sim(t) => t.as_mut().modem_lines(),
            Self::Serial(t) => t.modem_lines(),
        }
    }
}

pub fn open(config: &Config) -> Result<AnyTransport, String> {
    match config.transport {
        TransportKind::Sim => {
            #[cfg(feature = "inprocess-sim")]
            {
                let pbx = config
                    .sim_pbx
                    .clone()
                    .ok_or_else(|| "sim transport requires sim_pbx".to_string())?;
                Ok(AnyTransport::Sim(Box::new(SimTransportBridge::new(pbx))))
            }
            #[cfg(not(feature = "inprocess-sim"))]
            {
                Err("in-process sim transport not enabled in this build".into())
            }
        }
        TransportKind::Serial => open_serial(config),
    }
}

#[cfg(target_os = "linux")]
fn open_serial(config: &Config) -> Result<AnyTransport, String> {
    open_leased(
        &config.serial_device,
        &config.data_dir.join("port-lease.jsonl"),
        &crate::queue::next_job_id(),
        config.timing.link_baud,
        config.timing.send_bound_ms,
    )
    .map(|t| AnyTransport::Serial(Box::new(t)))
}

#[cfg(not(target_os = "linux"))]
fn open_serial(_config: &Config) -> Result<AnyTransport, String> {
    Err("serial transport requires Linux".into())
}

pub fn login(client: &mut Client<AnyTransport>, password: &str) -> Result<(), kxtd1232::Error> {
    let result = client.login(password);
    if let (Err(e), Some(t)) = (&result, client.login_trace()) {
        tracing::warn!(
            error_kind = e.kind(),
            bytes_received = t.bytes_received,
            xon_seen = t.xon_seen,
            dtr_cycled = t.dtr_cycled,
            wake_sent = t.wake_sent,
            dsr = ?t.lines.dsr,
            cts = ?t.lines.cts,
            dcd = ?t.lines.dcd,
            "login failed"
        );
    }
    result
}

pub fn client(config: &Config, transport: AnyTransport, access: Access) -> Client<AnyTransport> {
    Client::with(transport, access, config.timing).with_signon(config.signon.clone())
}
