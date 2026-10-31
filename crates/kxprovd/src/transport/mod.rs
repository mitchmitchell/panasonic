#[cfg(target_os = "linux")]
mod serial;
#[cfg(not(target_os = "linux"))]
mod serial_stub;
#[cfg(feature = "inprocess-sim")]
mod sim;

#[cfg(feature = "inprocess-sim")]
pub use sim::SimTransportBridge;

#[cfg(target_os = "linux")]
pub use serial::TokioSerialTransport;
#[cfg(target_os = "linux")]
pub(crate) use serial::{recv_with_poll, send_all_port};

#[cfg(not(target_os = "linux"))]
pub use serial_stub::TokioSerialTransport;

use crate::config::{Config, TransportKind};
use kxtd1232::frame::Access;
use kxtd1232::{Client, Transport};

pub enum AnyTransport {
    #[cfg(feature = "inprocess-sim")]
    Sim(Box<SimTransportBridge>),
    Serial(TokioSerialTransport),
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
        TransportKind::Serial => TokioSerialTransport::open(
            &config.serial_device,
            config.timing.link_baud,
            config.timing.send_bound_ms,
        )
        .map(AnyTransport::Serial),
    }
}

pub fn client(config: &Config, transport: AnyTransport, access: Access) -> Client<AnyTransport> {
    Client::with(transport, access, config.timing).with_signon(config.signon.clone())
}
