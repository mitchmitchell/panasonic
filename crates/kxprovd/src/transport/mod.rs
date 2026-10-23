#[cfg(target_os = "linux")]
mod serial;
#[cfg(not(target_os = "linux"))]
mod serial_stub;
mod sim;

pub use sim::SimTransportBridge;

#[cfg(target_os = "linux")]
pub use serial::TokioSerialTransport;

#[cfg(not(target_os = "linux"))]
pub use serial_stub::TokioSerialTransport;

use crate::config::TransportKind;
use kxtd1232::Transport;

pub fn open_sim() -> SimTransportBridge {
    SimTransportBridge::new()
}

pub enum AnyTransport {
    Sim(Box<SimTransportBridge>),
    Serial(TokioSerialTransport),
}

impl Transport for AnyTransport {
    fn send(&mut self, data: &[u8]) -> Result<(), kxtd1232::TransportError> {
        match self {
            Self::Sim(t) => t.as_mut().send(data),
            Self::Serial(t) => t.send(data),
        }
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, kxtd1232::TransportError> {
        match self {
            Self::Sim(t) => t.as_mut().recv(timeout_ms),
            Self::Serial(t) => t.recv(timeout_ms),
        }
    }

    fn now_ms(&mut self) -> u64 {
        match self {
            Self::Sim(t) => t.as_mut().now_ms(),
            Self::Serial(t) => t.now_ms(),
        }
    }
}

pub fn open(kind: TransportKind, device: &std::path::Path) -> Result<AnyTransport, String> {
    match kind {
        TransportKind::Sim => Ok(AnyTransport::Sim(Box::new(open_sim()))),
        TransportKind::Serial => TokioSerialTransport::open(device).map(AnyTransport::Serial),
    }
}
