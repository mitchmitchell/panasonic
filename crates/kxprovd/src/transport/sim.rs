use kxtd1232::{Transport, TransportError};
use kxtd1232_sim::{SimPbx, SimTransport};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Virtual-time bridge for the in-process simulator (Phase A default).
pub struct SimTransportBridge {
    inner: SimTransport,
    start: Instant,
}

impl SimTransportBridge {
    pub fn new() -> Self {
        Self {
            inner: SimTransport::new(SimPbx::default()),
            start: Instant::now(),
        }
    }

    /// Vendor `.DBH` header tail (0x1E–0xFF) from the in-process sim upload image.
    pub fn dbh_upload_header_tail(&self) -> [u8; crate::dbh::HEADER_TAIL_LEN] {
        let src = self.inner.sim.dbh_header_tail();
        let mut out = [0u8; crate::dbh::HEADER_TAIL_LEN];
        out.copy_from_slice(src);
        out
    }
}

impl Default for SimTransportBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for SimTransportBridge {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.inner.send(data)
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        self.inner.recv(timeout_ms)
    }

    fn now_ms(&mut self) -> u64 {
        let _ = &self.start;
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}
