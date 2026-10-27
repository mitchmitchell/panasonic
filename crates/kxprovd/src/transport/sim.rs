use kxtd1232::{Transport, TransportError};
use kxtd1232_sim::SimTransport;
use std::sync::Arc;

/// Virtual-time bridge for the in-process simulator (`inprocess-sim` feature).
pub struct SimTransportBridge {
    inner: SimTransport,
}

impl SimTransportBridge {
    pub fn new(shared_pbx: Arc<std::sync::Mutex<kxtd1232_sim::SimPbx>>) -> Self {
        Self {
            inner: SimTransport::with_shared(shared_pbx),
        }
    }

    /// Vendor `.DBH` header tail (0x1E–0xFF) from the in-process sim upload image.
    pub fn dbh_upload_header_tail(&self) -> [u8; crate::dbh::HEADER_TAIL_LEN] {
        let guard = self.inner.sim();
        let src = guard.dbh_header_tail();
        let mut out = [0u8; crate::dbh::HEADER_TAIL_LEN];
        out.copy_from_slice(src);
        out
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
        self.inner.now_ms()
    }
}
