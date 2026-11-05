use kxtd1232::{Transport, TransportError};
use kxtd1232_sim::SimTransport;
use std::sync::{Arc, Mutex};

/// Virtual-time bridge for the in-process simulator (`inprocess-sim` feature).
pub struct SimTransportBridge {
    inner: Arc<Mutex<SimTransport>>,
}

impl SimTransportBridge {
    pub fn new(shared_pbx: Arc<Mutex<kxtd1232_sim::SimPbx>>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SimTransport::with_shared(shared_pbx))),
        }
    }

    /// Shares an existing sim transport (integration tests only).
    #[cfg(feature = "test-util")]
    pub fn with_shared_transport(inner: Arc<Mutex<SimTransport>>) -> Self {
        Self { inner }
    }

    /// Vendor `.DBH` header tail (0x1E–0xFF) from the in-process sim upload image.
    pub fn dbh_upload_header_tail(&self) -> [u8; crate::dbh::HEADER_TAIL_LEN] {
        let guard = self.inner.lock().expect("sim transport lock");
        let sim_guard = guard.sim();
        let src = sim_guard.dbh_header_tail();
        let mut out = [0u8; crate::dbh::HEADER_TAIL_LEN];
        out.copy_from_slice(src);
        out
    }
}

impl Transport for SimTransportBridge {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.inner.lock().expect("sim transport lock").send(data)
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        self.inner
            .lock()
            .expect("sim transport lock")
            .recv(timeout_ms)
    }

    fn now_ms(&mut self) -> u64 {
        self.inner.lock().expect("sim transport lock").now_ms()
    }

    fn cycle_dtr(&mut self) -> Result<bool, TransportError> {
        self.inner.lock().expect("sim transport lock").cycle_dtr()
    }

    fn modem_lines(&mut self) -> kxtd1232::ModemLines {
        self.inner.lock().expect("sim transport lock").modem_lines()
    }
}
