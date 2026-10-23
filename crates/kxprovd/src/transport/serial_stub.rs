//! Non-Linux stub: serial is unavailable in CI/dev on non-Linux hosts.

use kxtd1232::{Transport, TransportError};
use std::path::Path;

pub struct TokioSerialTransport;

impl TokioSerialTransport {
    pub fn open(_path: &Path) -> Result<Self, String> {
        Err("serial transport requires Linux".into())
    }
}

impl Transport for TokioSerialTransport {
    fn send(&mut self, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::LinkDown("no serial".into()))
    }

    fn recv(&mut self, _timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        Err(TransportError::LinkDown("no serial".into()))
    }

    fn now_ms(&mut self) -> u64 {
        0
    }
}
