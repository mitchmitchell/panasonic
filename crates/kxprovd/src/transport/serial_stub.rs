use kxtd1232::{Transport, TransportError};

pub enum SerialTransport {}

impl Transport for SerialTransport {
    fn send(&mut self, _data: &[u8]) -> Result<(), TransportError> {
        match *self {}
    }

    fn recv(&mut self, _timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        match *self {}
    }

    fn now_ms(&mut self) -> u64 {
        match *self {}
    }
}
