//! Linux serial transport via `tokio-serial` (blocking read in the worker task).

use kxtd1232::{SendError, Transport, TransportError};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio_serial::{DataBits, FlowControl, Parity, SerialPortBuilderExt, StopBits};

pub struct TokioSerialTransport {
    port: tokio_serial::SerialStream,
}

impl TokioSerialTransport {
    pub fn open(path: &Path, baud: u32) -> Result<Self, String> {
        let path = path.to_string_lossy();
        let port = tokio_serial::new(path.as_ref(), baud)
            .data_bits(DataBits::Eight)
            .parity(Parity::None)
            .stop_bits(StopBits::One)
            .flow_control(FlowControl::None)
            .exclusive(true)
            .open_native_async()
            .map_err(|e| e.to_string())?;
        Ok(Self { port })
    }
}

impl Transport for TokioSerialTransport {
    fn send(&mut self, data: &[u8]) -> Result<usize, SendError> {
        if data.is_empty() {
            return Ok(0);
        }
        let mut written = 0;
        while written < data.len() {
            match self.port.write(&data[written..]) {
                Ok(0) => {
                    return if written == 0 {
                        Err(SendError::NothingWritten)
                    } else {
                        Err(SendError::Partial { written })
                    };
                }
                Ok(n) => written += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if written == 0 => return Err(SendError::LinkDown(e.to_string())),
                Err(_) => return Err(SendError::Partial { written }),
            }
        }
        Ok(written)
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let mut buf = [0u8; 256];
        loop {
            if Instant::now() >= deadline {
                return Err(TransportError::Timeout);
            }
            match self.port.read(&mut buf) {
                Ok(0) => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(n) => return Ok(buf[..n].to_vec()),
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    return Err(TransportError::Timeout);
                }
                Err(e) => return Err(TransportError::LinkDown(e.to_string())),
            }
        }
    }

    fn now_ms(&mut self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}
