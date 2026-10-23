//! Linux serial transport via `tokio-serial` (blocking read in the worker task).

use kxtd1232::{LinkDownError, Transport, TransportError};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio_serial::{DataBits, FlowControl, Parity, SerialPortBuilderExt, StopBits};

const SEND_BOUND_MS: u64 = 5_000;

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

    fn send_all(&mut self, data: &[u8]) -> Result<(), TransportError> {
        send_all_port(&mut self.port, data)
    }
}

fn send_all_port<W: Write>(port: &mut W, data: &[u8]) -> Result<(), TransportError> {
    if data.is_empty() {
        return Ok(());
    }
    let deadline = Instant::now() + Duration::from_millis(SEND_BOUND_MS);
    let mut written = 0;
    while written < data.len() {
        if Instant::now() >= deadline {
            return if written == 0 {
                Err(TransportError::NothingWritten(
                    "serial: send timed out with no bytes written".into(),
                ))
            } else {
                Err(TransportError::LinkDown(LinkDownError {
                    detail: format!(
                        "serial: send timed out after {written}/{} bytes",
                        data.len()
                    ),
                    bytes_sent: written,
                }))
            };
        }
        match port.write(&data[written..]) {
            Ok(0) => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(n) => written += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) if written == 0 => return Err(TransportError::NothingWritten(e.to_string())),
            Err(e) => {
                return Err(TransportError::LinkDown(LinkDownError {
                    detail: format!("serial: partial send {written}/{}: {e}", data.len()),
                    bytes_sent: written,
                }));
            }
        }
    }
    Ok(())
}

impl Transport for TokioSerialTransport {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.send_all(data)
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        recv_with_poll(&mut self.port, timeout_ms)
    }

    fn now_ms(&mut self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// Shared recv loop: `WouldBlock` means no data yet (wait, do not drop the link).
pub(crate) fn recv_with_poll<R: Read>(
    port: &mut R,
    timeout_ms: u64,
) -> Result<Vec<u8>, TransportError> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut buf = [0u8; 256];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(TransportError::Timeout);
        }
        let remaining = deadline.saturating_duration_since(now);
        match port.read(&mut buf) {
            Ok(0) => {
                std::thread::sleep(Duration::from_millis(5).min(remaining));
            }
            Ok(n) => return Ok(buf[..n].to_vec()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5).min(remaining));
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                return Err(TransportError::Timeout);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(TransportError::LinkDown(LinkDownError {
                    detail: e.to_string(),
                    bytes_sent: 0,
                }))
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::{ErrorKind, Read, Write};
    use std::sync::{Arc, Mutex};

    struct MockPort {
        read_plan: Arc<Mutex<Vec<std::io::Result<usize>>>>,
    }

    impl Read for MockPort {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut plan = self.read_plan.lock().unwrap();
            let step = plan.remove(0);
            match step {
                Ok(0) => Err(ErrorKind::WouldBlock.into()),
                Ok(n) => {
                    buf[0] = b'X';
                    Ok(n.min(1))
                }
                Err(e) => Err(e),
            }
        }
    }

    struct BlockThenWrite {
        blocks: u32,
    }

    impl Write for BlockThenWrite {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.blocks > 0 {
                self.blocks -= 1;
                return Err(ErrorKind::WouldBlock.into());
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn would_block_then_byte_is_not_link_down() {
        let read_plan = Arc::new(Mutex::new(vec![Err(ErrorKind::WouldBlock.into()), Ok(1)]));
        let mut port = MockPort {
            read_plan: Arc::clone(&read_plan),
        };
        let out = recv_with_poll(&mut port, 100).expect("recv succeeds after WouldBlock");
        assert_eq!(out, b"X");
    }

    #[test]
    fn would_block_on_send_retries_until_complete() {
        let mut port = BlockThenWrite { blocks: 2 };
        send_all_port(&mut port, &[1, 2, 3]).expect("send completes after WouldBlock retries");
    }

    #[test]
    fn send_zero_bytes_is_nothing_written() {
        struct ZeroWrite;
        impl Write for ZeroWrite {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Ok(0)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut zw = ZeroWrite;
        let err = send_all_port(&mut zw, &[0x01, 0x02]);
        assert!(matches!(err, Err(TransportError::NothingWritten(_))));
    }
}
