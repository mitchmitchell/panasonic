//! Linux serial transport via `tokio-serial` (blocking read in the worker task).

use kxtd1232::{LineLevel, ModemLines};
use kxtd1232::{LinkDownError, Transport, TransportError};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio_serial::{DataBits, FlowControl, Parity, SerialPort, SerialPortBuilderExt, StopBits};

const DTR_DROP_MS: u64 = 250;

pub struct TokioSerialTransport {
    port: tokio_serial::SerialStream,
    send_bound_ms: u64,
}

impl TokioSerialTransport {
    pub fn open(path: &Path, baud: u32, send_bound_ms: u64) -> Result<Self, String> {
        let holders = port_holders(Path::new("/proc"), path, std::process::id())
            .map_err(|e| format!("serial: cannot check {} holders: {e}", path.display()))?;
        if !holders.is_empty() {
            return Err(format!(
                "serial: {} is held by pid {holders:?}",
                path.display()
            ));
        }
        let path = path.to_string_lossy();
        let port = tokio_serial::new(path.as_ref(), baud)
            .data_bits(DataBits::Eight)
            .parity(Parity::None)
            .stop_bits(StopBits::One)
            .flow_control(FlowControl::None)
            .exclusive(true)
            .open_native_async()
            .map_err(|e| e.to_string())?;
        if !port.exclusive() {
            return Err("serial: exclusive open (TIOCEXCL and flock) not in effect".into());
        }
        Ok(Self {
            port,
            send_bound_ms,
        })
    }

    fn line_error(e: tokio_serial::Error) -> TransportError {
        TransportError::LinkDown(LinkDownError {
            detail: format!("serial: modem line: {e}"),
            bytes_sent: Some(0),
        })
    }

    fn send_all(&mut self, data: &[u8]) -> Result<(), TransportError> {
        send_all_port(&mut self.port, data, self.send_bound_ms)
    }
}

pub(crate) fn send_all_port<W: Write>(
    port: &mut W,
    data: &[u8],
    send_bound_ms: u64,
) -> Result<(), TransportError> {
    if data.is_empty() {
        return Ok(());
    }
    let deadline = Instant::now() + Duration::from_millis(send_bound_ms);
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
                    bytes_sent: Some(written),
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
                    bytes_sent: Some(written),
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

    fn cycle_dtr(&mut self) -> Result<bool, TransportError> {
        cycle_dtr_port(&mut self.port, DTR_DROP_MS).map_err(Self::line_error)?;
        Ok(true)
    }

    fn modem_lines(&mut self) -> ModemLines {
        ModemLines {
            dsr: LineLevel::from_read(self.port.read_data_set_ready()),
            cts: LineLevel::from_read(self.port.read_clear_to_send()),
            dcd: LineLevel::from_read(self.port.read_carrier_detect()),
        }
    }
}

pub(crate) trait DtrPort {
    fn set_dtr(&mut self, level: bool) -> tokio_serial::Result<()>;
    fn flush_input(&mut self) -> tokio_serial::Result<()>;
}

impl DtrPort for tokio_serial::SerialStream {
    fn set_dtr(&mut self, level: bool) -> tokio_serial::Result<()> {
        self.write_data_terminal_ready(level)
    }

    fn flush_input(&mut self) -> tokio_serial::Result<()> {
        self.clear(tokio_serial::ClearBuffer::Input)
    }
}

pub(crate) fn cycle_dtr_port<P: DtrPort>(port: &mut P, hold_ms: u64) -> tokio_serial::Result<()> {
    port.set_dtr(false)?;
    std::thread::sleep(Duration::from_millis(hold_ms));
    port.flush_input()?;
    port.set_dtr(true)
}

pub(crate) fn port_holders(
    proc_root: &Path,
    device: &Path,
    own_pid: u32,
) -> std::io::Result<Vec<u32>> {
    let meta = std::fs::metadata(device)?;
    let target = meta.file_type().is_char_device().then(|| meta.rdev());
    let canonical = std::fs::canonicalize(device)?;
    let mut holders = Vec::new();
    for entry in std::fs::read_dir(proc_root)?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == own_pid {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        let held = fds.flatten().any(|fd| {
            let path = fd.path();
            let by_link = std::fs::read_link(&path).is_ok_and(|l| l == canonical);
            let by_rdev = target.is_some_and(|rdev| {
                std::fs::metadata(&path)
                    .is_ok_and(|m| m.file_type().is_char_device() && m.rdev() == rdev)
            });
            by_link || by_rdev
        });
        if held {
            holders.push(pid);
        }
    }
    holders.sort_unstable();
    Ok(holders)
}

/// Shared recv loop: `WouldBlock` means no data yet (wait, do not drop the link).
pub(crate) fn recv_with_poll<R: Read>(
    port: &mut R,
    timeout_ms: u64,
) -> Result<Vec<u8>, TransportError> {
    let deadline = Instant::now().checked_add(Duration::from_millis(timeout_ms));
    let mut buf = [0u8; 256];
    loop {
        let now = Instant::now();
        let remaining = deadline.map_or(Duration::MAX, |d| d.saturating_duration_since(now));
        if remaining.is_zero() {
            return Err(TransportError::Timeout);
        }
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
                    bytes_sent: None,
                }))
            }
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "a failed test setup step should panic the test"
)]
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

    #[derive(Default)]
    struct RecordingPort {
        ops: Vec<&'static str>,
        fail_flush: bool,
    }

    impl DtrPort for RecordingPort {
        fn set_dtr(&mut self, level: bool) -> tokio_serial::Result<()> {
            self.ops.push(if level { "dtr_high" } else { "dtr_low" });
            Ok(())
        }

        fn flush_input(&mut self) -> tokio_serial::Result<()> {
            self.ops.push("tcflush_input");
            if self.fail_flush {
                return Err(tokio_serial::Error::new(
                    tokio_serial::ErrorKind::Unknown,
                    "flush failed",
                ));
            }
            Ok(())
        }
    }

    #[test]
    fn dtr_cycle_flushes_input_before_dtr_rises() {
        let mut port = RecordingPort::default();
        cycle_dtr_port(&mut port, 0).unwrap();
        assert_eq!(port.ops, ["dtr_low", "tcflush_input", "dtr_high"]);
    }

    #[test]
    fn dtr_cycle_reports_a_failed_flush() {
        let mut port = RecordingPort {
            fail_flush: true,
            ..RecordingPort::default()
        };
        assert!(cycle_dtr_port(&mut port, 0).is_err());
        assert_eq!(port.ops, ["dtr_low", "tcflush_input"]);
    }

    #[test]
    fn port_holders_finds_other_pids_and_skips_self() {
        let dir = tempfile::tempdir().unwrap();
        let device = dir.path().join("ttyFAKE");
        std::fs::write(&device, b"").unwrap();
        let canonical = std::fs::canonicalize(&device).unwrap();
        let proc_root = dir.path().join("proc");
        for (pid, link) in [(10u32, true), (11, false), (12, true)] {
            let fd_dir = proc_root.join(pid.to_string()).join("fd");
            std::fs::create_dir_all(&fd_dir).unwrap();
            let other = dir.path().join(format!("other{pid}"));
            std::fs::write(&other, b"").unwrap();
            std::os::unix::fs::symlink(&other, fd_dir.join("0")).unwrap();
            if link {
                std::os::unix::fs::symlink(&canonical, fd_dir.join("3")).unwrap();
            }
        }
        std::fs::create_dir_all(proc_root.join("self")).unwrap();
        assert_eq!(port_holders(&proc_root, &device, 12).unwrap(), vec![10]);
        assert_eq!(port_holders(&proc_root, &device, 99).unwrap(), vec![10, 12]);
    }

    #[test]
    fn port_holders_is_empty_when_nobody_has_the_device() {
        let dir = tempfile::tempdir().unwrap();
        let device = dir.path().join("ttyFAKE");
        std::fs::write(&device, b"").unwrap();
        std::fs::create_dir_all(dir.path().join("proc/7/fd")).unwrap();
        assert!(port_holders(&dir.path().join("proc"), &device, 1)
            .unwrap()
            .is_empty());
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
    fn a_wait_forever_timeout_does_not_overflow_the_deadline() {
        let read_plan = Arc::new(Mutex::new(vec![Err(ErrorKind::WouldBlock.into()), Ok(1)]));
        let mut port = MockPort {
            read_plan: Arc::clone(&read_plan),
        };
        let out = recv_with_poll(&mut port, u64::MAX).expect("u64::MAX timeout reads a byte");
        assert_eq!(out, b"X");
    }

    #[test]
    fn would_block_on_send_retries_until_complete() {
        let mut port = BlockThenWrite { blocks: 2 };
        send_all_port(&mut port, &[1, 2, 3], 5_000)
            .expect("send completes after WouldBlock retries");
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
        let err = send_all_port(&mut zw, &[0x01, 0x02], 5_000);
        assert!(matches!(err, Err(TransportError::NothingWritten(_))));
    }
}
