use crate::smdr_store::{IngestOutcome, SmdrStore, SmdrStoreError};
use chrono::{DateTime, Utc};
use kxtd1232::smdr::{LineKind, LineSplitter, SmdrLine};
use kxtd1232::{Transport, TransportError};

pub trait SmdrSource {
    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError>;
}

pub struct ReceiveOnly<T: Transport>(T);

impl<T: Transport> ReceiveOnly<T> {
    pub fn new(transport: T) -> Self {
        Self(transport)
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: Transport> SmdrSource for ReceiveOnly<T> {
    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        self.0.recv(timeout_ms)
    }
}

pub trait SmdrSink {
    fn ingest(
        &mut self,
        line: SmdrLine,
        rx: DateTime<Utc>,
    ) -> Result<IngestOutcome, SmdrStoreError>;
}

impl SmdrSink for SmdrStore {
    fn ingest(
        &mut self,
        line: SmdrLine,
        rx: DateTime<Utc>,
    ) -> Result<IngestOutcome, SmdrStoreError> {
        SmdrStore::ingest(self, line, rx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReaderEvent {
    Ingested(IngestOutcome),
    HeaderMismatch { rx: DateTime<Utc>, raw: String },
    Idle,
}

#[derive(Debug, thiserror::Error)]
pub enum ReaderError {
    #[error("smdr link down: {0:?}")]
    LinkDown(TransportError),
    #[error(transparent)]
    Store(#[from] SmdrStoreError),
}

pub struct SmdrReader<S: SmdrSource> {
    source: S,
    splitter: LineSplitter,
}

impl<S: SmdrSource> SmdrReader<S> {
    pub fn new(source: S) -> Self {
        Self {
            source,
            splitter: LineSplitter::new(),
        }
    }

    pub fn into_source(self) -> S {
        self.source
    }

    pub fn poll_once<K: SmdrSink>(
        &mut self,
        sink: &mut K,
        timeout_ms: u64,
        now: impl Fn() -> DateTime<Utc>,
    ) -> Result<Vec<ReaderEvent>, ReaderError> {
        let bytes = match self.source.recv(timeout_ms) {
            Ok(b) => b,
            Err(TransportError::Timeout) => return Ok(vec![ReaderEvent::Idle]),
            Err(e) => return Err(ReaderError::LinkDown(e)),
        };
        let lines = self.splitter.push(&bytes);
        self.deliver(sink, lines, now)
    }

    pub fn finish<K: SmdrSink>(
        &mut self,
        sink: &mut K,
        now: impl Fn() -> DateTime<Utc>,
    ) -> Result<Vec<ReaderEvent>, ReaderError> {
        let lines = self.splitter.finish().into_iter().collect();
        self.deliver(sink, lines, now)
    }

    fn deliver<K: SmdrSink>(
        &mut self,
        sink: &mut K,
        lines: Vec<SmdrLine>,
        now: impl Fn() -> DateTime<Utc>,
    ) -> Result<Vec<ReaderEvent>, ReaderError> {
        let mut events = Vec::with_capacity(lines.len());
        for line in lines {
            let rx = now();
            let mismatch = (line.kind() == LineKind::Header && !line.header_matches_spec())
                .then(|| line.raw().to_string());
            events.push(ReaderEvent::Ingested(sink.ingest(line, rx)?));
            if let Some(raw) = mismatch {
                events.push(ReaderEvent::HeaderMismatch { rx, raw });
            }
        }
        Ok(events)
    }
}

#[cfg(target_os = "linux")]
pub struct DeviceSmdrSource {
    file: std::fs::File,
}

#[cfg(target_os = "linux")]
impl DeviceSmdrSource {
    pub const BAUD: nix::sys::termios::BaudRate = nix::sys::termios::BaudRate::B9600;

    pub fn open(path: &std::path::Path) -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .custom_flags(nix::libc::O_NOCTTY | nix::libc::O_NONBLOCK)
            .open(path)?;
        if nix::unistd::isatty(std::os::fd::AsRawFd::as_raw_fd(&file)).unwrap_or(false) {
            use nix::sys::termios::{self, ControlFlags, SetArg};
            let mut t = termios::tcgetattr(&file)?;
            termios::cfmakeraw(&mut t);
            termios::cfsetspeed(&mut t, Self::BAUD)?;
            t.control_flags &= !(ControlFlags::PARENB | ControlFlags::CSTOPB);
            t.control_flags |= ControlFlags::CS8 | ControlFlags::CREAD | ControlFlags::CLOCAL;
            termios::tcsetattr(&file, SetArg::TCSANOW, &t)?;
        }
        Ok(Self { file })
    }

    pub fn is_read_only(&self) -> bool {
        nix::fcntl::fcntl(
            std::os::fd::AsRawFd::as_raw_fd(&self.file),
            nix::fcntl::FcntlArg::F_GETFL,
        )
        .map(|fl| fl & nix::libc::O_ACCMODE == nix::libc::O_RDONLY)
        .unwrap_or(false)
    }
}

#[cfg(target_os = "linux")]
impl SmdrSource for DeviceSmdrSource {
    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        crate::transport::recv_with_poll(&mut self.file, timeout_ms)
    }
}
