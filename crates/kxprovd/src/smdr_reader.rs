use crate::smdr_store::{IngestOutcome, SmdrStore, SmdrStoreError};
use chrono::{DateTime, Utc};
use kxtd1232::smdr::{LineKind, LineSplitter, SmdrLine};
use kxtd1232::{Transport, TransportError};
use std::collections::VecDeque;

pub trait SmdrSource {
    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError>;
}

/// ```compile_fail
/// use kxprovd::smdr_reader::ReceiveOnly;
/// use kxtd1232::Transport;
/// fn write<T: Transport>(r: &mut ReceiveOnly<T>) {
///     let _ = r.send(b"x");
/// }
/// ```
///
/// ```
/// use kxprovd::smdr_reader::{ReceiveOnly, SmdrSource};
/// use kxtd1232::Transport;
/// fn read<T: Transport>(r: &mut ReceiveOnly<T>) {
///     let _ = r.recv(1);
/// }
/// ```
pub struct ReceiveOnly<T: Transport>(T);

impl<T: Transport> ReceiveOnly<T> {
    pub fn new(transport: T) -> Self {
        Self(transport)
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
#[non_exhaustive]
pub enum ReaderEvent {
    Ingested(IngestOutcome),
    HeaderMismatch { rx: DateTime<Utc>, raw: String },
    Idle,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReaderError {
    #[error("smdr link down: {0:?}")]
    LinkDown(TransportError),
    #[error(transparent)]
    Store(#[from] SmdrStoreError),
}

pub struct SmdrReader<S: SmdrSource> {
    source: S,
    splitter: LineSplitter,
    pending: VecDeque<SmdrLine>,
    undelivered: Vec<ReaderEvent>,
}

impl<S: SmdrSource> SmdrReader<S> {
    pub fn new(source: S) -> Self {
        Self {
            source,
            splitter: LineSplitter::new(),
            pending: VecDeque::new(),
            undelivered: Vec::new(),
        }
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    pub fn into_source(self) -> S {
        self.source
    }

    #[must_use = "events carry header mismatches and ingest outcomes"]
    pub fn poll_once<K: SmdrSink>(
        &mut self,
        sink: &mut K,
        timeout_ms: u64,
        now: impl Fn() -> DateTime<Utc>,
    ) -> Result<Vec<ReaderEvent>, ReaderError> {
        if !self.pending.is_empty() {
            return self.deliver(sink, now);
        }
        let bytes = match self.source.recv(timeout_ms) {
            Ok(b) => b,
            Err(TransportError::Timeout) => return Ok(vec![ReaderEvent::Idle]),
            Err(e) => return Err(ReaderError::LinkDown(e)),
        };
        self.pending.extend(self.splitter.push(&bytes));
        self.deliver(sink, now)
    }

    #[must_use = "events carry header mismatches and ingest outcomes"]
    pub fn finish<K: SmdrSink>(
        &mut self,
        sink: &mut K,
        now: impl Fn() -> DateTime<Utc>,
    ) -> Result<Vec<ReaderEvent>, ReaderError> {
        self.pending.extend(self.splitter.finish());
        self.deliver(sink, now)
    }

    fn deliver<K: SmdrSink>(
        &mut self,
        sink: &mut K,
        now: impl Fn() -> DateTime<Utc>,
    ) -> Result<Vec<ReaderEvent>, ReaderError> {
        let mut events = std::mem::take(&mut self.undelivered);
        while let Some(line) = self.pending.pop_front() {
            let rx = now();
            let mismatch = (line.kind() == LineKind::Header && !line.header_matches_spec())
                .then(|| line.raw().to_string());
            match sink.ingest(line.clone(), rx) {
                Ok(outcome) => events.push(ReaderEvent::Ingested(outcome)),
                Err(e) => {
                    self.pending.push_front(line);
                    self.undelivered = events;
                    return Err(ReaderError::Store(e));
                }
            }
            if let Some(raw) = mismatch {
                events.push(ReaderEvent::HeaderMismatch { rx, raw });
            }
        }
        Ok(events)
    }
}
