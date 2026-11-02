//! Live call-log broadcast and reader counters (S6 design §2). Fed after a successful DB insert.

use crate::smdr_api::calls_after;
use crate::smdr_reader::{ReaderEvent, SmdrSink};
use crate::smdr_store::{IngestOutcome, SmdrStore, SmdrStoreError};
use chrono::{DateTime, SecondsFormat, Utc};
use kxprov_api::{SmdrCallView, QUERY_LIMIT_MAX, SMDR_BUS_CAPACITY};
use kxtd1232::smdr::SmdrLine;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use tokio::sync::broadcast;

#[derive(Debug, Default, Clone)]
struct LiveStats {
    running: bool,
    link_down: bool,
    last_byte_at: Option<String>,
    header_mismatch_count: u64,
}

/// What the reader reports about itself, as seen by status calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSnapshot {
    pub running: bool,
    pub link_down: bool,
    pub last_byte_at: Option<String>,
    pub header_mismatch_count: u64,
}

/// Shared between the reader (writer side) and the socket API (reader side).
pub struct SmdrLive {
    tx: broadcast::Sender<SmdrCallView>,
    stats: Mutex<LiveStats>,
}

impl Default for SmdrLive {
    fn default() -> Self {
        Self::new()
    }
}

fn utc(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

impl SmdrLive {
    pub fn new() -> Self {
        let (tx, _unused_initial_receiver) = broadcast::channel(SMDR_BUS_CAPACITY);
        Self {
            tx,
            stats: Mutex::new(LiveStats::default()),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SmdrCallView> {
        self.tx.subscribe()
    }

    /// Never blocks. With no subscriber the call is simply not delivered; it is already stored.
    pub fn publish(&self, call: SmdrCallView) {
        if self.tx.send(call).is_err() {
            tracing::trace!("no call-log subscribers");
        }
    }

    fn with_stats<R>(&self, f: impl FnOnce(&mut LiveStats) -> R) -> R {
        f(&mut self.stats.lock().unwrap_or_else(PoisonError::into_inner))
    }

    pub fn set_running(&self, running: bool) {
        self.with_stats(|s| s.running = running);
    }

    pub fn set_link_down(&self, down: bool) {
        self.with_stats(|s| s.link_down = down);
    }

    pub fn note_bytes(&self, at: DateTime<Utc>) {
        self.with_stats(|s| s.last_byte_at = Some(utc(at)));
    }

    pub fn note_events(&self, events: &[ReaderEvent]) {
        let mismatches = events
            .iter()
            .filter(|e| matches!(e, ReaderEvent::HeaderMismatch { .. }))
            .count() as u64;
        self.with_stats(|s| s.header_mismatch_count += mismatches);
    }

    pub fn snapshot(&self) -> LiveSnapshot {
        self.with_stats(|s| LiveSnapshot {
            running: s.running,
            link_down: s.link_down,
            last_byte_at: s.last_byte_at.clone(),
            header_mismatch_count: s.header_mismatch_count,
        })
    }
}

/// An [`SmdrSink`] that stores each line, then publishes newly stored calls to subscribers.
pub struct PublishingSink {
    store: SmdrStore,
    live: Arc<SmdrLive>,
    db: PathBuf,
    last_id: i64,
}

impl PublishingSink {
    pub fn new(store: SmdrStore, live: Arc<SmdrLive>) -> Self {
        let db = store.dir().join(crate::smdr_store::SMDR_DB_NAME);
        let last_id = crate::smdr_api::max_call_id(&db).unwrap_or(0);
        Self {
            store,
            live,
            db,
            last_id,
        }
    }

    pub fn into_store(self) -> SmdrStore {
        self.store
    }
}

impl SmdrSink for PublishingSink {
    fn ingest(
        &mut self,
        line: SmdrLine,
        rx: DateTime<Utc>,
    ) -> Result<IngestOutcome, SmdrStoreError> {
        let outcome = self.store.ingest(line, rx)?;
        if outcome == IngestOutcome::Stored {
            match calls_after(&self.db, self.last_id, QUERY_LIMIT_MAX) {
                Ok(calls) => {
                    for call in calls {
                        self.last_id = self.last_id.max(call.id);
                        self.live.publish(call);
                    }
                }
                Err(e) => tracing::warn!(%e, "stored call not published; subscribers re-query"),
            }
        }
        Ok(outcome)
    }
}
