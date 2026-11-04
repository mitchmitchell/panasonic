//! S7 wiring between the S4 reader, the [`HealthMonitor`] and [`SmdrLive`].
//!
//! Re-exported publicly only with `test-util`: no production code calls these until the
//! daemon reader loop lands (https://github.com/mitchmitchell/panasonic/issues/107).

use super::{HealthConfig, HealthMonitor, Observation};
use crate::smdr_bus::SmdrLive;
use crate::smdr_reader::{ReaderEvent, SmdrSource};
use chrono::{DateTime, Utc};
use kxtd1232::TransportError;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Maps S4 reader events to observations. Ingest outcomes and idle polls carry no health
/// signal: bytes are counted by [`ByteTap`], not by records.
pub fn observations_from_reader(events: &[ReaderEvent]) -> Vec<Observation> {
    events
        .iter()
        .filter_map(|e| match e {
            ReaderEvent::HeaderMismatch { .. } => Some(Observation::HeaderMismatch),
            ReaderEvent::HeaderMatched { .. } => Some(Observation::HeaderMatched),
            ReaderEvent::Ingested(_) | ReaderEvent::Idle => None,
        })
        .collect()
}

/// Counts bytes received through an [`SmdrSource`]. It adds no transmit path.
///
/// The counter wraps; [`ByteCounter::take_new`] only compares for change, and a non-empty
/// read can never move it by a multiple of 2^64. A read longer than `u64::MAX` (impossible
/// where usize is at most 64 bits) counts as `u64::MAX`, which still registers as new bytes.
pub struct ByteTap<S: SmdrSource> {
    inner: S,
    count: Arc<AtomicU64>,
}

impl<S: SmdrSource> ByteTap<S> {
    pub fn new(inner: S) -> (Self, ByteCounter) {
        let count = Arc::new(AtomicU64::new(0));
        let counter = ByteCounter {
            count: Arc::clone(&count),
            seen: 0,
        };
        (Self { inner, count }, counter)
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: SmdrSource> SmdrSource for ByteTap<S> {
    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        let bytes = self.inner.recv(timeout_ms)?;
        let n = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.count.fetch_add(n, Ordering::Relaxed);
        Ok(bytes)
    }
}

/// The health side of a [`ByteTap`]. `Default` is a counter with no tap, which never
/// reports new bytes.
#[derive(Debug, Default)]
pub struct ByteCounter {
    count: Arc<AtomicU64>,
    seen: u64,
}

impl ByteCounter {
    /// True when bytes arrived since the last call.
    pub fn take_new(&mut self) -> bool {
        let now = self.count.load(Ordering::Relaxed);
        let fresh = now != self.seen;
        self.seen = now;
        fresh
    }
}

/// Drives a [`HealthMonitor`] and publishes its edges and status through [`SmdrLive`].
pub struct HealthBoard {
    monitor: HealthMonitor,
    live: Arc<SmdrLive>,
    bytes: ByteCounter,
}

impl HealthBoard {
    pub fn new(cfg: HealthConfig, live: Arc<SmdrLive>, bytes: ByteCounter) -> Self {
        let monitor = HealthMonitor::new(cfg);
        live.set_health(monitor.active(), monitor.cts_status());
        Self {
            monitor,
            live,
            bytes,
        }
    }

    /// One timer tick: folds in new bytes, then re-evaluates. One timer per daemon drives this.
    pub fn tick(&mut self, now: Instant, wall: DateTime<Utc>) {
        self.observe(Observation::Tick, now, wall);
    }

    /// Applies `obs` together with any bytes the tap counted since the last step, then
    /// evaluates thresholds once, so neither input is judged against the other's stale state.
    pub fn observe(&mut self, obs: Observation, now: Instant, wall: DateTime<Utc>) {
        let bytes_arrived = self.bytes.take_new();
        let edges = self.monitor.step_after_bytes(bytes_arrived, obs, now, wall);
        self.live
            .set_health(self.monitor.active(), self.monitor.cts_status());
        for edge in edges {
            self.live.publish_alert(edge);
        }
    }

    pub fn monitor(&self) -> &HealthMonitor {
        &self.monitor
    }
}
