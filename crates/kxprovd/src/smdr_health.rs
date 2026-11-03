//! S7 SMDR health alerts: line silence, CTS low and header mismatch.
//!
//! [`HealthMonitor`] is a pure state machine driven by [`Observation`]s and an injected
//! monotonic `Instant`. It owns no port handle, so it cannot transmit; its byte input is a
//! counter fed by [`ByteTap`], which wraps an [`SmdrSource`] (receive only). It writes nothing
//! to SQLite. [`HealthBoard`] publishes its edges through [`SmdrLive`].

use chrono::{DateTime, SecondsFormat, Utc};
use kxprov_api::{CtsStatus, SmdrAlert, SmdrAlertKind, SmdrAlertState};
use std::time::{Duration, Instant};

#[cfg_attr(
    all(not(test), not(feature = "test-util")),
    expect(
        dead_code,
        reason = "no production caller until the reader loop lands, https://github.com/mitchmitchell/panasonic/issues/107"
    )
)]
#[cfg_attr(
    all(test, not(feature = "test-util")),
    allow(
        dead_code,
        reason = "unit tests reach only HealthBoard; the rest is exercised by tests/smdr_health.rs under test-util"
    )
)]
mod wiring;
#[cfg(feature = "test-util")]
pub use wiring::{observations_from_reader, ByteCounter, ByteTap, HealthBoard};
#[cfg(not(feature = "test-util"))]
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "no production caller until the reader loop lands, https://github.com/mitchmitchell/panasonic/issues/107"
    )
)]
#[cfg_attr(
    test,
    allow(
        unused_imports,
        reason = "unit tests reach only HealthBoard; the rest is exercised by tests/smdr_health.rs under test-util"
    )
)]
pub(crate) use wiring::{observations_from_reader, ByteCounter, ByteTap, HealthBoard};

/// Parsed thresholds, built by [`crate::config::SmdrConfig::health`]. Both durations are non-zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthConfig {
    pub silence_after: Duration,
    pub cts_low_after: Duration,
    pub cts_monitor: bool,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            silence_after: Duration::from_secs(86_400),
            cts_low_after: Duration::from_secs(30),
            cts_monitor: true,
        }
    }
}

/// What the SMDR port is doing, as far as S7 cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Smdr,
    Programming,
    Closed,
}

/// A modem-status read that failed. Keeps the `io::ErrorKind`; text is rendered only for
/// `smdr_status`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("modem status read failed: {detail}")]
pub struct ModemStatusError {
    pub kind: std::io::ErrorKind,
    pub detail: String,
}

impl From<&std::io::Error> for ModemStatusError {
    fn from(e: &std::io::Error) -> Self {
        Self {
            kind: e.kind(),
            detail: e.to_string(),
        }
    }
}

/// One input to [`HealthMonitor::step`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// At least one byte arrived on the receive handle.
    Bytes,
    /// S4 reported a header that differs from the spec.
    HeaderMismatch,
    /// S4 reported a header that matches the spec.
    HeaderMatched,
    Port(PortState),
    /// Result of one modem-status read; `Ok(true)` is CTS high. An error resets both the low
    /// and high runs, so a raised CtsLow stays raised until good high reads span the debounce.
    ModemStatus(Result<bool, ModemStatusError>),
    /// Time passed; re-evaluate thresholds.
    Tick,
}

fn utc(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[derive(Debug, Default)]
struct Cts {
    high: Option<bool>,
    read_error: Option<String>,
    low_since: Option<Instant>,
    high_since: Option<Instant>,
}

/// The S7 state machine. One per SMDR port; fresh on every daemon start.
#[derive(Debug)]
pub struct HealthMonitor {
    cfg: HealthConfig,
    port: PortState,
    silence_epoch: Option<Instant>,
    silence: Option<String>,
    cts: Cts,
    cts_alert: Option<String>,
    header: Option<String>,
    header_mismatches: u64,
}

impl HealthMonitor {
    /// Starts with the port closed: no silence is measured until [`PortState::Smdr`].
    pub fn new(cfg: HealthConfig) -> Self {
        Self {
            cfg,
            port: PortState::Closed,
            silence_epoch: None,
            silence: None,
            cts: Cts::default(),
            cts_alert: None,
            header: None,
            header_mismatches: 0,
        }
    }

    /// Applies one observation and returns the alert edges it caused, at most one per kind.
    ///
    /// `now` must come from one monotonic clock for the life of the monitor; all thresholds
    /// are measured on it. `wall` only stamps `since`/`at` on alerts and never drives timing.
    #[must_use = "edges must reach smdr_status and the subscribe stream"]
    pub fn step(&mut self, obs: Observation, now: Instant, wall: DateTime<Utc>) -> Vec<SmdrAlert> {
        self.step_after_bytes(false, obs, now, wall)
    }

    /// Like [`HealthMonitor::step`], but when `bytes_arrived` first folds in a byte arrival
    /// without evaluating, so thresholds are judged once, after both inputs are applied.
    #[must_use = "edges must reach smdr_status and the subscribe stream"]
    pub fn step_after_bytes(
        &mut self,
        bytes_arrived: bool,
        obs: Observation,
        now: Instant,
        wall: DateTime<Utc>,
    ) -> Vec<SmdrAlert> {
        let mut edges = Vec::new();
        if bytes_arrived {
            self.apply(Observation::Bytes, now, wall, &mut edges);
        }
        self.apply(obs, now, wall, &mut edges);
        self.evaluate(now, wall, &mut edges);
        edges
    }

    fn apply(
        &mut self,
        obs: Observation,
        now: Instant,
        wall: DateTime<Utc>,
        edges: &mut Vec<SmdrAlert>,
    ) {
        match obs {
            Observation::Bytes => {
                if self.port == PortState::Smdr {
                    self.silence_epoch = Some(now);
                }
                if let Some(since) = self.silence.take() {
                    edges.push(cleared(SmdrAlertKind::LineSilence, since, wall));
                }
            }
            Observation::HeaderMismatch => {
                self.header_mismatches = self.header_mismatches.saturating_add(1);
                if self.header.is_none() {
                    let since = utc(wall);
                    self.header = Some(since.clone());
                    edges.push(raised(SmdrAlertKind::HeaderMismatch, since));
                }
            }
            Observation::HeaderMatched => {
                if let Some(since) = self.header.take() {
                    edges.push(cleared(SmdrAlertKind::HeaderMismatch, since, wall));
                }
            }
            Observation::Port(state) => {
                if state == PortState::Smdr && self.port != PortState::Smdr {
                    self.silence_epoch = Some(now);
                } else if state != PortState::Smdr {
                    self.silence_epoch = None;
                }
                self.port = state;
            }
            Observation::ModemStatus(Ok(high)) => {
                self.cts.read_error = None;
                self.cts.high = Some(high);
                if high {
                    self.cts.low_since = None;
                    self.cts.high_since.get_or_insert(now);
                } else {
                    self.cts.high_since = None;
                    self.cts.low_since.get_or_insert(now);
                }
            }
            Observation::ModemStatus(Err(e)) => {
                tracing::warn!(kind = ?e.kind, reason = %e.detail, "CTS unknown; low/high continuity reset");
                self.cts = Cts {
                    read_error: Some(e.to_string()),
                    ..Cts::default()
                };
            }
            Observation::Tick => {}
        }
    }

    fn evaluate(&mut self, now: Instant, wall: DateTime<Utc>, edges: &mut Vec<SmdrAlert>) {
        let held = |since: Option<Instant>, d: Duration| {
            since.is_some_and(|s| now.saturating_duration_since(s) >= d)
        };
        if self.silence.is_none()
            && self.port == PortState::Smdr
            && held(self.silence_epoch, self.cfg.silence_after)
        {
            let since = utc(wall);
            self.silence = Some(since.clone());
            edges.push(raised(SmdrAlertKind::LineSilence, since));
        }
        match self.cts_alert.take() {
            None if self.cfg.cts_monitor && held(self.cts.low_since, self.cfg.cts_low_after) => {
                let since = utc(wall);
                self.cts_alert = Some(since.clone());
                edges.push(raised(SmdrAlertKind::CtsLow, since));
            }
            Some(since) if held(self.cts.high_since, self.cfg.cts_low_after) => {
                edges.push(cleared(SmdrAlertKind::CtsLow, since, wall));
            }
            unchanged => self.cts_alert = unchanged,
        }
    }

    /// Alerts currently raised, in kind order, each with its original `since`. Cleared alerts
    /// are not kept; they exist only as the edge `step` returned.
    pub fn active(&self) -> Vec<SmdrAlert> {
        [
            (SmdrAlertKind::LineSilence, &self.silence),
            (SmdrAlertKind::CtsLow, &self.cts_alert),
            (SmdrAlertKind::HeaderMismatch, &self.header),
        ]
        .into_iter()
        .filter_map(|(kind, since)| since.clone().map(|since| raised(kind, since)))
        .collect()
    }

    /// Last CTS reading and, if the last read failed, its rendered error.
    pub fn cts_status(&self) -> CtsStatus {
        CtsStatus {
            monitored: self.cfg.cts_monitor,
            high: self.cts.high,
            read_error: self.cts.read_error.clone(),
        }
    }

    /// Header mismatches seen since start, saturating.
    pub fn header_mismatches(&self) -> u64 {
        self.header_mismatches
    }
}

fn raised(kind: SmdrAlertKind, since: String) -> SmdrAlert {
    SmdrAlert {
        kind,
        state: SmdrAlertState::Raised { since },
    }
}

fn cleared(kind: SmdrAlertKind, since: String, at: DateTime<Utc>) -> SmdrAlert {
    SmdrAlert {
        kind,
        state: SmdrAlertState::Cleared { since, at: utc(at) },
    }
}
