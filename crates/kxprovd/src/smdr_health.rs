//! S7 SMDR health: line silence, CTS low and header mismatch, as a pure state machine.
//!
//! Design: grokbots/architecture/panasonic/2026-10-31-kx-provision-s7-design.md §1, §4, §6.
//! The monitor holds no transport and no lease, so it can never transmit or toggle modem lines.
//! Durations use a caller-supplied monotonic `Instant`; wall time is carried for display only.

use crate::smdr_reader::ReaderEvent;
use chrono::{DateTime, Utc};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warn,
    Crit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignalKind {
    LineSilence,
    CtsLow,
    HeaderMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HealthSignal {
    LineSilence { since_last_byte: Duration },
    CtsLow { since: DateTime<Utc> },
    HeaderMismatch { rx: DateTime<Utc>, count_24h: u32 },
}

impl HealthSignal {
    pub fn kind(&self) -> SignalKind {
        match self {
            HealthSignal::LineSilence { .. } => SignalKind::LineSilence,
            HealthSignal::CtsLow { .. } => SignalKind::CtsLow,
            HealthSignal::HeaderMismatch { .. } => SignalKind::HeaderMismatch,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    Raised {
        signal: HealthSignal,
        severity: Severity,
    },
    Cleared {
        kind: SignalKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// Any non-empty `recv` from the SMDR source, including bytes the line splitter strips.
    Byte,
    HeaderMismatch {
        rx: DateTime<Utc>,
    },
    Modem {
        cts: bool,
    },
    ReaderPaused,
    ReaderResumed,
    Tick,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthConfig {
    pub silence_warn: Duration,
    pub silence_crit: Duration,
    pub cts_low_grace: Duration,
    pub header_window: Duration,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            silence_warn: Duration::from_secs(24 * 3600),
            silence_crit: Duration::from_secs(72 * 3600),
            cts_low_grace: Duration::from_secs(30),
            header_window: Duration::from_secs(24 * 3600),
        }
    }
}

#[derive(Debug)]
pub struct HealthMonitor {
    config: HealthConfig,
    silence_accum: Duration,
    silence_mark: Option<Instant>,
    silence_raised: Option<Severity>,
    cts_low_since: Option<(Instant, DateTime<Utc>)>,
    cts_raised: bool,
    mismatches: VecDeque<Instant>,
    header_raised: bool,
}

impl HealthMonitor {
    /// Starts the silence clock at `now`, as if a byte had just arrived.
    pub fn new(config: HealthConfig, now: Instant) -> Self {
        Self {
            config,
            silence_accum: Duration::ZERO,
            silence_mark: Some(now),
            silence_raised: None,
            cts_low_since: None,
            cts_raised: false,
            mismatches: VecDeque::new(),
            header_raised: false,
        }
    }

    pub fn config(&self) -> &HealthConfig {
        &self.config
    }

    /// Silence counted so far, excluding time spent paused for a programming lease.
    pub fn silence(&self, now: Instant) -> Duration {
        self.silence_accum
            + self
                .silence_mark
                .map_or(Duration::ZERO, |m| now.saturating_duration_since(m))
    }

    pub fn active(&self) -> Vec<(SignalKind, Severity)> {
        let mut out = Vec::new();
        if let Some(s) = self.silence_raised {
            out.push((SignalKind::LineSilence, s));
        }
        if self.cts_raised {
            out.push((SignalKind::CtsLow, Severity::Warn));
        }
        if self.header_raised {
            out.push((SignalKind::HeaderMismatch, Severity::Warn));
        }
        out
    }

    pub fn step(&mut self, obs: Observation, now: Instant, wall: DateTime<Utc>) -> Vec<Transition> {
        let mut out = Vec::new();
        match obs {
            Observation::Byte => {
                self.silence_accum = Duration::ZERO;
                if self.silence_mark.is_some() {
                    self.silence_mark = Some(now);
                }
                if self.silence_raised.take().is_some() {
                    out.push(Transition::Cleared {
                        kind: SignalKind::LineSilence,
                    });
                }
            }
            Observation::ReaderPaused => {
                if let Some(m) = self.silence_mark.take() {
                    self.silence_accum += now.saturating_duration_since(m);
                }
            }
            Observation::ReaderResumed => {
                if self.silence_mark.is_none() {
                    self.silence_mark = Some(now);
                }
            }
            Observation::Modem { cts: true } => {
                self.cts_low_since = None;
                if std::mem::take(&mut self.cts_raised) {
                    out.push(Transition::Cleared {
                        kind: SignalKind::CtsLow,
                    });
                }
            }
            Observation::Modem { cts: false } => {
                if self.cts_low_since.is_none() {
                    self.cts_low_since = Some((now, wall));
                }
            }
            Observation::HeaderMismatch { rx } => {
                self.mismatches.push_back(now);
                self.prune_mismatches(now);
                let count_24h = u32::try_from(self.mismatches.len()).unwrap_or(u32::MAX);
                if !self.header_raised {
                    self.header_raised = true;
                    out.push(Transition::Raised {
                        signal: HealthSignal::HeaderMismatch { rx, count_24h },
                        severity: Severity::Warn,
                    });
                }
            }
            Observation::Tick => {}
        }
        self.evaluate(now, &mut out);
        out
    }

    fn prune_mismatches(&mut self, now: Instant) {
        while let Some(&first) = self.mismatches.front() {
            if now.saturating_duration_since(first) >= self.config.header_window {
                self.mismatches.pop_front();
            } else {
                break;
            }
        }
    }

    fn evaluate(&mut self, now: Instant, out: &mut Vec<Transition>) {
        let silence = self.silence(now);
        let want = if silence >= self.config.silence_crit {
            Some(Severity::Crit)
        } else if silence >= self.config.silence_warn {
            Some(Severity::Warn)
        } else {
            None
        };
        if let Some(sev) = want {
            if self.silence_raised != Some(sev) && self.silence_raised != Some(Severity::Crit) {
                self.silence_raised = Some(sev);
                out.push(Transition::Raised {
                    signal: HealthSignal::LineSilence {
                        since_last_byte: silence,
                    },
                    severity: sev,
                });
            }
        }

        if let Some((since, wall)) = self.cts_low_since {
            if !self.cts_raised && now.saturating_duration_since(since) >= self.config.cts_low_grace
            {
                self.cts_raised = true;
                out.push(Transition::Raised {
                    signal: HealthSignal::CtsLow { since: wall },
                    severity: Severity::Warn,
                });
            }
        }

        self.prune_mismatches(now);
        if self.header_raised && self.mismatches.is_empty() {
            self.header_raised = false;
            out.push(Transition::Cleared {
                kind: SignalKind::HeaderMismatch,
            });
        }
    }
}

/// Maps S4 reader events to health observations; ingest outcomes carry no health signal.
pub fn observations_from_reader(events: &[ReaderEvent]) -> Vec<Observation> {
    events
        .iter()
        .filter_map(|e| match e {
            ReaderEvent::HeaderMismatch { rx, .. } => Some(Observation::HeaderMismatch { rx: *rx }),
            ReaderEvent::Ingested(_) | ReaderEvent::Idle => None,
        })
        .collect()
}

/// PII guard: alert text carries only the signal name, a duration or a count.
pub fn alert_text(t: &Transition) -> String {
    match t {
        Transition::Raised { signal, severity } => match signal {
            HealthSignal::LineSilence { since_last_byte } => format!(
                "smdr {severity:?}: line silence for {}s",
                since_last_byte.as_secs()
            ),
            HealthSignal::CtsLow { since } => {
                format!("smdr {severity:?}: CTS low since {}", since.to_rfc3339())
            }
            HealthSignal::HeaderMismatch { count_24h, .. } => {
                format!("smdr {severity:?}: header mismatch ({count_24h} in 24h)")
            }
        },
        Transition::Cleared { kind } => format!("smdr cleared: {kind:?}"),
    }
}
