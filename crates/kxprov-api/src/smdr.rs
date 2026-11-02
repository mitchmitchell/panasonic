//! Read-only SMDR call-log query types (S6 design §1).

use serde::{Deserialize, Serialize};

/// Largest page a caller may request from the daemon.
pub const QUERY_LIMIT_MAX: u16 = 500;
/// Largest page an MCP caller may request.
pub const MCP_QUERY_LIMIT_MAX: u16 = 100;
/// Default page size when the caller gives none.
pub const QUERY_LIMIT_DEFAULT: u16 = 50;
/// Longest `[since, until)` window per request.
pub const MAX_RANGE_DAYS: u16 = 31;
/// Window used when the caller gives no `since`.
pub const DEFAULT_RANGE_MS: i64 = 24 * 60 * 60 * 1000;
const DAY_MS: i64 = 24 * 60 * 60 * 1000;
/// Extra length allowed on a [`MAX_RANGE_DAYS`] window: one hour, so 31 local calendar days
/// that span a fall daylight-saving change (25-hour day) still fit.
///
/// The cap is measured as UTC elapsed milliseconds (`until_ms - since_ms`), never in local
/// wall-clock time, so a spring-forward window (31 days minus one hour) is always inside it.
pub const DST_SLACK_MS: i64 = 60 * 60 * 1000;

/// Typed failures for call-log reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SmdrApiError {
    #[error("token scope denied")]
    ScopeDenied,
    #[error("range is longer than {max_days} days")]
    RangeTooLarge { max_days: u16 },
    #[error("range end is not after its start")]
    BadRange,
    #[error("page size must be from 1 to {max}")]
    BadLimit { max: u16 },
    #[error("cursor is not valid")]
    BadCursor,
    #[error("call log unavailable")]
    StoreUnavailable,
    #[error("call log is disabled")]
    Disabled,
    #[error("stored call {id} is unreadable")]
    CorruptRow { id: i64 },
}

impl SmdrApiError {
    /// Wire error code carried in [`crate::ApiErrorBody::code`].
    pub fn code(self) -> &'static str {
        match self {
            Self::ScopeDenied => "forbidden",
            Self::RangeTooLarge { .. } => "range_too_large",
            Self::BadRange => "bad_range",
            Self::BadLimit { .. } => "bad_limit",
            Self::BadCursor => "bad_cursor",
            Self::StoreUnavailable => "store_unavailable",
            Self::Disabled => "smdr_disabled",
            Self::CorruptRow { .. } => "smdr_corrupt_row",
        }
    }

    /// Inverse of [`Self::code`] for clients; `None` for codes this type does not own.
    ///
    /// The wire body carries only the code, so fields come from the daemon's own bounds:
    /// a daemon `bad_limit` is always against [`QUERY_LIMIT_MAX`], because the MCP cap is checked
    /// in kxprov-mcp before any call reaches the daemon, and a corrupt row id is reported as 0.
    pub fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "range_too_large" => Self::RangeTooLarge {
                max_days: MAX_RANGE_DAYS,
            },
            "bad_range" => Self::BadRange,
            "bad_limit" => Self::BadLimit {
                max: QUERY_LIMIT_MAX,
            },
            "bad_cursor" => Self::BadCursor,
            "store_unavailable" => Self::StoreUnavailable,
            "smdr_disabled" => Self::Disabled,
            "smdr_corrupt_row" => Self::CorruptRow { id: 0 },
            _ => return None,
        })
    }

    /// True when the caller sent a bad request (HTTP 400), as opposed to a server state.
    pub fn is_client_error(self) -> bool {
        matches!(
            self,
            Self::RangeTooLarge { .. } | Self::BadRange | Self::BadLimit { .. } | Self::BadCursor
        )
    }
}

/// Page size, 1..=[`QUERY_LIMIT_MAX`]. Construct with [`QueryLimit::new`] or [`QueryLimit::mcp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct QueryLimit(u16);

impl QueryLimit {
    pub fn new(n: u16) -> Result<Self, SmdrApiError> {
        Self::capped(n, QUERY_LIMIT_MAX)
    }

    /// MCP boundary: the cap is [`MCP_QUERY_LIMIT_MAX`].
    pub fn mcp(n: u16) -> Result<Self, SmdrApiError> {
        Self::capped(n, MCP_QUERY_LIMIT_MAX)
    }

    fn capped(n: u16, max: u16) -> Result<Self, SmdrApiError> {
        if (1..=max).contains(&n) {
            Ok(Self(n))
        } else {
            Err(SmdrApiError::BadLimit { max })
        }
    }

    pub fn get(self) -> u16 {
        self.0
    }
}

impl Default for QueryLimit {
    fn default() -> Self {
        Self(QUERY_LIMIT_DEFAULT)
    }
}

impl<'de> Deserialize<'de> for QueryLimit {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let n = u16::deserialize(d)?;
        Self::new(n).map_err(serde::de::Error::custom)
    }
}

/// Opaque keyset cursor: the `(rx_ts_utc, id)` of the last row on the previous page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmdrCursor {
    rx_ts_utc: String,
    id: i64,
}

impl SmdrCursor {
    pub fn new(rx_ts_utc: String, id: i64) -> Self {
        Self { rx_ts_utc, id }
    }

    pub fn rx_ts_utc(&self) -> &str {
        &self.rx_ts_utc
    }

    pub fn id(&self) -> i64 {
        self.id
    }

    /// Opaque text form for URLs and JSON.
    pub fn encode(&self) -> String {
        hex::encode(format!("{}|{}", self.rx_ts_utc, self.id))
    }

    pub fn decode(s: &str) -> Result<Self, SmdrApiError> {
        let bytes = hex::decode(s.trim()).map_err(bad_cursor)?;
        let text = String::from_utf8(bytes).map_err(bad_cursor)?;
        let (ts, id) = text.rsplit_once('|').ok_or(SmdrApiError::BadCursor)?;
        let id: i64 = id.parse().map_err(bad_cursor)?;
        let ts_ok = ts.len() == 24
            && ts.ends_with('Z')
            && ts
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'-' | b':' | b'T' | b'.' | b'Z'));
        if !ts_ok || id < 1 {
            return Err(SmdrApiError::BadCursor);
        }
        Ok(Self::new(ts.to_string(), id))
    }
}

/// Discards the decode error on purpose: the cursor is opaque, so every way it can be malformed
/// is the same typed [`SmdrApiError::BadCursor`] and the detail would only echo caller input.
fn bad_cursor<E>(_detail: E) -> SmdrApiError {
    SmdrApiError::BadCursor
}

impl Serialize for SmdrCursor {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.encode())
    }
}

impl<'de> Deserialize<'de> for SmdrCursor {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallDirection {
    Incoming,
    Outgoing,
}

/// Query for stored calls in the half-open window `[since_ms, until_ms)`, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmdrQueryParams {
    pub since_ms: i64,
    pub until_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<CallDirection>,
    #[serde(default)]
    pub limit: QueryLimit,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<SmdrCursor>,
}

impl SmdrQueryParams {
    /// Fills a missing end with `now_ms` and a missing start with `end - 24 h`.
    pub fn with_defaults(since_ms: Option<i64>, until_ms: Option<i64>, now_ms: i64) -> Self {
        let until_ms = until_ms.unwrap_or(now_ms);
        let since_ms = since_ms.unwrap_or(until_ms.saturating_sub(DEFAULT_RANGE_MS));
        Self {
            since_ms,
            until_ms,
            ext: None,
            direction: None,
            limit: QueryLimit::default(),
            cursor: None,
        }
    }

    /// Checks the window: non-empty and at most [`MAX_RANGE_DAYS`] plus [`DST_SLACK_MS`].
    pub fn validate(&self) -> Result<(), SmdrApiError> {
        if self.until_ms <= self.since_ms {
            return Err(SmdrApiError::BadRange);
        }
        let max_ms = i64::from(MAX_RANGE_DAYS) * DAY_MS + DST_SLACK_MS;
        if self.until_ms.saturating_sub(self.since_ms) > max_ms {
            return Err(SmdrApiError::RangeTooLarge {
                max_days: MAX_RANGE_DAYS,
            });
        }
        Ok(())
    }
}

/// One stored call as shown to callers (every caller holds the CallLog scope).
///
/// `raw` is the PBX's SMDR line exactly as received, including the CD column, uninterpreted
/// (#97). No answered/unanswered or mapped-CD field is derived from it; #95 tracks a mapped enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmdrCallView {
    pub id: i64,
    pub rx_ts_utc: String,
    pub pbx_local: String,
    pub ext: String,
    pub co: String,
    pub direction: CallDirection,
    pub number: String,
    pub cid_text: Option<String>,
    pub ring_s: Option<u32>,
    pub duration_s: Option<u32>,
    pub acc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

/// Tracking issue for calls the PBX may not report while the reader is paused for programming.
pub const GAP_TRACKING: &str = "https://github.com/mitchmitchell/panasonic/issues/14";

/// A window when the SMDR reader was paused for one programming lease, so calls may be missing.
///
/// Built from the lease journal (`reader_paused` to `reader_resumed`), one per lease.
/// `to_utc` is `None` while the lease is still held.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapWindow {
    pub from_utc: String,
    pub to_utc: Option<String>,
    pub job_id: String,
    pub tracking: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmdrPage {
    pub calls: Vec<SmdrCallView>,
    pub next: Option<SmdrCursor>,
    /// Reader gaps that overlap the queried `[since, until)` range, oldest first.
    #[serde(default)]
    pub gaps: Vec<GapWindow>,
}

/// Capacity of the daemon's live-call broadcast; a subscriber further behind gets [`SmdrStreamEvent::Lagged`].
pub const SMDR_BUS_CAPACITY: usize = 256;
/// Seconds between keep-alive events on a call-log subscription.
pub const SMDR_HEARTBEAT_SECS: u64 = 15;
/// Live call-log streams one web session may hold open at once.
pub const SMDR_STREAMS_PER_SESSION: usize = 4;

/// Why the SMDR reader is not listening.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DownReason {
    /// The daemon has not started an SMDR reader.
    ReaderNotRunning,
    /// The reader lost the serial link.
    LinkDown,
}

/// What the SMDR port is doing, for the call-log banner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum PortModeView {
    Listening,
    PausedForProgramming { job_id: String },
    Disabled,
    Down { reason: DownReason },
}

/// Reader counters; shown only to callers holding the `CallLog` scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmdrCounters {
    pub last_byte_at: Option<String>,
    pub last_line_at: Option<String>,
    /// Stored calls received since local midnight on the daemon host.
    pub lines_today: u64,
    pub unparsed_count: u64,
    pub header_mismatch_count: u64,
}

/// Call-log status. `counters` is `None` for a caller with `Read` but not `CallLog`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmdrStatus {
    pub port_mode: PortModeView,
    pub counters: Option<SmdrCounters>,
}

/// Acknowledges a subscription; events follow on the same connection, one JSON line each.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmdrSubscribed {
    /// Calls after this id are replayed before live events.
    pub replay_after_id: i64,
}

/// One event on a call-log subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
#[non_exhaustive]
#[expect(
    clippy::large_enum_variant,
    reason = "Call is the event sent almost every time; boxing it would only add an allocation per call"
)]
pub enum SmdrStreamEvent {
    Call {
        call: SmdrCallView,
    },
    /// The subscriber fell behind and missed `skipped` calls; it must re-query the first page.
    Lagged {
        skipped: u64,
    },
    Heartbeat,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test setup failures should abort the test"
    )]

    use super::*;

    #[test]
    fn status_and_stream_events_have_stable_wire_shapes() {
        let s = SmdrStatus {
            port_mode: PortModeView::PausedForProgramming {
                job_id: "j1".into(),
            },
            counters: None,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["port_mode"]["state"], "paused_for_programming");
        assert_eq!(v["port_mode"]["job_id"], "j1");
        let down = serde_json::to_value(PortModeView::Down {
            reason: DownReason::ReaderNotRunning,
        })
        .unwrap();
        assert_eq!(down["reason"], "reader_not_running");
        let lag = serde_json::to_string(&SmdrStreamEvent::Lagged { skipped: 3 }).unwrap();
        assert_eq!(lag, r#"{"event":"lagged","skipped":3}"#);
        assert_eq!(
            serde_json::from_str::<SmdrStreamEvent>(r#"{"event":"heartbeat"}"#).unwrap(),
            SmdrStreamEvent::Heartbeat
        );
    }

    #[test]
    fn limit_bounds_differ_by_boundary() {
        assert!(QueryLimit::new(0).is_err());
        assert_eq!(QueryLimit::new(500).map(QueryLimit::get), Ok(500));
        assert!(QueryLimit::new(501).is_err());
        assert_eq!(QueryLimit::mcp(100).map(QueryLimit::get), Ok(100));
        assert_eq!(
            QueryLimit::mcp(101),
            Err(SmdrApiError::BadLimit {
                max: MCP_QUERY_LIMIT_MAX
            })
        );
        assert!(serde_json::from_str::<QueryLimit>("501").is_err());
    }

    #[test]
    fn range_is_capped_at_31_days() {
        let mut p = SmdrQueryParams::with_defaults(None, Some(DAY_MS * 40), 0);
        assert_eq!(p.until_ms - p.since_ms, DEFAULT_RANGE_MS);
        assert_eq!(p.validate(), Ok(()));
        p.since_ms = p.until_ms - 31 * DAY_MS - DST_SLACK_MS;
        assert_eq!(p.validate(), Ok(()));
        p.since_ms -= 1;
        assert_eq!(
            p.validate(),
            Err(SmdrApiError::RangeTooLarge { max_days: 31 })
        );
        p.since_ms = p.until_ms;
        assert_eq!(p.validate(), Err(SmdrApiError::BadRange));
    }

    fn window(since_ms: i64, until_ms: i64) -> SmdrQueryParams {
        let mut p = SmdrQueryParams::with_defaults(None, Some(until_ms), 0);
        p.since_ms = since_ms;
        p
    }

    const OVER_SLACK_MS: i64 = 3_660_000;

    #[test]
    fn cap_is_utc_elapsed_across_spring_forward() {
        let since = 1_771_567_200_000;
        let until = 1_774_242_000_000;
        assert_eq!(until - since, 31 * DAY_MS - 3_600_000);
        assert_eq!(window(since, until).validate(), Ok(()));
        assert_eq!(
            window(since, since + 31 * DAY_MS + OVER_SLACK_MS).validate(),
            Err(SmdrApiError::RangeTooLarge { max_days: 31 })
        );
    }

    #[test]
    fn cap_is_utc_elapsed_across_fall_back() {
        let since = 1_792_040_400_000;
        let until = 1_794_722_400_000;
        assert_eq!(until - since, 31 * DAY_MS + 3_600_000);
        assert_eq!(window(since, until).validate(), Ok(()));
        assert_eq!(
            window(since, since + 31 * DAY_MS + OVER_SLACK_MS).validate(),
            Err(SmdrApiError::RangeTooLarge { max_days: 31 })
        );
    }

    #[test]
    fn cursor_round_trips_and_rejects_garbage() {
        let c = SmdrCursor::new("2026-11-01T12:00:00.000Z".into(), 7);
        assert_eq!(SmdrCursor::decode(&c.encode()), Ok(c));
        for bad in [
            "",
            "zz",
            "00",
            &hex::encode("x|1"),
            &hex::encode("2026-11-01T12:00:00.000Z|0"),
        ] {
            assert_eq!(
                SmdrCursor::decode(bad),
                Err(SmdrApiError::BadCursor),
                "{bad}"
            );
        }
    }

    #[test]
    fn call_view_has_raw_line_but_no_answered_or_mapped_cd_field() {
        let v = SmdrCallView {
            id: 1,
            rx_ts_utc: "2026-11-01T12:00:00.000Z".into(),
            pbx_local: "2026-11-01T06:00".into(),
            ext: "101".into(),
            co: "01".into(),
            direction: CallDirection::Incoming,
            number: "5550100".into(),
            cid_text: None,
            ring_s: None,
            duration_s: Some(3),
            acc: None,
            raw: Some("RAW".into()),
        };
        let json = serde_json::to_value(&v).expect("serialize");
        let keys: Vec<&str> = json
            .as_object()
            .expect("call view serializes as an object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        assert_eq!(
            keys,
            [
                "acc",
                "cid_text",
                "co",
                "direction",
                "duration_s",
                "ext",
                "id",
                "number",
                "pbx_local",
                "raw",
                "ring_s",
                "rx_ts_utc",
            ],
            "exact field set: raw line only, no cd or answered field"
        );
    }
}
