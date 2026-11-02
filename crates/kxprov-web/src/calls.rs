//! Read-only call-log page (S6). Fetches stored calls through the backend; no PBX access.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use chrono_tz::America::Chicago;
use kxprov_api::{
    CallDirection, GapWindow, QueryLimit, SmdrApiError, SmdrCallView, SmdrCursor, SmdrQueryParams,
};
use kxprov_mock::BackendError;
use serde::Deserialize;
use tower_sessions::Session;

use crate::WebState;
use axum::http::HeaderMap;
use axum::response::sse::{Event, Sse};
use axum::Json;
use kxprov_api::SmdrStreamEvent;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex, PoisonError};

/// Counts open live streams per session so one session holds at most
/// [`kxprov_api::SMDR_STREAMS_PER_SESSION`].
#[derive(Debug, Default)]
pub struct StreamLimiter {
    open: Mutex<HashMap<String, usize>>,
}

/// One open stream; dropping it frees the slot.
#[derive(Debug)]
pub struct StreamPermit {
    limiter: Arc<StreamLimiter>,
    key: String,
}

impl StreamLimiter {
    pub fn try_acquire(self: &Arc<Self>, key: &str) -> Option<StreamPermit> {
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        let n = open.entry(key.to_string()).or_insert(0);
        if *n >= kxprov_api::SMDR_STREAMS_PER_SESSION {
            return None;
        }
        *n += 1;
        Some(StreamPermit {
            limiter: Arc::clone(self),
            key: key.to_string(),
        })
    }

    pub fn open_for(&self, key: &str) -> usize {
        self.open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .copied()
            .unwrap_or(0)
    }
}

impl Drop for StreamPermit {
    fn drop(&mut self) {
        let mut open = self
            .limiter
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = open.get_mut(&self.key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                open.remove(&self.key);
            }
        }
    }
}

/// Rows per page on the web view.
pub const CALLS_PAGE_SIZE: u16 = 100;

#[derive(Debug, Default, Deserialize)]
pub struct CallsQuery {
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub to: String,
    #[serde(default)]
    pub ext: String,
    #[serde(default)]
    pub direction: String,
    #[serde(default)]
    pub cursor: String,
    /// Clock (Unix ms) the first page used, carried on "Older calls" links so the default
    /// last-24-hours window does not move while paging.
    #[serde(default)]
    pub at: String,
}

pub struct CallRow {
    pub time: String,
    pub ext: String,
    pub co: String,
    pub direction: &'static str,
    pub number: String,
    pub cid_text: String,
    pub ring_s: String,
    pub duration_s: String,
}

/// A reader gap shown inline among the calls.
pub struct GapRow {
    pub text: String,
    pub href: String,
}

/// One line of the call table: a call, or a marker where calls may be missing.
pub enum Entry {
    Call(CallRow),
    Gap(GapRow),
}

#[derive(Template)]
#[template(path = "calls.html")]
pub struct CallsTemplate {
    pub from_value: String,
    pub to_value: String,
    pub ext_value: String,
    pub direction_value: String,
    pub show_error: bool,
    pub error: String,
    pub entries: Vec<Entry>,
    pub show_next: bool,
    pub next_href: String,
    /// Newest unfiltered page: new calls are added live by `calls.js`.
    pub live_tail: bool,
    /// Newest call id rendered on the live page; the stream replays calls after it.
    pub live_since_id: String,
    /// Port state line above the table; empty when the status could not be read.
    pub banner: String,
}

/// Banner text for each port state (design §5).
pub fn banner_text(mode: &kxprov_api::PortModeView) -> String {
    use kxprov_api::{DownReason, PortModeView};
    match mode {
        PortModeView::Listening => "Listening".into(),
        PortModeView::PausedForProgramming { job_id } => {
            format!("Paused for programming session (job {job_id})")
        }
        PortModeView::Disabled => "Port disabled".into(),
        PortModeView::Down { reason } => {
            let why = match reason {
                DownReason::ReaderNotRunning => "reader not running",
                DownReason::LinkDown => "link down",
                _newer_reason_shown_generically => "unknown reason",
            };
            format!("Port down: {why}")
        }
        _newer_state_shown_generically => "Port state unknown".into(),
    }
}

fn chicago_midnight_ms(day: NaiveDate) -> Option<i64> {
    let naive = day.and_hms_opt(0, 0, 0)?;
    Chicago
        .from_local_datetime(&naive)
        .earliest()
        .map(|dt| dt.with_timezone(&Utc).timestamp_millis())
}

fn parse_day(raw: &str) -> Result<Option<NaiveDate>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    NaiveDate::parse_from_str(raw, "%Y-%m-%d")
        .map(Some)
        .map_err(|_| "Enter dates as YYYY-MM-DD.".to_string())
}

/// Turns the page's form values into a daemon query. Dates are US Central days; `to` is inclusive.
pub fn query_from_form(q: &CallsQuery, now_ms: i64) -> Result<SmdrQueryParams, String> {
    let bad_date = || "Enter dates as YYYY-MM-DD.".to_string();
    let from_day = parse_day(&q.from)?;
    let to_day = parse_day(&q.to)?;
    let since = from_day
        .or(to_day)
        .map(|d| chicago_midnight_ms(d).ok_or_else(bad_date))
        .transpose()?;
    let until = to_day
        .map(|d| {
            d.checked_add_signed(Duration::days(1))
                .and_then(chicago_midnight_ms)
                .ok_or_else(bad_date)
        })
        .transpose()?;
    let direction = match q.direction.trim() {
        "" => None,
        "incoming" => Some(CallDirection::Incoming),
        "outgoing" => Some(CallDirection::Outgoing),
        _ => return Err("Choose a direction from the list.".into()),
    };
    let cursor = match q.cursor.trim() {
        "" => None,
        c => Some(SmdrCursor::decode(c).map_err(|e| call_log_message(e).to_string())?),
    };
    let ext = Some(q.ext.trim().to_string()).filter(|e| !e.is_empty());
    let params = SmdrQueryParams {
        ext,
        direction,
        cursor,
        limit: QueryLimit::new(CALLS_PAGE_SIZE).map_err(|e| e.to_string())?,
        ..SmdrQueryParams::with_defaults(since, until, now_ms)
    };
    params
        .validate()
        .map_err(|e| call_log_message(e).to_string())?;
    Ok(params)
}

const UNKNOWN_ERROR_REASON: &str =
    "SmdrApiError is non_exhaustive; a variant added later is shown as unavailable until it gets its own text";

/// Plain-language text for each call-log failure.
pub fn call_log_message(e: SmdrApiError) -> &'static str {
    match e {
        SmdrApiError::ScopeDenied => "You don't have access to the call log.",
        SmdrApiError::RangeTooLarge { .. } => "Choose a range of 31 days or less.",
        SmdrApiError::BadRange => "The end date must be on or after the start date.",
        SmdrApiError::BadLimit { .. } => "That page size isn't allowed.",
        SmdrApiError::BadCursor => {
            "That page link is no longer valid. Start again from the newest calls."
        }
        SmdrApiError::StoreUnavailable => "Call log unavailable. Try again in a moment.",
        SmdrApiError::Disabled => "Port disabled. The call log is turned off.",
        SmdrApiError::CorruptRow { .. } => {
            "A stored call in this range is unreadable. Try a different range."
        }
        other => {
            tracing::warn!(reason = UNKNOWN_ERROR_REASON, ?other, "call log error");
            "Call log unavailable. Try again in a moment."
        }
    }
}

fn status_for(e: &BackendError) -> (StatusCode, String) {
    match e {
        BackendError::ForbiddenScope | BackendError::ForbiddenAdmin => (
            StatusCode::FORBIDDEN,
            call_log_message(SmdrApiError::ScopeDenied).into(),
        ),
        BackendError::CallLog(err) if err.is_client_error() => {
            (StatusCode::BAD_REQUEST, call_log_message(*err).into())
        }
        BackendError::CallLog(err) => (
            StatusCode::SERVICE_UNAVAILABLE,
            call_log_message(*err).into(),
        ),
        other => {
            tracing::warn!(reason = "backend error outside the call-log set", %other, "call log read failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                call_log_message(SmdrApiError::StoreUnavailable).into(),
            )
        }
    }
}

fn opt<T: ToString>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_default()
}

fn central(utc: &str) -> Result<String, chrono::ParseError> {
    DateTime::parse_from_rfc3339(utc).map(|t| {
        t.with_timezone(&Chicago)
            .format("%Y-%m-%d %H:%M:%S %Z")
            .to_string()
    })
}

fn row(c: SmdrCallView) -> CallRow {
    let time = central(&c.rx_ts_utc).unwrap_or_else(|e| {
        tracing::warn!(id = c.id, %e, "stored call time is not RFC 3339");
        format!("{} (UTC, unparsed time)", c.rx_ts_utc)
    });
    CallRow {
        time,
        ext: c.ext,
        co: c.co,
        direction: match c.direction {
            CallDirection::Incoming => "Incoming",
            CallDirection::Outgoing => "Outgoing",
        },
        number: c.number,
        cid_text: c.cid_text.unwrap_or_default(),
        ring_s: opt(c.ring_s),
        duration_s: opt(c.duration_s),
    }
}

fn gap_row(g: &GapWindow) -> GapRow {
    let when = |utc: &str| central(utc).unwrap_or_else(|_unparsed| format!("{utc} (UTC)"));
    let span = match &g.to_utc {
        Some(to) => format!("{} to {}", when(&g.from_utc), when(to)),
        None => format!("since {}, still running", when(&g.from_utc)),
    };
    GapRow {
        text: format!(
            "Calls during programming session {} ({span}) may be missing (#14).",
            g.job_id
        ),
        href: g.tracking.clone(),
    }
}

fn gap_key(g: &GapWindow) -> &str {
    g.to_utc.as_deref().unwrap_or("~")
}

/// Merges gaps into the newest-first calls: each gap sits above the first call older than its end.
///
/// `after` is the previous page's oldest call time (the cursor), `None` on the first page. A gap
/// ending after it was shown on an earlier page; any other gap shows on the page holding the
/// first call older than its end, or on the last page when no call is older, so paging shows
/// every marker exactly once.
pub fn entries(
    calls: Vec<SmdrCallView>,
    gaps: &[GapWindow],
    after: Option<&str>,
    last_page: bool,
) -> Vec<Entry> {
    let mut gaps: Vec<&GapWindow> = gaps.iter().collect();
    gaps.sort_by(|a, b| gap_key(b).cmp(gap_key(a)));
    let mut gaps = gaps.into_iter().peekable();
    let mut out = Vec::new();
    for c in calls {
        while let Some(g) = gaps.next_if(|g| gap_key(g) > c.rx_ts_utc.as_str()) {
            if after.is_none_or(|a| gap_key(g) <= a) {
                out.push(Entry::Gap(gap_row(g)));
            }
        }
        out.push(Entry::Call(row(c)));
    }
    if last_page {
        out.extend(gaps.map(|g| Entry::Gap(gap_row(g))));
    }
    out
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(b).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn next_href(q: &CallsQuery, cursor: &SmdrCursor, at_ms: i64) -> String {
    format!(
        "/calls?from={}&to={}&ext={}&direction={}&at={at_ms}&cursor={}",
        enc(q.from.trim()),
        enc(q.to.trim()),
        enc(q.ext.trim()),
        enc(q.direction.trim()),
        cursor.encode()
    )
}

/// The clock for this page: the first page's `at` when the link carries one that is not in the
/// future, otherwise now. A malformed `at` is treated as absent.
fn page_clock(q: &CallsQuery) -> i64 {
    let now = now_ms();
    q.at.trim()
        .parse::<i64>()
        .ok()
        .filter(|at| *at <= now)
        .unwrap_or(now)
}

fn blank(q: &CallsQuery) -> CallsTemplate {
    CallsTemplate {
        live_tail: false,
        live_since_id: String::new(),
        banner: String::new(),
        from_value: q.from.clone(),
        to_value: q.to.clone(),
        ext_value: q.ext.clone(),
        direction_value: q.direction.clone(),
        show_error: false,
        error: String::new(),
        entries: Vec::new(),
        show_next: false,
        next_href: String::new(),
    }
}

fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

pub async fn calls_page(
    State(state): State<WebState>,
    session: Session,
    Query(q): Query<CallsQuery>,
) -> Response {
    let mut tpl = blank(&q);
    let clock = page_clock(&q);
    let params = match query_from_form(&q, clock) {
        Ok(p) => p,
        Err(msg) => {
            tpl.show_error = true;
            tpl.error = msg;
            return (StatusCode::BAD_REQUEST, crate::render_page(&tpl)).into_response();
        }
    };
    let caller = crate::caller_from_session(&session);
    let client = kxprov_mock::ReadOnlyPbxClient::new(state.backend.clone());
    if let Ok(status) = client.smdr_status(&caller).await {
        tpl.banner = banner_text(&status.port_mode);
    }
    let after = params.cursor.as_ref().map(|c| c.rx_ts_utc().to_string());
    match client.smdr_query(&caller, params).await {
        Ok(page) => {
            if let Some(c) = &page.next {
                tpl.show_next = true;
                tpl.next_href = next_href(&q, c, clock);
            }
            let first_page = q.cursor.trim().is_empty();
            tpl.live_tail = first_page
                && [&q.to, &q.ext, &q.direction]
                    .iter()
                    .all(|v| v.trim().is_empty());
            if tpl.live_tail {
                tpl.live_since_id = page
                    .calls
                    .iter()
                    .map(|c| c.id)
                    .max()
                    .map(|id| id.to_string())
                    .unwrap_or_default();
            }
            tpl.entries = entries(
                page.calls,
                &page.gaps,
                after.as_deref(),
                page.next.is_none(),
            );
            crate::render_page(&tpl).into_response()
        }
        Err(e) => {
            let (status, msg) = status_for(&e);
            tpl.show_error = true;
            tpl.error = msg;
            (status, crate::render_page(&tpl)).into_response()
        }
    }
}

/// `GET /calls/status`: banner state and counters as JSON.
pub async fn calls_status(State(state): State<WebState>, session: Session) -> Response {
    let caller = crate::caller_from_session(&session);
    match kxprov_mock::ReadOnlyPbxClient::new(state.backend.clone())
        .smdr_status(&caller)
        .await
    {
        Ok(s) => Json(s).into_response(),
        Err(e) => status_for(&e).into_response(),
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct StreamQuery {
    pub since_id: Option<i64>,
}

fn sse_event(e: SmdrStreamEvent) -> Event {
    match e {
        SmdrStreamEvent::Call { call } => {
            let id = call.id.to_string();
            Event::default()
                .event("call")
                .id(id)
                .json_data(&call)
                .unwrap_or_else(|_unserializable| Event::default().comment("call not sent"))
        }
        SmdrStreamEvent::Lagged { skipped } => {
            Event::default().event("lagged").data(skipped.to_string())
        }
        SmdrStreamEvent::Heartbeat => Event::default().comment("heartbeat"),
        _newer_event_kind_this_page_ignores => Event::default().comment("ignored"),
    }
}

/// The browser's `Last-Event-ID`. A missing, non-ASCII or non-numeric value means "no
/// replay": the stream then starts live, and the page's own reload covers any gap.
fn last_event_id(headers: &HeaderMap) -> Option<i64> {
    let text = match headers.get("last-event-id")?.to_str() {
        Ok(t) => t,
        Err(_non_ascii_header_means_start_live_without_replay) => return None,
    };
    text.trim().parse().ok()
}

/// `GET /calls/stream`: Server-Sent Events of new calls. `since_id` or the browser's
/// `Last-Event-ID` replays calls missed while disconnected. At most four per session (429).
pub async fn calls_stream(
    State(state): State<WebState>,
    session: Session,
    headers: HeaderMap,
    Query(q): Query<StreamQuery>,
) -> Response {
    let caller = crate::caller_from_session(&session);
    let key = match &caller {
        kxprov_mock::CallerIdentity::Web(w) => w.session_key.clone(),
        kxprov_mock::CallerIdentity::Mcp(t) => t.token_id.0.clone(),
    };
    let Some(permit) = state.call_streams.try_acquire(&key) else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "Too many live call-log views are open. Close one and try again.",
        )
            .into_response();
    };
    let since_id = q.since_id.or_else(|| last_event_id(&headers));
    let rx = match kxprov_mock::ReadOnlyPbxClient::new(state.backend.clone())
        .smdr_subscribe(&caller, since_id)
        .await
    {
        Ok(rx) => rx,
        Err(e) => return status_for(&e).into_response(),
    };
    let stream = futures_util::stream::unfold((rx, permit), |(mut rx, permit)| async move {
        rx.recv()
            .await
            .map(|e| (Ok::<_, Infallible>(sse_event(e)), (rx, permit)))
    });
    Sse::new(stream).into_response()
}

/// Most rows one CSV export returns; a larger result is refused so the caller narrows the range.
pub const CSV_EXPORT_MAX_ROWS: usize = 10_000;

/// Header of the CSV export. `raw` is the PBX line as received (#97), not interpreted.
pub const CSV_HEADER: &str =
    "id,rx_ts_utc,pbx_local,ext,co,direction,number,cid_text,ring_s,duration_s,acc,raw";

/// One CSV cell: quoted when needed, with a leading `'` on text a spreadsheet would run as a
/// formula.
pub fn csv_cell(v: &str) -> String {
    let guarded = if v.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{v}")
    } else {
        v.to_string()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

fn csv_row(c: &SmdrCallView) -> String {
    let opt_num = |n: Option<u32>| n.map(|v| v.to_string()).unwrap_or_default();
    let direction = match c.direction {
        CallDirection::Incoming => "incoming",
        CallDirection::Outgoing => "outgoing",
    };
    [
        c.id.to_string(),
        csv_cell(&c.rx_ts_utc),
        csv_cell(&c.pbx_local),
        csv_cell(&c.ext),
        csv_cell(&c.co),
        direction.to_string(),
        csv_cell(&c.number),
        csv_cell(c.cid_text.as_deref().unwrap_or("")),
        opt_num(c.ring_s),
        opt_num(c.duration_s),
        csv_cell(c.acc.as_deref().unwrap_or("")),
        csv_cell(c.raw.as_deref().unwrap_or("")),
    ]
    .join(",")
}

fn plain(status: StatusCode, msg: String) -> Response {
    (
        status,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        msg,
    )
        .into_response()
}

/// `GET /calls/export.csv`: the same filters, range cap and scope check as `/calls`, every page
/// of the range, at most [`CSV_EXPORT_MAX_ROWS`] rows. Logs only the row count.
pub async fn calls_export_csv(
    State(state): State<WebState>,
    session: Session,
    Query(q): Query<CallsQuery>,
) -> Response {
    let mut params = match query_from_form(&q, now_ms()) {
        Ok(p) => p,
        Err(msg) => return plain(StatusCode::BAD_REQUEST, msg),
    };
    params.cursor = None;
    params.limit = match QueryLimit::new(kxprov_api::QUERY_LIMIT_MAX) {
        Ok(l) => l,
        Err(e) => return plain(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let caller = crate::caller_from_session(&session);
    let client = kxprov_mock::ReadOnlyPbxClient::new(state.backend.clone());
    let mut out = String::from(CSV_HEADER);
    out.push_str("\r\n");
    let mut rows = 0usize;
    loop {
        let page = match client.smdr_query(&caller, params.clone()).await {
            Ok(p) => p,
            Err(e) => {
                let (status, msg) = status_for(&e);
                return plain(status, msg);
            }
        };
        rows += page.calls.len();
        if rows > CSV_EXPORT_MAX_ROWS {
            tracing::info!(
                limit = CSV_EXPORT_MAX_ROWS,
                "calls csv export refused: too many rows"
            );
            return plain(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("More than {CSV_EXPORT_MAX_ROWS} calls in this range. Narrow the dates or filters."),
            );
        }
        for c in &page.calls {
            out.push_str(&csv_row(c));
            out.push_str("\r\n");
        }
        match page.next {
            Some(next) => params.cursor = Some(next),
            None => break,
        }
    }
    tracing::info!(rows, "calls csv export");
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"calls.csv\"",
            ),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        out,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_central_days_and_to_is_inclusive() {
        let q = CallsQuery {
            from: "2026-11-01".into(),
            to: "2026-11-01".into(),
            ..CallsQuery::default()
        };
        let p = query_from_form(&q, 0).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            p.until_ms - p.since_ms,
            25 * 3_600_000,
            "DST ends on 2026-11-01 in Chicago"
        );
        let start = DateTime::<Utc>::from_timestamp_millis(p.since_ms).map(|d| d.to_rfc3339());
        assert_eq!(start.as_deref(), Some("2026-11-01T05:00:00+00:00"));
    }

    #[test]
    fn a_lone_to_date_is_that_whole_central_day() {
        let q = CallsQuery {
            to: "2026-11-01".into(),
            ..CallsQuery::default()
        };
        let p = query_from_form(&q, 0).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p.until_ms - p.since_ms, 25 * 3_600_000);
        let start = DateTime::<Utc>::from_timestamp_millis(p.since_ms).map(|d| d.to_rfc3339());
        assert_eq!(start.as_deref(), Some("2026-11-01T05:00:00+00:00"));
    }

    #[test]
    fn thirty_one_central_days_across_the_fall_change_are_accepted() {
        let q = CallsQuery {
            from: "2026-10-15".into(),
            to: "2026-11-14".into(),
            ..CallsQuery::default()
        };
        let p = query_from_form(&q, 0).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p.until_ms - p.since_ms, (31 * 24 + 1) * 3_600_000);
        let q = CallsQuery {
            from: "2026-10-15".into(),
            to: "2026-11-15".into(),
            ..CallsQuery::default()
        };
        assert!(query_from_form(&q, 0).is_err(), "32 days is still too long");
    }

    #[test]
    fn bad_form_values_are_messages_not_panics() {
        for q in [
            CallsQuery {
                from: "11/01/2026".into(),
                ..CallsQuery::default()
            },
            CallsQuery {
                from: "2026-01-01".into(),
                to: "2026-03-01".into(),
                ..CallsQuery::default()
            },
            CallsQuery {
                from: "2026-03-02".into(),
                to: "2026-03-01".into(),
                ..CallsQuery::default()
            },
            CallsQuery {
                direction: "answered".into(),
                ..CallsQuery::default()
            },
            CallsQuery {
                cursor: "<script>".into(),
                ..CallsQuery::default()
            },
        ] {
            assert!(query_from_form(&q, 1_800_000_000_000).is_err(), "{q:?}");
        }
    }

    fn view(id: i64, ts: &str) -> SmdrCallView {
        SmdrCallView {
            id,
            rx_ts_utc: ts.into(),
            pbx_local: String::new(),
            ext: "101".into(),
            co: "01".into(),
            direction: CallDirection::Incoming,
            number: String::new(),
            cid_text: None,
            ring_s: None,
            duration_s: None,
            acc: None,
            raw: None,
        }
    }

    fn gap(job: &str, from: &str, to: Option<&str>) -> GapWindow {
        GapWindow {
            from_utc: from.into(),
            to_utc: to.map(Into::into),
            job_id: job.into(),
            tracking: kxprov_api::GAP_TRACKING.into(),
        }
    }

    fn shape(e: &[Entry]) -> Vec<String> {
        e.iter()
            .map(|e| match e {
                Entry::Call(c) => c.time.clone(),
                Entry::Gap(g) => g.text.clone(),
            })
            .collect()
    }

    #[test]
    fn gaps_sit_inline_above_the_first_older_call_and_link_issue_14() {
        let calls = vec![
            view(3, "2026-11-01T18:00:00.000Z"),
            view(2, "2026-11-01T16:00:00.000Z"),
            view(1, "2026-11-01T14:00:00.000Z"),
        ];
        let gaps = [
            gap(
                "old",
                "2026-11-01T12:00:00.000Z",
                Some("2026-11-01T12:10:00.000Z"),
            ),
            gap(
                "mid",
                "2026-11-01T16:30:00.000Z",
                Some("2026-11-01T17:00:00.000Z"),
            ),
            gap("live", "2026-11-01T19:00:00.000Z", None),
        ];
        let all = entries(calls.clone(), &gaps, None, true);
        let s = shape(&all);
        assert_eq!(s.len(), 6);
        assert!(
            s[0].contains("session live (since 2026-11-01 13:00:00 CST, still running)"),
            "{}",
            s[0]
        );
        assert!(s[1].starts_with("2026-11-01 12:00:00 CST"), "{}", s[1]);
        assert!(s[2].contains("session mid (2026-11-01 10:30:00 CST to 2026-11-01 11:00:00 CST) may be missing (#14)"), "{}", s[2]);
        assert!(s[5].contains("session old"), "{}", s[5]);
        assert!(all.iter().all(|e| match e {
            Entry::Gap(g) => g.href == "https://github.com/mitchmitchell/panasonic/issues/14",
            Entry::Call(_) => true,
        }));
        let middle = shape(&entries(
            calls.clone(),
            &gaps,
            Some("2026-11-01T18:30:00.000Z"),
            false,
        ));
        assert_eq!(
            middle.len(),
            4,
            "edge gaps belong to the first and last pages only"
        );
        assert!(middle[1].contains("session mid"));
    }

    #[test]
    fn a_gap_on_a_page_boundary_shows_once_on_the_later_page() {
        let gaps = [gap(
            "edge",
            "2026-11-01T14:30:00.000Z",
            Some("2026-11-01T15:00:00.000Z"),
        )];
        let first = shape(&entries(
            vec![
                view(3, "2026-11-01T18:00:00.000Z"),
                view(2, "2026-11-01T16:00:00.000Z"),
            ],
            &gaps,
            None,
            false,
        ));
        let second = shape(&entries(
            vec![view(1, "2026-11-01T14:00:00.000Z")],
            &gaps,
            Some("2026-11-01T16:00:00.000Z"),
            true,
        ));
        assert_eq!(
            first.iter().filter(|e| e.contains("session edge")).count(),
            0
        );
        assert_eq!(second.len(), 2);
        assert!(second[0].contains("session edge"), "{}", second[0]);
    }

    #[test]
    fn page_clock_keeps_a_past_at_and_ignores_future_or_garbage() {
        let q = |at: &str| CallsQuery {
            at: at.into(),
            ..CallsQuery::default()
        };
        assert_eq!(page_clock(&q("1000")), 1000);
        let now = now_ms();
        assert!(page_clock(&q(&(now + 86_400_000).to_string())) >= now);
        assert!(page_clock(&q("soon")) >= now);
    }
}
