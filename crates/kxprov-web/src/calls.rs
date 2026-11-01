//! Read-only call-log page (S6). Fetches stored calls through the backend; no PBX access.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use chrono_tz::America::Chicago;
use kxprov_api::{
    CallDirection, QueryLimit, SmdrApiError, SmdrCallView, SmdrCursor, SmdrQueryParams,
};
use kxprov_mock::BackendError;
use serde::Deserialize;
use tower_sessions::Session;

use crate::WebState;

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

#[derive(Template)]
#[template(path = "calls.html")]
pub struct CallsTemplate {
    pub from_value: String,
    pub to_value: String,
    pub ext_value: String,
    pub direction_value: String,
    pub show_error: bool,
    pub error: String,
    pub calls: Vec<CallRow>,
    pub show_next: bool,
    pub next_href: String,
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

fn row(c: SmdrCallView) -> CallRow {
    let time = DateTime::parse_from_rfc3339(&c.rx_ts_utc)
        .map(|t| {
            t.with_timezone(&Chicago)
                .format("%Y-%m-%d %H:%M:%S %Z")
                .to_string()
        })
        .unwrap_or_else(|e| {
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

fn next_href(q: &CallsQuery, cursor: &SmdrCursor) -> String {
    format!(
        "/calls?from={}&to={}&ext={}&direction={}&cursor={}",
        enc(q.from.trim()),
        enc(q.to.trim()),
        enc(q.ext.trim()),
        enc(q.direction.trim()),
        cursor.encode()
    )
}

fn blank(q: &CallsQuery) -> CallsTemplate {
    CallsTemplate {
        from_value: q.from.clone(),
        to_value: q.to.clone(),
        ext_value: q.ext.clone(),
        direction_value: q.direction.clone(),
        show_error: false,
        error: String::new(),
        calls: Vec::new(),
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
    let params = match query_from_form(&q, now_ms()) {
        Ok(p) => p,
        Err(msg) => {
            tpl.show_error = true;
            tpl.error = msg;
            return (StatusCode::BAD_REQUEST, crate::render_page(&tpl)).into_response();
        }
    };
    let caller = crate::caller_from_session(&session);
    match state.backend.smdr_query(&caller, params).await {
        Ok(page) => {
            if let Some(c) = &page.next {
                tpl.show_next = true;
                tpl.next_href = next_href(&q, c);
            }
            tpl.calls = page.calls.into_iter().map(row).collect();
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
}
