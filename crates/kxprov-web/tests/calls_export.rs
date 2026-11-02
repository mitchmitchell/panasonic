#![allow(
    clippy::unwrap_used,
    reason = "test setup failures should abort the test"
)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use kxprov_api::{CallDirection, SmdrCallView};
use kxprov_mock::MockDaemon;
use kxprov_web::{csv_cell, CSV_EXPORT_MAX_ROWS, CSV_HEADER};
use kxprov_web::{LoginRateLimiter, WebState};
use support::TestVerifier;
use tower::ServiceExt;
use tower_sessions::{MemoryStore, SessionManagerLayer};

fn call(id: i64, rx_ts: &str, ext: &str, direction: CallDirection, cid: &str) -> SmdrCallView {
    SmdrCallView {
        id,
        rx_ts_utc: rx_ts.into(),
        pbx_local: "2026-10-20T10:00".into(),
        ext: ext.into(),
        co: "01".into(),
        direction,
        number: format!("555{id:04}"),
        cid_text: Some(cid.into()),
        ring_s: Some(4),
        duration_s: Some(30),
        acc: None,
        raw: Some(format!("RAW {id} CD")),
    }
}

fn ts(i: i64) -> String {
    format!(
        "2026-10-20T{:02}:{:02}:{:02}.000Z",
        12 + i / 3600,
        (i / 60) % 60,
        i % 60
    )
}

async fn app(calls: Vec<SmdrCallView>) -> Router {
    let mock = MockDaemon::new();
    for c in calls {
        let ms = chrono::DateTime::parse_from_rfc3339(&c.rx_ts_utc)
            .unwrap()
            .timestamp_millis();
        mock.test_add_call(ms, c).await;
    }
    let state = WebState {
        call_streams: Default::default(),
        backend: Arc::new(mock),
        admin: Arc::new(TestVerifier),
        login_limiter: Arc::new(LoginRateLimiter::new(
            Duration::from_secs(1),
            Duration::from_secs(30),
            Duration::from_secs(300),
        )),
    };
    kxprov_web::router(state).layer(SessionManagerLayer::new(MemoryStore::default()))
}

async fn get(app: Router, uri: &str) -> (StatusCode, Option<String>, String) {
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let ctype = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_string());
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, ctype, String::from_utf8_lossy(&bytes).into_owned())
}

const DAY: &str = "/calls/export.csv?from=2026-10-20&to=2026-10-20";

#[tokio::test]
async fn export_applies_the_page_filters() {
    let app = app(vec![
        call(1, &ts(1), "101", CallDirection::Incoming, "a"),
        call(2, &ts(2), "102", CallDirection::Incoming, "b"),
        call(3, &ts(3), "101", CallDirection::Outgoing, "c"),
        call(
            4,
            "2026-10-25T12:00:00.000Z",
            "101",
            CallDirection::Incoming,
            "d",
        ),
    ])
    .await;
    let (status, ctype, csv) = get(app, &format!("{DAY}&ext=101&direction=incoming")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ctype.as_deref(), Some("text/csv; charset=utf-8"));
    let lines: Vec<&str> = csv.split("\r\n").filter(|l| !l.is_empty()).collect();
    assert_eq!(lines[0], CSV_HEADER);
    assert_eq!(lines.len(), 2, "{csv}");
    assert!(lines[1].starts_with("1,"), "{csv}");
    assert!(lines[1].ends_with(",RAW 1 CD"), "{csv}");
}

#[tokio::test]
async fn export_walks_every_page_of_the_range() {
    let calls = (1..=1200)
        .map(|i| call(i, &ts(i), "101", CallDirection::Incoming, "x"))
        .collect();
    let (status, _, csv) = get(app(calls).await, DAY).await;
    assert_eq!(status, StatusCode::OK);
    let ids: Vec<i64> = csv
        .split("\r\n")
        .skip(1)
        .filter(|l| !l.is_empty())
        .map(|l| l.split(',').next().unwrap().parse().unwrap())
        .collect();
    assert_eq!(ids, (1..=1200).rev().collect::<Vec<_>>());
}

#[tokio::test]
async fn export_streams_one_page_per_frame() {
    let calls = (1..=1200)
        .map(|i| call(i, &ts(i), "101", CallDirection::Incoming, "x"))
        .collect();
    let resp = app(calls)
        .await
        .oneshot(Request::builder().uri(DAY).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();
    let mut frames = 0;
    while let Some(frame) = body.frame().await {
        if frame.unwrap().is_data() {
            frames += 1;
        }
    }
    assert_eq!(frames, 3, "1200 rows at 500 per query page");
}

#[tokio::test]
async fn export_over_the_row_cap_ends_the_body_with_an_error() {
    let n = i64::try_from(CSV_EXPORT_MAX_ROWS).unwrap() + 1;
    let calls = (1..=n)
        .map(|i| call(i, &ts(i), "101", CallDirection::Incoming, "x"))
        .collect();
    let resp = app(calls)
        .await
        .oneshot(Request::builder().uri(DAY).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();
    let mut rows = 0usize;
    let mut failed = false;
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(f) => {
                if let Some(d) = f.data_ref() {
                    rows += d.iter().filter(|b| **b == b'\n').count();
                }
            }
            Err(e) => {
                assert!(e.to_string().contains("more than"), "{e}");
                failed = true;
            }
        }
    }
    assert!(failed, "an over-cap export must not end cleanly");
    assert!(rows <= CSV_EXPORT_MAX_ROWS + 1, "{rows}");
}

#[tokio::test]
async fn export_keeps_the_query_range_cap_and_filter_checks() {
    let app = app(vec![]).await;
    for uri in [
        "/calls/export.csv?from=2026-01-01&to=2026-03-01",
        "/calls/export.csv?from=yesterday",
        "/calls/export.csv?direction=answered",
    ] {
        let (status, _, _) = get(app.clone(), uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
    }
}

#[tokio::test]
async fn export_has_no_interpreted_columns() {
    let header: Vec<&str> = CSV_HEADER.split(',').collect();
    for absent in ["answered", "cd", "disposition", "status"] {
        assert!(!header.contains(&absent), "{absent}");
    }
}

#[tokio::test]
async fn cells_are_quoted_and_formula_guarded() {
    assert_eq!(csv_cell("SMITH JANE"), "SMITH JANE");
    assert_eq!(csv_cell("a,b\"c"), "\"a,b\"\"c\"");
    assert_eq!(csv_cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
    assert_eq!(csv_cell("@SUM(1)"), "'@SUM(1)");
    assert_eq!(csv_cell("line\nbreak"), "\"line\nbreak\"");
    let app = app(vec![call(
        1,
        &ts(1),
        "101",
        CallDirection::Incoming,
        "=cmd|' /C calc'!A0",
    )])
    .await;
    let (_, _, csv) = get(app, DAY).await;
    assert!(csv.contains(",'=cmd|' /C calc'!A0,"), "{csv}");
}
