#![allow(
    clippy::unwrap_used,
    reason = "test setup failures should abort the test"
)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use kxprov_api::{CallDirection, SmdrCallView};
use kxprov_mock::MockDaemon;
use kxprov_web::{LoginRateLimiter, WebState};
use support::TestVerifier;
use tower::ServiceExt;
use tower_sessions::{MemoryStore, SessionManagerLayer};

fn call(id: i64, rx_ts: &str, number: &str, cid: &str) -> SmdrCallView {
    SmdrCallView {
        id,
        rx_ts_utc: rx_ts.into(),
        pbx_local: String::new(),
        ext: "101".into(),
        co: "01".into(),
        direction: CallDirection::Incoming,
        number: number.into(),
        cid_text: Some(cid.into()),
        ring_s: Some(4),
        duration_s: Some(30),
        acc: None,
    }
}

fn ms(rfc: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(rfc)
        .unwrap()
        .timestamp_millis()
}

async fn app(calls: Vec<SmdrCallView>) -> Router {
    let mock = MockDaemon::new();
    for c in calls {
        mock.test_add_call(ms(&c.rx_ts_utc), c).await;
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

async fn get(app: Router, uri: &str) -> (StatusCode, String) {
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn caller_id_text_is_html_escaped() {
    let app = app(vec![call(
        1,
        "2026-10-20T15:00:00.000Z",
        "5550100",
        "<script>alert(1)</script>&\"",
    )])
    .await;
    let (status, html) = get(app, "/calls?from=2026-10-20&to=2026-10-20").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!html.contains("<script>alert"), "{html}");
    assert!(
        html.contains("&lt;script&gt;alert(1)&lt;/script&gt;&amp;"),
        "{html}"
    );
    assert!(html.contains("2026-10-20 10:00:00 CDT"), "{html}");
}

#[tokio::test]
async fn page_shows_no_answered_status_or_cd_code() {
    let app = app(vec![call(1, "2026-10-20T15:00:00.000Z", "5550100", "A")]).await;
    let (_, html) = get(app, "/calls?from=2026-10-20&to=2026-10-20").await;
    let lower = html.to_ascii_lowercase();
    assert!(!lower.contains("answered"), "{html}");
    assert!(!lower.contains("missed"), "{html}");
    assert!(!html.contains(">XX<"), "{html}");
}

#[tokio::test]
async fn empty_range_shows_an_empty_state() {
    let app = app(vec![]).await;
    let (status, html) = get(app, "/calls").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("No calls in this range."), "{html}");
}

#[tokio::test]
async fn filters_and_older_link_page_through_results() {
    let calls: Vec<SmdrCallView> = (1..=150)
        .map(|i| {
            let ts = format!("2026-10-20T15:{:02}:{:02}.000Z", i / 60, i % 60);
            call(i, &ts, &format!("555{i:04}"), "x")
        })
        .collect();
    let app = app(calls).await;
    let (_, first) = get(
        app.clone(),
        "/calls?from=2026-10-20&to=2026-10-20&ext=101&direction=incoming",
    )
    .await;
    assert!(first.contains("5550150") && first.contains("5550051"));
    assert!(!first.contains("5550050"));
    let href = first
        .split("<a href=\"")
        .find(|s| s.starts_with("/calls?"))
        .and_then(|s| s.split('"').next())
        .unwrap()
        .replace("&amp;", "&");
    let (_, second) = get(app.clone(), &href).await;
    assert!(second.contains("5550050") && second.contains("5550001"));
    assert!(!second.contains("5550051"));
    assert!(!second.contains("Older calls"));
    let (_, outgoing) = get(
        app,
        "/calls?from=2026-10-20&to=2026-10-20&direction=outgoing",
    )
    .await;
    assert!(outgoing.contains("No calls in this range."));
}

#[tokio::test]
async fn bad_filters_are_400_with_a_message() {
    let app = app(vec![]).await;
    for uri in [
        "/calls?from=2026-01-01&to=2026-03-01",
        "/calls?cursor=%3Cscript%3E",
        "/calls?from=yesterday",
        "/calls?direction=answered",
    ] {
        let (status, html) = get(app.clone(), uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert!(html.contains("role=\"alert\""), "{uri}");
        assert!(!html.contains("<script>"), "{uri}");
    }
}
