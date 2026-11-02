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
use kxprov_api::{CallDirection, PortModeView, SmdrCallView, SMDR_STREAMS_PER_SESSION};
use kxprov_mock::MockDaemon;
use kxprov_web::{LoginRateLimiter, WebState};
use support::TestVerifier;
use tower::ServiceExt;
use tower_sessions::{MemoryStore, SessionManagerLayer};

const WAIT: Duration = Duration::from_secs(10);

fn call(id: i64) -> SmdrCallView {
    SmdrCallView {
        id,
        rx_ts_utc: format!("2026-10-20T15:00:{:02}.000Z", id % 60),
        pbx_local: String::new(),
        ext: "101".into(),
        co: "01".into(),
        direction: CallDirection::Incoming,
        number: format!("555{id:04}"),
        cid_text: None,
        ring_s: Some(4),
        duration_s: Some(30),
        acc: None,
        raw: None,
    }
}

fn app(mock: Arc<MockDaemon>) -> Router {
    let state = WebState {
        call_streams: Default::default(),
        backend: mock,
        admin: Arc::new(TestVerifier),
        login_limiter: Arc::new(LoginRateLimiter::new(
            Duration::from_secs(1),
            Duration::from_secs(30),
            Duration::from_secs(300),
        )),
    };
    kxprov_web::router(state).layer(SessionManagerLayer::new(MemoryStore::default()))
}

async fn open(app: &Router, uri: &str, last_event_id: Option<&str>) -> axum::response::Response {
    let mut req = Request::builder().uri(uri);
    if let Some(id) = last_event_id {
        req = req.header("last-event-id", id);
    }
    app.clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn read_until(body: &mut Body, needle: &str) -> String {
    let mut seen = String::new();
    tokio::time::timeout(WAIT, async {
        while !seen.contains(needle) {
            let frame = body.frame().await.unwrap().unwrap();
            if let Ok(data) = frame.into_data() {
                seen.push_str(&String::from_utf8_lossy(&data));
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {needle:?} in {seen:?}"));
    seen
}

#[tokio::test]
async fn new_calls_arrive_as_sse_call_events_with_ids() {
    let mock = Arc::new(MockDaemon::new());
    let app = app(Arc::clone(&mock));
    let resp = open(&app, "/calls/stream", None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/event-stream"));
    let mut body = resp.into_body();
    mock.test_add_call(0, call(7)).await;
    let seen = read_until(&mut body, "5550007").await;
    assert!(seen.contains("event: call"), "{seen}");
    assert!(seen.contains("id: 7"), "{seen}");
}

#[tokio::test]
async fn since_id_and_last_event_id_replay_missed_calls() {
    let mock = Arc::new(MockDaemon::new());
    for id in 1..=3 {
        mock.test_add_call(0, call(id)).await;
    }
    let app = app(Arc::clone(&mock));
    let mut body = open(&app, "/calls/stream?since_id=1", None)
        .await
        .into_body();
    let seen = read_until(&mut body, "5550003").await;
    assert!(
        seen.contains("5550002") && !seen.contains("5550001"),
        "{seen}"
    );
    let mut body = open(&app, "/calls/stream", Some("2")).await.into_body();
    let seen = read_until(&mut body, "5550003").await;
    assert!(!seen.contains("5550002"), "{seen}");
}

#[tokio::test]
async fn heartbeat_is_an_sse_comment() {
    let mock = Arc::new(MockDaemon::new());
    mock.test_set_heartbeat(Duration::from_millis(20)).await;
    let app = app(Arc::clone(&mock));
    let mut body = open(&app, "/calls/stream", None).await.into_body();
    read_until(&mut body, ": heartbeat").await;
}

#[tokio::test]
async fn a_slow_reader_gets_lagged_instead_of_blocking_ingest() {
    let mock = Arc::new(MockDaemon::new());
    let app = app(Arc::clone(&mock));
    let mut body = open(&app, "/calls/stream", None).await.into_body();
    tokio::time::timeout(WAIT, async {
        for id in 1..=600 {
            mock.test_add_call(0, call(id)).await;
        }
    })
    .await
    .expect("publishing must not wait for the reader");
    let seen = read_until(&mut body, "event: lagged").await;
    assert!(seen.contains("event: lagged"), "{seen}");
}

#[tokio::test]
async fn a_session_gets_four_streams_then_429_until_one_closes() {
    let mock = Arc::new(MockDaemon::new());
    let app = app(mock);
    let mut held = Vec::new();
    for _ in 0..SMDR_STREAMS_PER_SESSION {
        let resp = open(&app, "/calls/stream", None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        held.push(resp);
    }
    let over = open(&app, "/calls/stream", None).await;
    assert_eq!(over.status(), StatusCode::TOO_MANY_REQUESTS);
    drop(held.pop());
    let again = open(&app, "/calls/stream", None).await;
    assert_eq!(again.status(), StatusCode::OK);
}

#[tokio::test]
async fn status_route_returns_the_banner_state_as_json() {
    let mock = Arc::new(MockDaemon::new());
    mock.test_set_port_mode(PortModeView::PausedForProgramming {
        job_id: "job-42".into(),
    })
    .await;
    let app = app(Arc::clone(&mock));
    let resp = open(&app, "/calls/status", None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["port_mode"]["state"], "paused_for_programming");
    assert_eq!(v["port_mode"]["job_id"], "job-42");
}

#[tokio::test]
async fn newest_unfiltered_page_loads_the_live_script_and_filtered_pages_do_not() {
    let mock = Arc::new(MockDaemon::new());
    mock.test_add_call(0, call(1)).await;
    let app = app(mock);
    let page = |uri: &'static str| {
        let app = app.clone();
        async move {
            let resp = open(&app, uri, None).await;
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            String::from_utf8_lossy(&bytes).into_owned()
        }
    };
    assert!(page("/calls").await.contains("/static/calls.js"));
    assert!(!page("/calls?ext=101").await.contains("/static/calls.js"));
    let js = page("/static/calls.js").await;
    assert!(js.contains("EventSource") && !js.contains("innerHTML"));
}

async fn add_dated(mock: &MockDaemon, c: SmdrCallView) {
    let ms = chrono::DateTime::parse_from_rfc3339(&c.rx_ts_utc)
        .unwrap()
        .timestamp_millis();
    mock.test_add_call(ms, c).await;
}

async fn page_body(app: &Router, uri: &str) -> (StatusCode, String) {
    let resp = open(app, uri, None).await;
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn banner_names_every_port_state_and_paused_still_serves_history() {
    use kxprov_api::DownReason;
    let mock = Arc::new(MockDaemon::new());
    add_dated(&mock, call(1)).await;
    let app = app(Arc::clone(&mock));
    let cases = [
        (PortModeView::Listening, "Listening"),
        (
            PortModeView::PausedForProgramming {
                job_id: "job-9".into(),
            },
            "Paused for programming session (job job-9)",
        ),
        (
            PortModeView::Down {
                reason: DownReason::ReaderNotRunning,
            },
            "Port down: reader not running",
        ),
        (
            PortModeView::Down {
                reason: DownReason::LinkDown,
            },
            "Port down: link down",
        ),
    ];
    for (mode, text) in cases {
        mock.test_set_port_mode(mode).await;
        let (status, html) = page_body(&app, "/calls?from=2026-10-01&to=2026-10-31").await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains(&format!(">{text}</p>")), "{text}: {html}");
        assert!(html.contains("5550001"), "history hidden for {text}");
    }
}

#[tokio::test]
async fn disabled_port_hides_history_and_says_port_disabled() {
    let mock = Arc::new(MockDaemon::new());
    add_dated(&mock, call(1)).await;
    mock.test_set_port_mode(PortModeView::Disabled).await;
    let app = app(Arc::clone(&mock));
    let (_, html) = page_body(&app, "/calls?from=2026-10-01&to=2026-10-31").await;
    assert!(html.contains(">Port disabled</p>"), "{html}");
    assert!(!html.contains("5550001"), "{html}");
    let stream = open(&app, "/calls/stream", None).await;
    assert_ne!(stream.status(), StatusCode::OK);
}
