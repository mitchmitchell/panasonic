#![allow(
    clippy::unwrap_used,
    reason = "test setup failures should abort the test"
)]

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use kxprov_api::{Profile, SMDR_STREAMS_PER_SESSION};
use kxprov_gw::daemon_client::DaemonClient;
use kxprov_mock::DaemonBackend;
use kxprovd::test_util::{ingest_smdr_bytes, synthetic_smdr_bytes, GATEWAY_SECRET};
use tower::ServiceExt;
use tower_sessions::{MemoryStore, SessionManagerLayer};

const RSS_BUDGET_KIB: u64 = 20 * 1024;
const CALLS: usize = 2_000;
const BATCH: usize = 100;

fn rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reader_plus_four_sse_clients_stay_within_the_rss_budget_on_the_sim() {
    let tmp = tempfile::TempDir::new().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (daemon, sock) =
        kxprovd::Daemon::sim_for_tests_as_gateway_profile(tmp.path(), uid, Profile::Sim);
    for _ in 0..200 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let data_dir = kxprovd::config::profile_data_dir(tmp.path(), Profile::Sim);
    ingest_smdr_bytes(&data_dir, daemon.smdr_live(), b"");
    let client = DaemonClient::connect(&sock, GATEWAY_SECRET.to_string())
        .await
        .unwrap();
    let backend: Arc<dyn DaemonBackend> = client;
    let state = kxprov_web::WebState {
        call_streams: Default::default(),
        backend,
        admin: Arc::new(support::TestVerifier),
        login_limiter: Arc::new(kxprov_web::LoginRateLimiter::new(
            Duration::from_secs(1),
            Duration::from_secs(30),
            Duration::from_secs(300),
        )),
    };
    let app = kxprov_web::router(state).layer(SessionManagerLayer::new(MemoryStore::default()));

    let seen = Arc::new(AtomicUsize::new(0));
    let mut readers = Vec::new();
    for _ in 0..SMDR_STREAMS_PER_SESSION {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/calls/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let seen = Arc::clone(&seen);
        readers.push(tokio::spawn(async move {
            let mut body = resp.into_body();
            while let Some(Ok(frame)) = body.frame().await {
                if let Ok(data) = frame.into_data() {
                    let text = String::from_utf8_lossy(&data);
                    seen.fetch_add(text.matches("event: call").count(), Ordering::Relaxed);
                }
            }
        }));
    }

    let mut peak = 0;
    for batch in 0..CALLS / BATCH {
        let live = daemon.smdr_live();
        let dir = data_dir.clone();
        let stored = tokio::task::spawn_blocking(move || {
            ingest_smdr_bytes(&dir, live, &synthetic_smdr_bytes(batch * BATCH, BATCH))
        })
        .await
        .unwrap();
        assert_eq!(stored, BATCH);
        peak = peak.max(rss_kib());
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        while seen.load(Ordering::Relaxed) < CALLS * SMDR_STREAMS_PER_SESSION {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("clients saw {} call events", seen.load(Ordering::Relaxed)));
    let steady = rss_kib();
    eprintln!("rss peak {peak} KiB, steady {steady} KiB, budget {RSS_BUDGET_KIB} KiB");
    assert!(
        peak.max(steady) <= RSS_BUDGET_KIB,
        "RSS peak {peak} KiB, steady {steady} KiB, over the {RSS_BUDGET_KIB} KiB budget"
    );
    for r in readers {
        r.abort();
    }
}
