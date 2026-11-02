#![allow(
    clippy::unwrap_used,
    reason = "test setup failures should abort the test"
)]

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use kxprov_api::{Profile, SmdrQueryParams, SmdrStreamEvent};
use kxprov_gw::daemon_client::DaemonClient;
use kxprov_mock::{CallerIdentity, DaemonBackend, WebSessionIdentity};
use kxprovd::test_util::{ingest_smdr_bytes, smdr_fixture, GATEWAY_SECRET};
use tower::ServiceExt;
use tower_sessions::{MemoryStore, SessionManagerLayer};

const WRONG_SECRET: &str = "pii-capture-wrong-gateway-secret-7b1c";
const CALLER_DATA: [&str; 4] = ["5551230000", "5559870000", "DOE JOHN", "SMITH JANE"];

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn get(app: &axum::Router, uri: &str) -> String {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_call_log_paths_never_log_caller_data_at_info_or_secrets_at_any_level() {
    let captured = Captured::default();
    let sink = captured.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish(),
    )
    .unwrap();

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
    let caller = CallerIdentity::Web(WebSessionIdentity {
        session_key: "sess-pii".into(),
    });
    let mut live = client.smdr_subscribe(&caller, None).await.unwrap();

    let live_bus = daemon.smdr_live();
    let dir = data_dir.clone();
    tokio::task::spawn_blocking(move || {
        ingest_smdr_bytes(&dir, live_bus, &smdr_fixture("mixed_stream.txt"))
    })
    .await
    .unwrap();
    let mut streamed = 0;
    tokio::time::timeout(Duration::from_secs(10), async {
        while streamed < 3 {
            if let Some(SmdrStreamEvent::Call { .. }) = live.recv().await {
                streamed += 1;
            }
        }
    })
    .await
    .unwrap();

    let now = chrono_free_now_ms();
    let page = client
        .smdr_query(&caller, SmdrQueryParams::with_defaults(None, None, now))
        .await
        .unwrap();
    assert!(page.calls.iter().any(|c| c.number == CALLER_DATA[1]));
    client.smdr_status(&caller).await.unwrap();

    let backend: Arc<dyn DaemonBackend> = client.clone();
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
    assert!(get(&app, "/calls").await.contains(CALLER_DATA[1]));
    assert!(get(&app, "/calls/status").await.contains("port_mode"));
    let csv = get(&app, "/calls/export.csv").await;
    assert!(
        csv.starts_with(kxprov_web::CSV_HEADER) && csv.contains(CALLER_DATA[1]),
        "{csv}"
    );

    if let Ok(wrong) = DaemonClient::connect(&sock, WRONG_SECRET.to_string()).await {
        assert!(wrong.smdr_status(&caller).await.is_err());
    }
    drop(live);
    drop(daemon);

    let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(
        text.contains("gateway audit"),
        "the capture missed the daemon threads"
    );
    for line in text.lines() {
        for secret in [GATEWAY_SECRET, WRONG_SECRET] {
            assert!(!line.contains(secret), "secret in log: {line}");
        }
        if [" INFO ", " WARN ", " ERROR "]
            .iter()
            .any(|lvl| line.contains(lvl))
        {
            for pii in CALLER_DATA {
                assert!(!line.contains(pii), "caller data at info+: {line}");
            }
        }
    }
}

fn chrono_free_now_ms() -> i64 {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    i64::try_from(since.as_millis()).unwrap() + 1000
}
