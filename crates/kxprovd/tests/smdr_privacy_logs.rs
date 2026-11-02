#![allow(
    clippy::unwrap_used,
    reason = "test setup failures should abort the test"
)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use kxprov_api::{ApiClient, RequestBody, ResponseResult, SmdrQueryParams, SmdrStreamEvent};
use kxprovd::smdr_store::SmdrStore;
use kxprovd::test_util::{ingest_smdr_bytes, smdr_fixture, GATEWAY_SECRET};
use kxtd1232::smdr::DateOrder;

const WRONG_BEARER: &str = "pii-capture-wrong-bearer-0f3a";
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn call_log_paths_never_log_caller_data_at_info_or_tokens_at_any_level() {
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

    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (daemon, sock) = kxprovd::Daemon::sim_for_tests_as_gateway_profile(
        tmp.path(),
        uid,
        kxprov_api::Profile::Sim,
    );
    common::wait_daemon_api_ready(&sock).await;
    let data_dir = kxprovd::config::profile_data_dir(tmp.path(), kxprov_api::Profile::Sim);
    let auth = || Some(common::bearer_auth(GATEWAY_SECRET));
    let audit = || Some("web session".to_string());
    drop(SmdrStore::open(&data_dir, &[&data_dir.join("backups")], DateOrder::Mdy).unwrap());

    let (_, mut events) = ApiClient::connect(&sock)
        .await
        .unwrap()
        .subscribe_smdr(None, auth(), audit())
        .await
        .unwrap();

    let live = daemon.smdr_live();
    let dir = data_dir.clone();
    let mut bytes = smdr_fixture("mixed_stream.txt");
    bytes.extend(smdr_fixture("malformed_short.txt"));
    tokio::task::spawn_blocking(move || ingest_smdr_bytes(&dir, live, &bytes))
        .await
        .unwrap();

    let mut streamed = 0;
    tokio::time::timeout(Duration::from_secs(10), async {
        while streamed < 3 {
            if let Some(SmdrStreamEvent::Call { .. }) = events.next_event().await.unwrap() {
                streamed += 1;
            }
        }
    })
    .await
    .unwrap();

    let mut c = ApiClient::connect(&sock).await.unwrap();
    let page = c
        .call_auth_audit(
            RequestBody::SmdrQuery {
                params: SmdrQueryParams::with_defaults(
                    None,
                    None,
                    Utc::now().timestamp_millis() + 1000,
                ),
            },
            auth(),
            audit(),
        )
        .await
        .unwrap();
    let ResponseResult::SmdrPage(page) = page else {
        panic!("{page:?}")
    };
    assert!(page.calls.iter().any(|c| c.number == CALLER_DATA[1]));
    let status = c
        .call_auth_audit(RequestBody::SmdrStatus, auth(), audit())
        .await
        .unwrap();
    assert!(matches!(status, ResponseResult::SmdrStatus(_)));
    let refused = c
        .call_auth(
            RequestBody::SmdrStatus,
            Some(common::bearer_auth(WRONG_BEARER)),
        )
        .await;
    assert!(refused.is_err());
    drop(events);
    drop(daemon);

    let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(
        text.contains("gateway audit"),
        "the capture missed the daemon threads"
    );
    for line in text.lines() {
        for secret in [GATEWAY_SECRET, WRONG_BEARER] {
            assert!(!line.contains(secret), "token in log: {line}");
        }
        let info_or_above = [" INFO ", " WARN ", " ERROR "]
            .iter()
            .any(|lvl| line.contains(lvl));
        if info_or_above {
            for pii in CALLER_DATA {
                assert!(!line.contains(pii), "caller data at info+: {line}");
            }
        }
    }
}
