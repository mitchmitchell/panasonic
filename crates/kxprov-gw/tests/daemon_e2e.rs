//! End-to-end: gateway `DaemonClient` speaks real `kxprovd` JSON envelopes with bearer auth.

use std::sync::Arc;
use std::time::Duration;

use kxprov_api::{Profile, RequestAuth, RequestBody, ResponseResult};
use kxprov_gw::daemon_client::DaemonClient;
use kxprov_mock::{CallerIdentity, DaemonBackend, WebSessionIdentity};
use kxprovd::test_util::GATEWAY_SECRET;
use tempfile::TempDir;

#[tokio::test]
async fn daemon_client_status_uses_bearer_and_audit() {
    let tmp = TempDir::new().unwrap();
    let uid = unsafe { libc::getuid() };
    let (_daemon, sock) = kxprovd::Daemon::sim_for_tests_profile(tmp.path(), uid, Profile::Sim);
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(sock.exists(), "daemon socket at {}", sock.display());
    let client = DaemonClient::connect(&sock, GATEWAY_SECRET.to_string())
        .await
        .expect("connect");
    let caller = CallerIdentity::Web(WebSessionIdentity {
        session_key: "sess-e2e".into(),
    });
    client.status(&caller).await.expect("status");

    let mut api = kxprov_api::ApiClient::connect(&sock).await.unwrap();
    let result = api
        .call_auth_audit(
            RequestBody::Status,
            Some(RequestAuth {
                bearer: GATEWAY_SECRET.to_string(),
            }),
            Some("web-session:test".into()),
        )
        .await
        .expect("daemon status");
    assert!(matches!(result, ResponseResult::Status(_)));
    let _ = Arc::new(client);
}
