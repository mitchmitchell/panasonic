//! Serve Unix socket SO_PEERCRED controls login XFF trust (not TCP loopback).

use kxprov_gw::serve_peer::{ServeTrustConfig, SERVE_LOOPBACK_PEER};
use kxprov_web::login_rate_ip_key;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

async fn accept_unix_pair(path: &std::path::Path) -> (UnixStream, UnixStream) {
    let listener = UnixListener::bind(path).unwrap();
    let client = UnixStream::connect(path).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (server, client)
}

#[tokio::test]
async fn unix_peercred_matching_uid_trusts_xff_on_real_connection() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("web.sock");
    let uid = nix::unistd::getuid().as_raw();
    let trust = ServeTrustConfig {
        trust_x_forwarded_for: true,
        expected_peer_uid: uid,
    };
    let (server, _client) = accept_unix_pair(&sock).await;
    let info = trust.web_connect_info(&server);
    assert!(info.serve_proxy_trusted);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.55".parse().expect("header"));
    assert_eq!(
        login_rate_ip_key(&headers, info.remote, true, info.serve_proxy_trusted),
        "ip:203.0.113.55"
    );
}

#[tokio::test]
async fn unix_peercred_non_matching_uid_ignores_xff() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("web.sock");
    let uid = nix::unistd::getuid().as_raw();
    let trust = ServeTrustConfig {
        trust_x_forwarded_for: true,
        expected_peer_uid: uid.saturating_add(1),
    };
    let (server, _client) = accept_unix_pair(&sock).await;
    let info = trust.web_connect_info(&server);
    assert!(!info.serve_proxy_trusted);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.55".parse().expect("header"));
    assert_eq!(
        login_rate_ip_key(&headers, info.remote, true, info.serve_proxy_trusted),
        format!("ip:{}", SERVE_LOOPBACK_PEER.ip())
    );
}

#[tokio::test]
async fn tcp_loopback_connection_never_trusts_xff() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
    let _client = TcpStream::connect(addr).await.unwrap();
    let (stream, peer) = accept.await.unwrap();
    drop(stream);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.77".parse().expect("header"));
    let info = kxprov_web::WebConnectInfo::from_parts(peer, false);
    assert_eq!(
        login_rate_ip_key(&headers, info.remote, true, info.serve_proxy_trusted),
        format!("ip:{}", peer.ip())
    );
    assert_ne!(peer, SocketAddr::from(([0, 0, 0, 0], 0)));
}

#[tokio::test]
async fn web_serve_bind_sets_socket_mode_0660() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("web-serve.sock");
    let _listener = kxprov_gw::serve_peer::bind_web_serve_listener(&path, None)
        .await
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o660
        );
    }
}

#[test]
fn config_rejects_missing_and_invalid_serve_peer_uid() {
    let missing = kxprov_gw::config::GatewayConfig::default();
    assert!(
        missing.validate_web_xff_trust().is_err(),
        "Serve Unix listener requires explicit serve_peer_uid"
    );
    let invalid = kxprov_gw::config::GatewayConfig {
        web_tailnet: kxprov_gw::config::WebListenerSettings {
            serve_peer_uid: Some(u32::MAX),
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(invalid.validate_web_xff_trust().is_err());
}
