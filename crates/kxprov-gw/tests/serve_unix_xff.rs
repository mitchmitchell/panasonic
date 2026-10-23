//! Serve Unix socket SO_PEERCRED controls login XFF trust (not TCP loopback).
//! Serialized with [`serial_test::serial`] — parallel bind races caused flaky `EACCES` under full `cargo test`.

use kxprov_gw::serve_peer::{ServeTrustConfig, SERVE_LOOPBACK_PEER};
use kxprov_web::login_rate_ip_key;
use serial_test::serial;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

fn unique_socket_path(dir: &Path, label: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("{label}-{n}.sock"))
}

fn remove_stale_socket(path: &Path) {
    if path.exists() {
        std::fs::remove_file(path).ok();
    }
}

async fn wait_for_unix_connect(path: &Path) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match UnixStream::connect(path).await {
            Ok(stream) => return stream,
            Err(_) if Instant::now() < deadline => {
                tokio::task::yield_now().await;
            }
            Err(e) => panic!("connect to {}: {e}", path.display()),
        }
    }
}

async fn bind_unix_listener(path: &Path) -> UnixListener {
    remove_stale_socket(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match UnixListener::bind(path) {
            Ok(listener) => return listener,
            Err(e)
                if e.kind() == std::io::ErrorKind::PermissionDenied
                    && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(e) => panic!("bind unix socket {}: {e}", path.display()),
        }
    }
}

async fn accept_unix_pair(path: &Path) -> (UnixStream, UnixStream) {
    let listener = bind_unix_listener(path).await;
    let accept_task = tokio::spawn(async move { listener.accept().await.unwrap() });
    let client = wait_for_unix_connect(path).await;
    let (server, _addr) = accept_task.await.expect("accept task");
    (server, client)
}

fn prep_runtime_dir(dir: &std::path::Path) {
    if dir.exists() {
        std::fs::remove_dir_all(dir).ok();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750)).unwrap();
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).unwrap();
    }
}

#[tokio::test]
#[serial]
async fn unix_peercred_matching_uid_trusts_xff_on_real_connection() {
    let dir = tempfile::tempdir().unwrap();
    let sock = unique_socket_path(dir.path(), "peercred-match");
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
#[serial]
async fn unix_peercred_non_matching_uid_ignores_xff() {
    let dir = tempfile::tempdir().unwrap();
    let sock = unique_socket_path(dir.path(), "peercred-mismatch");
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
#[serial]
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
#[serial]
async fn web_serve_bind_sets_runtime_dir_0750_and_socket_mode_0660() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = dir.path().join("run");
    prep_runtime_dir(&runtime);
    let path = unique_socket_path(&runtime, "web-serve");
    let _listener = kxprov_gw::serve_peer::bind_web_serve_listener(&path, None)
        .await
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&runtime).unwrap().permissions().mode() & 0o777,
            0o750
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o660
        );
    }
}

#[tokio::test]
#[serial]
async fn bind_fails_when_serve_socket_group_missing() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = dir.path().join("run");
    prep_runtime_dir(&runtime);
    let path = unique_socket_path(&runtime, "web-serve");
    let err = kxprov_gw::serve_peer::bind_web_serve_listener(
        &path,
        Some("nonexistent-kxprov-group-name"),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("not found"), "{err}");
}

#[tokio::test]
#[serial]
async fn bind_rejects_symlink_runtime_directory() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = dir.path().join("run-link");
    std::os::unix::fs::symlink(dir.path(), &runtime).unwrap();
    let path = unique_socket_path(&runtime, "web-serve");
    let err = kxprov_gw::serve_peer::bind_web_serve_listener(&path, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("symlink"), "{err}");
}

#[tokio::test]
#[serial]
async fn bind_rejects_symlink_at_socket_path() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = dir.path().join("run");
    prep_runtime_dir(&runtime);
    let real = unique_socket_path(&runtime, "real");
    let link = unique_socket_path(&runtime, "web-serve");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let err = kxprov_gw::serve_peer::bind_web_serve_listener(&link, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("symlink"), "{err}");
}

#[test]
#[serial]
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
