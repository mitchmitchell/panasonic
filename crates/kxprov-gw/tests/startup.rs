use std::path::PathBuf;
use std::sync::Arc;

use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::Argon2;
use kxprov_gw::config::GatewayConfig;
use kxprov_gw::serve;
use kxprov_mock::MockDaemon;
use rcgen::{CertificateParams, KeyPair};
use tempfile::TempDir;

fn write_admin_hash(path: &std::path::Path) {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let hash = Argon2::default()
        .hash_password(b"test-admin", &salt)
        .expect("hash")
        .to_string();
    std::fs::write(path, hash).unwrap();
}

fn write_tokens(path: &std::path::Path) {
    let body = r#"
[[tokens]]
id = "approver"
name = "Approver"
role = "approver"
token_sha256_hex = "0101010101010101010101010101010101010101010101010101010101010101"
[[tokens]]
id = "comms"
name = "Comms"
role = "communications"
token_sha256_hex = "0202020202020202020202020202020202020202020202020202020202020202"
"#;
    std::fs::write(path, body).unwrap();
}

fn write_tls_pair(dir: &TempDir) -> (PathBuf, PathBuf) {
    let key_pair = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(["localhost".into()]).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "kxprov-test");
    let cert = params.self_signed(&key_pair).expect("cert");
    let cert_path = dir.path().join("lan.crt");
    let key_path = dir.path().join("lan.key");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    (cert_path, key_path)
}

fn sample_config(dir: &TempDir) -> GatewayConfig {
    let (cert_path, key_path) = write_tls_pair(dir);
    let admin_path = dir.path().join("admin.hash");
    let tokens_path = dir.path().join("tokens.toml");
    write_admin_hash(&admin_path);
    write_tokens(&tokens_path);
    GatewayConfig {
        bind: Some("127.0.0.1:0".into()),
        lan_ip: None,
        serve_hostname: None,
        web_https_port: 8443,
        web_serve_socket: dir.path().join("web-serve.sock"),
        serve_socket_group: None,
        mcp_tailnet_bind: "127.0.0.1:0".into(),
        mcp_tokens_path: tokens_path.clone(),
        daemon_tokens_path: dir.path().join("tokens.json"),
        gateway_bearer_path: dir.path().join("gateway.bearer"),
        admin_password_path: admin_path,
        daemon_socket_path: dir.path().join("kxprovd.sock"),
        tls_cert_path: cert_path,
        tls_key_path: key_path,
        session_ttl_secs: 900,
        session_absolute_secs: kxprov_web::WEB_SESSION_ABSOLUTE_SECS,
        rate_limit_per_minute: 120,
        allowed_hosts: vec![],
        allowed_origins: vec![],
        web_tailnet: kxprov_gw::config::WebListenerSettings {
            serve_peer_uid: Some(0),
            ..Default::default()
        },
        web_https: Default::default(),
    }
}

#[tokio::test]
async fn gateway_starts_from_sample_config() {
    std::env::set_var("KXPROV_SKIP_SECRET_FILE_CHECKS", "1");
    let dir = tempfile::tempdir().unwrap();
    let config = sample_config(&dir);
    let backend = Arc::new(MockDaemon::new());
    let handles = serve(config, backend).await.expect("gateway should start");
    assert!(handles.web_serve_socket.exists());
    assert!(handles.web_lan.port() > 0);
    assert!(handles.mcp.port() > 0);
    handles.shutdown.stop();
}

#[tokio::test]
async fn missing_tls_cert_fails_loudly() {
    std::env::set_var("KXPROV_SKIP_SECRET_FILE_CHECKS", "1");
    let dir = tempfile::tempdir().unwrap();
    let mut config = sample_config(&dir);
    config.tls_cert_path = dir.path().join("missing.crt");
    let backend = Arc::new(MockDaemon::new());
    let err = match serve(config, backend).await {
        Err(e) => e,
        Ok(_) => panic!("expected TLS load to fail"),
    };
    let msg = err.to_string();
    assert!(msg.contains("TLS certificate not found"), "{msg}");
}
