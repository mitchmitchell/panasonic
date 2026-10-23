#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ConnectInfo;
use kxprov_mock::MockDaemon;
use kxprov_web::{LoginRateLimiter, PasswordVerifier, WebConnectInfo, WebState};
use std::net::SocketAddr;

pub fn apply_web_connect(
    req: &mut axum::http::Request<axum::body::Body>,
    peer: SocketAddr,
    serve_proxy_trusted: bool,
) {
    req.extensions_mut().insert(ConnectInfo(peer));
    req.extensions_mut()
        .insert(WebConnectInfo::from_parts(peer, serve_proxy_trusted));
}

pub struct TestVerifier;

impl PasswordVerifier for TestVerifier {
    fn verify(&self, password: &str) -> bool {
        password == "test-admin-password"
    }
}

pub fn test_web_state() -> WebState {
    WebState {
        backend: Arc::new(MockDaemon::new()),
        admin: Arc::new(TestVerifier),
        login_limiter: Arc::new(LoginRateLimiter::new(
            Duration::from_secs(1),
            Duration::from_secs(30),
            Duration::from_secs(300),
        )),
    }
}

pub fn form_urlencoded(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

pub fn cookie_header_from_set_cookies(headers: &axum::http::HeaderMap) -> String {
    use axum::http::header;
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|line| line.split(';').next().unwrap_or(line).trim())
        .collect::<Vec<_>>()
        .join("; ")
}
