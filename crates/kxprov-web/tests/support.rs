#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use axum::Router;
use axum_csrf::CsrfConfig;
use kxprov_mock::MockDaemon;
use kxprov_web::{LoginRateLimiter, PasswordVerifier, WebState};

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
            Duration::from_secs(60),
        )),
        csrf_config: CsrfConfig::default(),
    }
}

#[allow(dead_code)]
pub fn test_router() -> Router {
    kxprov_web::router(test_web_state())
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

pub fn merge_cookie_headers(existing: &str, headers: &axum::http::HeaderMap) -> String {
    let mut pairs: std::collections::HashMap<String, String> = existing
        .split(';')
        .filter_map(|part| {
            let part = part.trim();
            let (name, value) = part.split_once('=')?;
            Some((name.to_string(), value.to_string()))
        })
        .collect();
    for line in cookie_header_from_set_cookies(headers).split(';') {
        let line = line.trim();
        if let Some((name, value)) = line.split_once('=') {
            pairs.insert(name.trim().to_string(), value.trim().to_string());
        }
    }
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn with_peer(mut req: Request<Body>) -> Request<Body> {
    req.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:10001".parse::<SocketAddr>().expect("peer"),
    ));
    req
}
