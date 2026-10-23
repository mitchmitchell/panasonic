//! Login IP backoff uses the socket peer when the listener does not trust X-Forwarded-For.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use kxprov_gw::{production_web_router, HostOriginConfig, RateLimiter};
use kxprov_web::LoginRateLimiter;
mod support;

use support::{cookie_header_from_set_cookies, form_urlencoded, test_web_state, TestVerifier};
use tower::ServiceExt;

async fn fetch_login_csrf(
    app: &Router,
    peer: std::net::SocketAddr,
    login_uri: &str,
) -> (String, String) {
    let get = app
        .clone()
        .oneshot({
            let mut req = Request::builder()
                .uri(login_uri)
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(peer));
            req
        })
        .await
        .unwrap();
    let cookie = cookie_header_from_set_cookies(get.headers());
    let body_bytes = get.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&body_bytes);
    let csrf = html
        .split("name=\"_csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("csrf")
        .to_string();
    (cookie, csrf)
}

async fn assert_rotating_xff_hits_ip_backoff(
    app: Router,
    peer: std::net::SocketAddr,
    login_uri: &str,
    host: &str,
    origin: &str,
    attempts: usize,
) {
    let (cookie, csrf) = fetch_login_csrf(&app, peer, login_uri).await;
    let mut last = StatusCode::OK;
    for i in 0..attempts {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(login_uri)
            .header(header::HOST, host)
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, &cookie)
            .header(
                header::HeaderName::from_static("x-forwarded-for"),
                format!("198.51.100.{}", i + 1),
            )
            .body(Body::from(format!(
                "password=wrong&_csrf={}",
                form_urlencoded(&csrf)
            )))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        let resp = app.clone().oneshot(req).await.unwrap();
        last = resp.status();
        if last == StatusCode::TOO_MANY_REQUESTS {
            assert!(
                resp.headers().get(header::RETRY_AFTER).is_some(),
                "IP backoff must include Retry-After"
            );
            return;
        }
    }
    panic!("expected 429 after {attempts} rotating XFF attempts; last status {last}");
}

fn login_test_app(host: &str, origin: &str, trust_x_forwarded_for: bool) -> Router {
    let mut state = test_web_state();
    state.login_limiter = Arc::new(LoginRateLimiter::new(
        Duration::from_millis(50),
        Duration::from_secs(30),
        Duration::from_secs(300),
    ));
    state.admin = Arc::new(TestVerifier);
    production_web_router(
        state,
        HostOriginConfig {
            allowed_hosts: vec![host.into()],
            allowed_origins: vec![origin.into()],
        },
        trust_x_forwarded_for,
        900,
        kxprov_web::WEB_SESSION_ABSOLUTE_SECS,
        RateLimiter::new(120),
    )
}

#[tokio::test]
async fn spoofed_xff_on_non_serve_listener_still_rate_limits_peer_ip() {
    let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let app = login_test_app("localhost:8080", "http://localhost:8080", false);
    assert_rotating_xff_hits_ip_backoff(
        app,
        peer,
        "http://localhost:8080/login",
        "localhost:8080",
        "http://localhost:8080",
        30,
    )
    .await;
}

/// Direct TLS listener stack (`web_https`): `trust_x_forwarded_for` is false; rotating XFF must not bypass IP backoff.
#[tokio::test]
async fn rotating_xff_on_direct_tls_listener_still_rate_limits() {
    let peer: std::net::SocketAddr = "127.0.0.1:8443".parse().unwrap();
    let app = login_test_app("localhost:8443", "https://localhost:8443", false);
    assert_rotating_xff_hits_ip_backoff(
        app,
        peer,
        "https://localhost:8443/login",
        "localhost:8443",
        "https://localhost:8443",
        10,
    )
    .await;
}
