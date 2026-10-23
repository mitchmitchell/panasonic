//! Login IP backoff uses the socket peer when the listener does not trust X-Forwarded-For.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use kxprov_gw::{production_web_router, HostOriginConfig, RateLimiter};
use kxprov_web::LoginRateLimiter;
mod support;

use support::{cookie_header_from_set_cookies, form_urlencoded, test_web_state, TestVerifier};
use tower::ServiceExt;

#[tokio::test]
async fn spoofed_xff_on_non_serve_listener_still_rate_limits_peer_ip() {
    let mut state = test_web_state();
    state.login_limiter = Arc::new(LoginRateLimiter::new(
        Duration::from_millis(50),
        Duration::from_secs(30),
        Duration::from_secs(300),
    ));
    state.admin = Arc::new(TestVerifier);
    let app = production_web_router(
        state,
        HostOriginConfig {
            allowed_hosts: vec!["localhost:8080".into()],
            allowed_origins: vec!["http://localhost:8080".into()],
        },
        false,
        900,
        kxprov_web::WEB_SESSION_ABSOLUTE_SECS,
        RateLimiter::new(120),
    );

    let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let get = app
        .clone()
        .oneshot({
            let mut req = Request::builder()
                .uri("http://localhost:8080/login")
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
        .expect("csrf");

    let mut last = StatusCode::OK;
    for i in 0..30 {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("http://localhost:8080/login")
            .header(header::HOST, "localhost:8080")
            .header(header::ORIGIN, "http://localhost:8080")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, &cookie)
            .header(
                header::HeaderName::from_static("x-forwarded-for"),
                format!("198.51.100.{i}"),
            )
            .body(Body::from(format!(
                "password=wrong&_csrf={}",
                form_urlencoded(csrf)
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
    panic!("expected 429 after repeated failures on same peer; last status {last}");
}
