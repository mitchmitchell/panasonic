//! Host / Origin allow-list: port-less entries and HTTP/2-style URI authority.

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
async fn localhost_with_port_passes_host_and_origin_on_login_post() {
    let mut state = test_web_state();
    state.login_limiter = Arc::new(LoginRateLimiter::new(
        Duration::from_secs(1),
        Duration::from_secs(30),
        Duration::from_secs(300),
    ));
    state.admin = Arc::new(TestVerifier);
    let app = production_web_router(
        state,
        HostOriginConfig {
            allowed_hosts: vec!["localhost".into()],
            allowed_origins: vec!["http://localhost".into()],
        },
        900,
        RateLimiter::new(120),
    );

    let get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("http://localhost:8080/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    let cookie = cookie_header_from_set_cookies(get.headers());
    let body_bytes = get.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&body_bytes);
    let csrf = html
        .split("name=\"_csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("csrf");

    let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:8080/login")
        .header(header::HOST, "localhost:8080")
        .header(header::ORIGIN, "http://localhost:8080")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .body(Body::from(format!(
            "password=test-admin-password&_csrf={}",
            form_urlencoded(csrf)
        )))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    let post = app.oneshot(req).await.unwrap();
    assert_eq!(post.status(), StatusCode::SEE_OTHER);
}
