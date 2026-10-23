use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use kxprov_gw::{production_web_router, HostOriginConfig, RateLimiter};
use kxprov_web::{LoginPrecheck, LoginRateLimiter};
use tower::ServiceExt;

mod support;
use support::{
    apply_web_connect, cookie_header_from_set_cookies, form_urlencoded, test_web_state,
    TestVerifier,
};

#[tokio::test]
async fn login_limiter_tracks_account_and_ip_separately() {
    let limiter = LoginRateLimiter::new(
        Duration::from_millis(100),
        Duration::from_secs(30),
        Duration::from_secs(30),
    );
    limiter.record_failure("acct:admin", "ip:1").await;
    assert!(limiter.delay_before_attempt("acct:admin", "ip:1").await > Duration::ZERO);
    limiter.on_success("acct:admin", "ip:1").await;
    assert_eq!(
        limiter.delay_before_attempt("acct:admin", "ip:1").await,
        Duration::ZERO
    );
}

#[tokio::test]
async fn ip_backoff_returns_exact_429_with_retry_after() {
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
            allowed_hosts: vec!["127.0.0.1:8080".into()],
            allowed_origins: vec!["http://127.0.0.1:8080".into()],
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
                .uri("/login")
                .header(header::HOST, "127.0.0.1:8080")
                .body(Body::empty())
                .unwrap();
            apply_web_connect(&mut req, peer, false);
            req
        })
        .await
        .unwrap();
    let cookie = cookie_header_from_set_cookies(get.headers());
    let bytes = get.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&bytes);
    let csrf = html
        .split("name=\"_csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("csrf");

    let mut saw_429 = false;
    for _ in 0..20 {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/login")
            .header(header::HOST, "127.0.0.1:8080")
            .header(header::ORIGIN, "http://127.0.0.1:8080")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, &cookie)
            .body(Body::from(format!(
                "password=wrong&_csrf={}",
                form_urlencoded(csrf)
            )))
            .unwrap();
        apply_web_connect(&mut req, peer, false);
        let resp = app.clone().oneshot(req).await.unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            assert!(resp.headers().get(header::RETRY_AFTER).is_some());
            saw_429 = true;
            break;
        }
    }
    assert!(saw_429, "expected exact 429 from IP backoff");
}

#[tokio::test]
async fn account_soft_delay_capped_at_two_seconds() {
    let limiter = LoginRateLimiter::new(
        Duration::from_millis(100),
        Duration::from_secs(30),
        Duration::from_secs(300),
    );
    for i in 0..10 {
        limiter
            .record_failure("acct:admin", &format!("ip:other-{i}"))
            .await;
    }
    let started = std::time::Instant::now();
    limiter
        .enter_account_login("acct:admin", "ip:clean", None, || async {})
        .await
        .expect("clean ip");
    assert!(started.elapsed() <= Duration::from_millis(2100));
    assert!(matches!(
        limiter.precheck_login("acct:admin", "ip:clean").await,
        LoginPrecheck::Ready
    ));
}
