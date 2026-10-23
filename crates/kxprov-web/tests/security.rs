mod support;

use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::middleware::from_fn;
use axum::Router;
use http_body_util::BodyExt;
use kxprov_web::require_web_session;
use kxprov_web::LoginRateLimiter;
use kxprov_web::PasswordVerifier;
use support::{
    cookie_header_from_set_cookies, form_urlencoded, test_web_state, with_peer, TestVerifier,
};
use tower::ServiceExt;
use tower_sessions::cookie::time::Duration as CookieDuration;
use tower_sessions::cookie::SameSite;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn secured_app() -> Router {
    let state = test_web_state();
    let session = SessionManagerLayer::new(MemoryStore::default())
        .with_name("__Host-kxprov.sid")
        .with_secure(true)
        .with_http_only(true)
        .with_same_site(SameSite::Strict)
        .with_expiry(Expiry::OnInactivity(CookieDuration::seconds(900)));
    kxprov_web::router(state)
        .layer(from_fn(require_web_session))
        .layer(session)
}

#[tokio::test]
async fn dashboard_redirects_without_session() {
    let app = secured_app();
    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/login");
}

#[tokio::test]
async fn login_rejects_bad_password() {
    let app = secured_app();
    let get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let set_cookie = cookie_header_from_set_cookies(get.headers());
    let html = body_string(get).await;
    let csrf = html
        .split("name=\"_csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("csrf in login form");
    let req = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, set_cookie)
        .header(header::ORIGIN, "http://127.0.0.1")
        .body(Body::from(format!(
            "password=wrong&_csrf={}",
            form_urlencoded(csrf)
        )))
        .unwrap();
    let resp = app.oneshot(with_peer(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("/login"));
}

#[tokio::test]
async fn login_uses_exponential_backoff_not_hard_lockout() {
    let limiter = LoginRateLimiter::new(
        Duration::from_millis(40),
        Duration::from_secs(30),
        Duration::from_secs(300),
    );
    assert_eq!(
        limiter.delay_before_attempt("acct:admin", "ip:9").await,
        Duration::ZERO
    );
    limiter.record_failure("acct:admin", "ip:9").await;
    assert!(limiter.delay_before_attempt("acct:admin", "ip:9").await > Duration::ZERO);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        limiter.delay_before_attempt("acct:admin", "ip:9").await,
        Duration::ZERO
    );
    assert_eq!(
        limiter.delay_before_attempt("acct:admin", "ip:10").await,
        Duration::ZERO
    );
}

#[tokio::test]
async fn password_verifier_is_used() {
    let v = TestVerifier;
    assert!(v.verify("test-admin-password"));
    assert!(!v.verify("nope"));
}
