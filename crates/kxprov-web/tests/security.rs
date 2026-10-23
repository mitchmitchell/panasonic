mod support;

use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::middleware::from_fn;
use axum::Router;
use axum_csrf::{CsrfConfig, CsrfLayer};
use http_body_util::BodyExt;
use kxprov_web::require_web_session;
use kxprov_web::LoginRateLimiter;
use kxprov_web::PasswordVerifier;
use support::{test_web_state, TestVerifier};
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
        .layer(CsrfLayer::new(CsrfConfig::default()))
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
    let set_cookie = get
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let html = body_string(get).await;
    let csrf = html
        .split("name=\"_csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("csrf in login form");
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, set_cookie)
                .header(header::ORIGIN, "http://127.0.0.1")
                .body(Body::from(format!("password=wrong&_csrf={csrf}")))
                .unwrap(),
        )
        .await
        .unwrap();
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
async fn login_rate_limits_account_and_ip_separately() {
    let limiter = LoginRateLimiter::new(2, Duration::from_secs(300));
    assert!(limiter.allow("acct:admin").await);
    limiter.record_failure("acct:admin", "ip:9").await;
    limiter.record_failure("acct:admin", "ip:9").await;
    assert!(!limiter.allow("acct:admin").await);
    assert!(limiter.allow("ip:10").await);
}

#[tokio::test]
async fn password_verifier_is_used() {
    let v = TestVerifier;
    assert!(v.verify("test-admin-password"));
    assert!(!v.verify("nope"));
}
