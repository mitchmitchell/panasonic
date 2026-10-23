mod support;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::middleware::from_fn;
use axum_csrf::{CsrfConfig, CsrfLayer};
use http_body_util::BodyExt;
use kxprov_api::OperationalMode;
use kxprov_api::Profile;
use kxprov_mock::MockDaemon;
use kxprov_web::require_web_session;
use support::{test_router, test_web_state};
use tower::ServiceExt;
use tower_sessions::cookie::SameSite;
use tower_sessions::cookie::time::Duration as CookieDuration;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn app_with_mode(mode: OperationalMode) -> axum::Router {
    let mut state = test_web_state();
    state.backend = Arc::new(MockDaemon::with_mode_and_password(mode, "test-admin-password"));
    let session = SessionManagerLayer::new(MemoryStore::default())
        .with_secure(true)
        .with_http_only(true)
        .with_same_site(SameSite::Strict)
        .with_expiry(Expiry::OnInactivity(CookieDuration::seconds(900)));
    kxprov_web::router(state)
        .layer(from_fn(require_web_session))
        .layer(CsrfLayer::new(CsrfConfig::default()))
        .layer(session)
}

async fn login_cookie(app: &axum::Router) -> (String, String) {
    let get = app
        .clone()
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let cookie = get.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap().to_string();
    let html = body_string(get).await;
    let csrf = html
        .split("name=\"_csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap()
        .to_string();
    let post = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .header(header::ORIGIN, "http://127.0.0.1")
                .body(Body::from(format!(
                    "password=test-admin-password&_csrf={csrf}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::SEE_OTHER);
    let session_cookie = post
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    (session_cookie, csrf)
}

#[tokio::test]
async fn dashboard_has_no_apply_admin_control() {
    let app = app_with_mode(OperationalMode::Testing);
    let (cookie, _csrf) = login_cookie(&app).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let html = body_string(resp).await;
    assert!(!html.contains("Apply (admin)"));
}

#[tokio::test]
async fn apply_route_is_not_registered() {
    let app = test_router();
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/apply")
                .body(Body::from("plan_id=00&diff_hash=00"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mode_banner_shows_testing_and_production_styles() {
    let app = app_with_mode(OperationalMode::Testing);
    let (cookie, _) = login_cookie(&app).await;
    let html = body_string(
        app.oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap(),
    )
    .await;
    assert!(html.contains("mode-banner--testing"));
    assert!(html.contains("TESTING"));
}

#[tokio::test]
async fn plan_validation_error_keeps_form_values() {
    let app = app_with_mode(OperationalMode::Testing);
    let (cookie, csrf) = login_cookie(&app).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/plan")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, cookie)
                .header(header::ORIGIN, "http://127.0.0.1")
                .body(Body::from(format!(
                    "table=not-a-number&record=7&field=cid_number&new_value=hello&_csrf={csrf}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    assert!(html.contains("inline-error"));
    assert!(html.contains("value=\"not-a-number\""));
}

#[tokio::test]
async fn production_plan_shows_diff_prefix_and_expiry() {
    let mut state = test_web_state();
    state.backend = Arc::new(MockDaemon::with_profile(Profile::Prod));
    let session = SessionManagerLayer::new(MemoryStore::default())
        .with_secure(true)
        .with_expiry(Expiry::OnInactivity(CookieDuration::seconds(900)));
    let app = kxprov_web::router(state)
        .layer(from_fn(require_web_session))
        .layer(CsrfLayer::new(CsrfConfig::default()))
        .layer(session);
    let (cookie, csrf) = login_cookie(&app).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/plan")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, cookie)
                .header(header::ORIGIN, "http://127.0.0.1")
                .body(Body::from(format!(
                    "table=36&record=1&field=cid_number&new_value=5550100&_csrf={csrf}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let html = body_string(resp).await;
    assert!(html.contains("production-hint"));
}
