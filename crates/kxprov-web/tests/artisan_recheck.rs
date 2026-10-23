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
use kxprov_web::{reject_authenticated_login, require_web_session};
use support::{
    cookie_header_from_set_cookies, form_urlencoded, merge_cookie_headers, test_router,
    test_web_state, with_peer,
};
use tower::ServiceExt;
use tower_sessions::cookie::time::Duration as CookieDuration;
use tower_sessions::cookie::SameSite;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn app_with_mode(mode: OperationalMode) -> axum::Router {
    let csrf_config = CsrfConfig::default();
    let mut state = test_web_state();
    state.backend = Arc::new(MockDaemon::with_mode_and_password(
        mode,
        "test-admin-password",
    ));
    state.csrf_config = csrf_config.clone();
    let session = SessionManagerLayer::new(MemoryStore::default())
        .with_name("__Host-kxprov.sid")
        .with_secure(true)
        .with_http_only(true)
        .with_same_site(SameSite::Strict)
        .with_expiry(Expiry::OnInactivity(CookieDuration::seconds(900)));
    kxprov_web::router(state)
        .layer(from_fn(require_web_session))
        .layer(from_fn(reject_authenticated_login))
        .layer(CsrfLayer::new(csrf_config))
        .layer(session)
}

async fn login_cookie(app: &axum::Router) -> (String, String) {
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
    let cookie = cookie_header_from_set_cookies(get.headers());
    let html = body_string(get).await;
    let csrf = html
        .split("name=\"_csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap()
        .to_string();
    let post = app
        .clone()
        .oneshot(with_peer(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .header(header::ORIGIN, "http://127.0.0.1")
                .body(Body::from(format!(
                    "password=test-admin-password&_csrf={}",
                    form_urlencoded(&csrf)
                )))
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::SEE_OTHER);
    let session_cookie = merge_cookie_headers(&cookie, post.headers());
    let dash = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let dash_html = body_string(dash).await;
    let dash_csrf = dash_html
        .split("name=\"_csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap()
        .to_string();
    (session_cookie, dash_csrf)
}

#[tokio::test]
async fn login_page_has_h1_without_inline_styles() {
    let app = kxprov_web::router(test_web_state()).layer(CsrfLayer::new(CsrfConfig::default()));
    let html = body_string(
        app.oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap(),
    )
    .await;
    assert!(html.contains("<h1>Sign in</h1>"));
    assert!(!html.contains("style="));
}

#[tokio::test]
async fn read_record_shows_fields_before_plan() {
    let app = app_with_mode(OperationalMode::Testing);
    let (cookie, csrf) = login_cookie(&app).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/read")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, cookie)
                .header(header::ORIGIN, "http://127.0.0.1")
                .body(Body::from(format!(
                    "table=36&record=1&_csrf={}",
                    form_urlencoded(&csrf)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let html = body_string(resp).await;
    assert!(html.contains("read-result"));
    assert!(html.contains("cid_number"));
}

#[tokio::test]
async fn plan_rejects_field_not_in_table_spec() {
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
                    "table=36&record=1&field=cid_name&new_value=hello&_csrf={}",
                    form_urlencoded(&csrf)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let html = body_string(resp).await;
    assert!(html.contains("inline-error"));
    assert!(html.contains("not valid for the phone table"));
}

#[tokio::test]
async fn plan_summary_lists_table_record_and_values() {
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
                .header(header::ORIGIN, "http://127.0.0.1")
                .body(Body::from(format!(
                    "table=36&record=1&field=cid_number&new_value=5550100&_csrf={}",
                    form_urlencoded(&csrf)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let html = body_string(resp).await;
    assert!(html.contains("plan-detail"));
    assert!(html.contains("Current value"));
    assert!(html.contains("5550100"));
}

#[tokio::test]
async fn production_plan_shows_chicago_expiry_and_countdown() {
    let csrf_config = CsrfConfig::default();
    let mut state = test_web_state();
    state.backend = Arc::new(MockDaemon::with_profile(Profile::Prod));
    state.csrf_config = csrf_config.clone();
    let session = SessionManagerLayer::new(MemoryStore::default())
        .with_name("__Host-kxprov.sid")
        .with_secure(true)
        .with_http_only(true)
        .with_same_site(SameSite::Strict)
        .with_expiry(Expiry::OnInactivity(CookieDuration::seconds(900)));
    let app = kxprov_web::router(state)
        .layer(from_fn(require_web_session))
        .layer(from_fn(reject_authenticated_login))
        .layer(CsrfLayer::new(csrf_config))
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
                    "table=36&record=1&field=cid_number&new_value=5550100&_csrf={}",
                    form_urlencoded(&csrf)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let html = body_string(resp).await;
    assert!(html.contains(" CT"));
    assert!(html.contains("plan-expiry-countdown"));
    assert!(html.contains("plan-expiry.js"));
    assert!(!html.contains("nanosecond"));
}

#[tokio::test]
async fn dashboard_uses_plain_lock_wording() {
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
    assert!(!html.contains("Locked: false"));
    assert!(html.contains("phone database"));
}

#[tokio::test]
async fn dashboard_css_wraps_hashes_at_narrow_width() {
    let app = test_router();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/static/site.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let css = body_string(resp).await;
    assert!(css.contains("overflow-wrap: anywhere"));
    assert!(css.contains("375px"));
}
