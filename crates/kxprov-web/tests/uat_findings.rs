mod support;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::middleware::from_fn;
use http_body_util::BodyExt;
use kxprov_api::{OperationalMode, Profile};
use kxprov_mock::MockDaemon;
use kxprov_web::{require_web_session, LOGIN_FAILED_MESSAGE};
use support::{
    cookie_header_from_set_cookies, form_urlencoded, merge_cookie_headers, test_web_state,
    with_peer,
};
use tower::ServiceExt;
use tower_sessions::cookie::time::Duration as CookieDuration;
use tower_sessions::cookie::SameSite;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn app(mode: OperationalMode, profile: Profile) -> axum::Router {
    app_with_mock(mode, profile).0
}

fn app_with_mock(mode: OperationalMode, profile: Profile) -> (axum::Router, Arc<MockDaemon>) {
    let mock = Arc::new(MockDaemon::with_mode_profile(mode, profile));
    let mut state = test_web_state();
    state.backend = mock.clone();
    let session = SessionManagerLayer::new(MemoryStore::default())
        .with_name("__Host-kxprov.sid")
        .with_secure(true)
        .with_http_only(true)
        .with_same_site(SameSite::Strict)
        .with_expiry(Expiry::OnInactivity(CookieDuration::seconds(900)));
    let router = kxprov_web::router(state)
        .layer(from_fn(require_web_session))
        .layer(session);
    (router, mock)
}

fn form_csrf(html: &str) -> String {
    html.split("name=\"_csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap()
        .to_string()
}

async fn sign_in(app: &axum::Router) -> (String, String, String) {
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
    let csrf = form_csrf(&body_string(get).await);
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
    let cookie = merge_cookie_headers(&cookie, post.headers());
    let dash = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = merge_cookie_headers(&cookie, dash.headers());
    let html = body_string(dash).await;
    (cookie, form_csrf(&html), html)
}

fn split_cookie_request(path: &str, cookie: &str, body: String) -> Request<Body> {
    let mut pairs: Vec<&str> = cookie.split("; ").collect();
    pairs.sort_by_key(|p| !p.starts_with("__Host-kxprov.sid="));
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ORIGIN, "http://127.0.0.1");
    for pair in pairs {
        builder = builder.header(header::COOKIE, pair);
    }
    builder.body(Body::from(body)).unwrap()
}

#[tokio::test]
async fn logout_accepts_cookies_split_across_http2_headers() {
    let app = app(OperationalMode::Testing, Profile::Test);
    let (cookie, csrf, _) = sign_in(&app).await;
    let req = split_cookie_request(
        "/logout",
        &cookie,
        format!("_csrf={}", form_urlencoded(&csrf)),
    );
    assert_eq!(req.headers().get_all(header::COOKIE).iter().count(), 2);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/login");
}

#[tokio::test]
async fn read_accepts_cookies_split_across_http2_headers() {
    let app = app(OperationalMode::Testing, Profile::Test);
    let (cookie, csrf, _) = sign_in(&app).await;
    let req = split_cookie_request(
        "/read",
        &cookie,
        format!("table=36&record=1&_csrf={}", form_urlencoded(&csrf)),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn csrf_rejection_renders_in_layout_with_link_home() {
    let app = app(OperationalMode::Testing, Profile::Test);
    let (cookie, _, _) = sign_in(&app).await;
    let req = split_cookie_request("/logout", &cookie, "_csrf=wrong".into());
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let html = body_string(resp).await;
    assert!(html.contains("site-header"));
    assert!(html.contains("href=\"/\">Go to the home page"));
    assert!(html.contains("nothing was changed"));
    assert!(!html.contains("CSRF"));
}

#[tokio::test]
async fn failed_login_shows_message_and_focuses_password() {
    let app = app(OperationalMode::Testing, Profile::Test);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/login?error=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let html = body_string(resp).await;
    let (before, after) = LOGIN_FAILED_MESSAGE.split_once('\'').unwrap();
    assert!(html.contains(before));
    assert!(html.contains(after));
    assert!(html.contains("autofocus"));
}

#[tokio::test]
async fn login_without_error_has_no_message() {
    let app = app(OperationalMode::Testing, Profile::Test);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let html = body_string(resp).await;
    assert!(!html.contains("role=\"alert\""));
}

#[tokio::test]
async fn sim_profile_banner_says_simulator_not_production() {
    let app = app(OperationalMode::Production, Profile::Sim);
    let (_, _, html) = sign_in(&app).await;
    assert!(html.contains("mode-banner--sim"));
    assert!(html.contains("SIMULATOR"));
    assert!(!html.contains("PRODUCTION"));
}

#[tokio::test]
async fn prod_profile_banner_still_shows_production() {
    let app = app(OperationalMode::Production, Profile::Prod);
    let (_, _, html) = sign_in(&app).await;
    assert!(html.contains("mode-banner--production"));
    assert!(html.contains("PRODUCTION"));
}

async fn post_form(
    app: &axum::Router,
    path: &str,
    cookie: &str,
    body: String,
) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(split_cookie_request(path, cookie, body))
        .await
        .unwrap();
    let status = resp.status();
    (status, body_string(resp).await)
}

fn table_36_range() -> (u16, u16) {
    kxtd1232::tables::spec(36).unwrap().label_range().unwrap()
}

#[tokio::test]
async fn first_and_last_labels_map_to_first_and_last_index() {
    let (app, mock) = app_with_mock(OperationalMode::Testing, Profile::Sim);
    let (cookie, csrf, _) = sign_in(&app).await;
    let csrf = form_urlencoded(&csrf);
    let (first, last) = table_36_range();
    let records = kxtd1232::tables::spec(36).unwrap().records;
    for label in [first, last] {
        let (status, html) = post_form(
            &app,
            "/read",
            &cookie,
            format!("table=36&record={label}&_csrf={csrf}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("read-result"), "read {label}");
        assert!(
            html.contains(&format!("Record {label} in table 36")),
            "read {label}"
        );
        let (status, html) = post_form(
            &app,
            "/plan",
            &cookie,
            format!("table=36&record={label}&field=cid_number&new_value=1&_csrf={csrf}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("plan-result"), "plan {label}");
    }
    assert_eq!(
        mock.requested_indexes().await,
        vec![0, 0, records - 1, records - 1]
    );
}

#[tokio::test]
async fn labels_outside_the_table_range_get_the_in_page_error() {
    let (app, mock) = app_with_mock(OperationalMode::Testing, Profile::Sim);
    let (cookie, csrf, _) = sign_in(&app).await;
    let csrf = form_urlencoded(&csrf);
    let (first, last) = table_36_range();
    let error = format!("Enter a whole number from {first} to {last} for table 36.");
    let mut outside = vec![
        (last + 1).to_string(),
        "abc".into(),
        "1.5".into(),
        "-1".into(),
        String::new(),
        "65536".into(),
    ];
    if let Some(below) = first.checked_sub(1) {
        outside.push(below.to_string());
    }
    for record in &outside {
        let (status, html) = post_form(
            &app,
            "/read",
            &cookie,
            format!("table=36&record={record}&_csrf={csrf}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains(&error), "read {record:?}");
        assert!(!html.contains("read-result"), "read {record:?}");
        let (status, html) = post_form(
            &app,
            "/plan",
            &cookie,
            format!("table=36&record={record}&field=cid_number&new_value=1&_csrf={csrf}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains(&error), "plan {record:?}");
        assert!(!html.contains("plan-result"), "plan {record:?}");
    }
    assert!(mock.requested_indexes().await.is_empty());
}

#[tokio::test]
async fn help_text_names_each_table_range() {
    let app = app(OperationalMode::Testing, Profile::Sim);
    let (_, _, dashboard) = sign_in(&app).await;
    let (first, last) = table_36_range();
    assert!(dashboard.contains(&format!("table 36 from {first} to {last}")));
    assert!(!dashboard.contains("9999"));
}

#[tokio::test]
async fn missing_form_fields_render_in_layout_not_bare_422() {
    let app = app(OperationalMode::Testing, Profile::Sim);
    let (cookie, csrf, _) = sign_in(&app).await;
    let (status, html) = post_form(
        &app,
        "/read",
        &cookie,
        format!("_csrf={}", form_urlencoded(&csrf)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("site-header"));
    assert!(html.contains("inline-error"));
}

#[tokio::test]
async fn sim_plan_result_has_no_production_hint_and_shows_current_value() {
    let app = app(OperationalMode::Production, Profile::Sim);
    let (cookie, csrf, _) = sign_in(&app).await;
    let (_, html) = post_form(
        &app,
        "/plan",
        &cookie,
        format!(
            "table=36&record=1&field=cid_number&new_value=5550199&_csrf={}",
            form_urlencoded(&csrf)
        ),
    )
    .await;
    assert!(html.contains("plan-result"));
    assert!(!html.contains("production-hint"));
    assert!(html.contains("<dt>Current value</dt><dd>5550001</dd>"));
}

#[tokio::test]
async fn prod_plan_result_keeps_production_hint() {
    let app = app(OperationalMode::Production, Profile::Prod);
    let (cookie, csrf, _) = sign_in(&app).await;
    let (_, html) = post_form(
        &app,
        "/plan",
        &cookie,
        format!(
            "table=36&record=1&field=cid_number&new_value=5550199&_csrf={}",
            form_urlencoded(&csrf)
        ),
    )
    .await;
    assert!(html.contains("production-hint"));
}
