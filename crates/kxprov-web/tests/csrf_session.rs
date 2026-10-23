mod support;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::middleware::from_fn;
use http_body_util::BodyExt;
use kxprov_web::require_web_session;
use support::{cookie_header_from_set_cookies, form_urlencoded, test_web_state, with_peer};
use tower::ServiceExt;
use tower_sessions::cookie::time::Duration as CookieDuration;
use tower_sessions::cookie::SameSite;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

async fn body_string(resp: axum::response::Response) -> String {
    String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned()
}

fn secured_app() -> axum::Router {
    let session = SessionManagerLayer::new(MemoryStore::default())
        .with_name("__Host-kxprov.sid")
        .with_secure(true)
        .with_http_only(true)
        .with_same_site(SameSite::Strict)
        .with_expiry(Expiry::OnInactivity(CookieDuration::seconds(900)));
    kxprov_web::router(test_web_state())
        .layer(from_fn(require_web_session))
        .layer(session)
}

#[tokio::test]
async fn post_rejects_missing_csrf_field() {
    let app = secured_app();
    let get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .header(header::HOST, "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = cookie_header_from_set_cookies(get.headers());
    let resp = app
        .oneshot(with_peer(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::HOST, "127.0.0.1")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, cookie)
                .header(header::ORIGIN, "http://127.0.0.1")
                .body(Body::from("password=test-admin-password"))
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn post_rejects_csrf_from_another_session() {
    let app = secured_app();
    let login_a = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .header(header::HOST, "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie_a = cookie_header_from_set_cookies(login_a.headers());
    let html_a = body_string(login_a).await;
    let csrf_a = html_a
        .split("name=\"_csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap();

    let login_b = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .header(header::HOST, "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie_b = cookie_header_from_set_cookies(login_b.headers());

    let resp = app
        .oneshot(with_peer(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::HOST, "127.0.0.1")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, cookie_b)
                .header(header::ORIGIN, "http://127.0.0.1")
                .body(Body::from(format!(
                    "password=test-admin-password&_csrf={}",
                    form_urlencoded(csrf_a)
                )))
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let _ = cookie_a;
}
