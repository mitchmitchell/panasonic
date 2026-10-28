//! HTTPS listener: port-less Host and https://127.0.0.1 Origin (P5-22).

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use kxprov_gw::{production_web_router, HostOriginConfig, RateLimiter};
use support::{apply_web_connect, cookie_header_from_set_cookies, test_web_state};
use tower::ServiceExt;

mod support;

#[tokio::test]
async fn https_origin_with_portless_host_allowed_on_443_listener() {
    let app = production_web_router(
        test_web_state(),
        HostOriginConfig {
            allowed_hosts: vec!["127.0.0.1".into(), "127.0.0.1:443".into()],
            allowed_origins: vec!["https://127.0.0.1".into()],
        },
        false,
        900,
        kxprov_web::WEB_SESSION_ABSOLUTE_SECS,
        RateLimiter::new(120),
    );
    let peer: std::net::SocketAddr = "127.0.0.1:443".parse().unwrap();
    let get = app
        .clone()
        .oneshot({
            let mut req = Request::builder()
                .uri("/login")
                .header(header::HOST, "127.0.0.1")
                .body(Body::empty())
                .unwrap();
            apply_web_connect(&mut req, peer, false);
            req
        })
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    let cookie = cookie_header_from_set_cookies(get.headers());

    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::HOST, "127.0.0.1")
        .header(header::ORIGIN, "https://127.0.0.1")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .body(Body::from("password=x&_csrf=not-the-session-token"))
        .unwrap();
    apply_web_connect(&mut req, peer, false);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "host/origin passed; invalid CSRF yields forbidden"
    );
}
