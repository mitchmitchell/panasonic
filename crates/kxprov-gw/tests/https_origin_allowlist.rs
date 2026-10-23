//! HTTPS listener: port-less Host and https://127.0.0.1 Origin (P5-22).

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use kxprov_gw::{production_web_router, HostOriginConfig, RateLimiter};
use support::test_web_state;
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
        RateLimiter::new(120),
    );
    let peer: std::net::SocketAddr = "127.0.0.1:443".parse().unwrap();
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::HOST, "127.0.0.1")
        .header(header::ORIGIN, "https://127.0.0.1")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("_csrf=x"))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "host/origin passed; invalid CSRF yields forbidden"
    );
}
