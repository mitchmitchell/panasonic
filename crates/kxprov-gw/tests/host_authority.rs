//! Host authority consistency (P5-18).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use kxprov_gw::{production_web_router, HostOriginConfig, RateLimiter};
use support::{apply_web_connect, test_web_state};
use tower::ServiceExt;

mod support;

#[tokio::test]
async fn host_header_mismatch_with_uri_authority_returns_400() {
    let app = production_web_router(
        test_web_state(),
        HostOriginConfig {
            allowed_hosts: vec!["localhost:8080".into()],
            allowed_origins: vec!["http://localhost:8080".into()],
        },
        false,
        900,
        kxprov_web::WEB_SESSION_ABSOLUTE_SECS,
        RateLimiter::new(120),
    );
    let peer: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let mut req = Request::builder()
        .uri("http://localhost:8080/login")
        .header(axum::http::header::HOST, "localhost:9090")
        .body(Body::empty())
        .unwrap();
    apply_web_connect(&mut req, peer, false);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
