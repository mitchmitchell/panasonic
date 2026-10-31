use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use kxprov_gw::{production_web_router, HostOriginConfig, RateLimiter};
use support::{apply_web_connect, test_web_state};
use tower::ServiceExt;

mod support;

fn app() -> axum::Router {
    production_web_router(
        test_web_state(),
        HostOriginConfig {
            allowed_hosts: vec!["127.0.0.1:8443".into()],
            allowed_origins: vec!["https://127.0.0.1:8443".into()],
        },
        false,
        900,
        kxprov_web::WEB_SESSION_ABSOLUTE_SECS,
        RateLimiter::new(120),
    )
}

async fn post(origin: Option<&str>) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/read")
        .header(header::HOST, "127.0.0.1:8443")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(origin) = origin {
        builder = builder.header(header::ORIGIN, origin);
    }
    let mut req = builder
        .body(Body::from("table=36&record=1&_csrf=x"))
        .unwrap();
    apply_web_connect(&mut req, "127.0.0.1:50000".parse().unwrap(), false);
    let resp = app().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn assert_layout(html: &str) {
    assert!(html.contains("site-header"));
    assert!(html.contains("Go to the home page"));
    assert!(html.contains("nothing was changed"));
}

#[tokio::test]
async fn foreign_origin_post_renders_in_layout() {
    let (status, html) = post(Some("https://evil.example")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_layout(&html);
}

#[tokio::test]
async fn post_without_origin_or_referer_renders_in_layout() {
    let (status, html) = post(None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_layout(&html);
}
