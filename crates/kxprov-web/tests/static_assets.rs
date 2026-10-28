use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use kxprov_web::router;
use tower::ServiceExt;

mod support;
use support::test_web_state;

#[tokio::test]
async fn static_logo_is_served() {
    let app = router(test_web_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/static/logo.svg")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("content-type").unwrap(), "image/svg+xml");
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert!(!body.is_empty());
}

#[tokio::test]
async fn site_css_is_served() {
    let app = router(test_web_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/static/site.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/css"));
}
