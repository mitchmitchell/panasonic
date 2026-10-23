use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use kxprov_api::MockDaemon;
use kxprov_web::{router, WebState};
use tower::ServiceExt;

#[tokio::test]
async fn static_logo_is_served() {
    let app = router(WebState {
        backend: Arc::new(MockDaemon::new()),
        session_id: Arc::from("test"),
    });
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
