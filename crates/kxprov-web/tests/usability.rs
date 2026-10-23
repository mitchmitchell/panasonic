use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use kxprov_api::{MockDaemon, Mode, Profile};
use kxprov_web::{router, WebState};
use tower::ServiceExt;

fn app_with_mode(mode: Mode) -> axum::Router {
    router(WebState {
        backend: Arc::new(MockDaemon::with_mode_and_password(
            mode,
            "test-admin-password",
        )),
        session_id: Arc::from("usability-test"),
    })
}

fn app_prod_profile() -> axum::Router {
    router(WebState {
        backend: Arc::new(MockDaemon::with_profile(Profile::prod())),
        session_id: Arc::from("usability-test"),
    })
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn dashboard_has_no_apply_admin_control() {
    let app = app_with_mode(Mode::Testing);
    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let html = body_string(resp).await;
    assert!(!html.contains("Apply (admin)"), "web must not offer apply");
    assert!(!html.contains("action=\"/apply\""));
}

#[tokio::test]
async fn apply_route_is_not_registered() {
    let app = app_with_mode(Mode::Testing);
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/apply")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("plan_id=00&diff_hash=00"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mode_banner_shows_testing_and_production_styles() {
    let testing = app_with_mode(Mode::Testing);
    let html = body_string(
        testing
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap(),
    )
    .await;
    assert!(html.contains("mode-banner--testing"));
    assert!(html.contains("TESTING"));

    let production = app_with_mode(Mode::Production);
    let html = body_string(
        production
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap(),
    )
    .await;
    assert!(html.contains("mode-banner--production"));
    assert!(html.contains("PRODUCTION"));
    assert!(html.contains("profile-badge"));
}

#[tokio::test]
async fn plan_validation_error_keeps_form_values() {
    let app = app_with_mode(Mode::Testing);
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/plan")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "table=not-a-number&record=7&field=label&new_value=hello&_csrf=",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    assert!(html.contains("inline-error"));
    assert!(html.contains("value=\"not-a-number\""));
    assert!(html.contains("value=\"7\""));
    assert!(html.contains("value=\"label\""));
    assert!(html.contains("value=\"hello\""));
}

#[tokio::test]
async fn production_plan_shows_diff_prefix_and_expiry() {
    let app = app_prod_profile();
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/plan")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "table=36&record=1&field=name&new_value=hello&_csrf=",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let html = body_string(resp).await;
    assert!(html.contains("production-hint"));
    assert!(html.contains("diff hash prefix"));
    assert!(html.contains("Approval window expires"));
}
