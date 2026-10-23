use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use kxprov_api::{MockDaemon, FORBIDDEN_MODE_PROFILE_PATHS, WEB_ROUTES};
use kxprov_web::{router, WebState};
use tower::ServiceExt;

fn app() -> axum::Router {
    router(WebState {
        backend: Arc::new(MockDaemon::new()),
        session_id: Arc::from("route-table-test"),
    })
}

fn allowed_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
    )
}

#[tokio::test]
async fn forbidden_mode_profile_paths_return_404_or_405() {
    let app = app();
    for path in FORBIDDEN_MODE_PROFILE_PATHS {
        for method in [Method::GET, Method::POST, Method::PUT, Method::DELETE] {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri(*path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                allowed_status(resp.status()),
                "{} {} on {path} returned {}",
                method,
                path,
                resp.status()
            );
        }
    }
}

#[tokio::test]
async fn registered_get_routes_are_not_404() {
    let app = app();
    for route in WEB_ROUTES {
        if route.method != "GET" {
            continue;
        }
        let uri = if route.path == "/static/{file}" {
            "/static/logo.svg"
        } else {
            route.path
        };
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "registered GET {uri} should exist"
        );
    }
}
