mod support;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use kxprov_gw::{production_web_router, HostOriginConfig, RateLimiter};
use kxprov_mcp::KxMcpServer;
use kxprov_mock::{MCP_APPROVAL_TOOLS, MCP_TOOLS, WEB_APPROVAL_APPLY_HTTP_PATHS, WEB_ROUTES};
use kxprov_web::LoginRateLimiter;
use std::net::SocketAddr;
use support::{apply_web_connect, test_web_state, TestVerifier};
use tower::ServiceExt;
fn production_like_app() -> axum::Router {
    let mut state = test_web_state();
    state.login_limiter = Arc::new(LoginRateLimiter::new(
        Duration::from_secs(1),
        Duration::from_secs(30),
        Duration::from_secs(300),
    ));
    state.admin = Arc::new(TestVerifier);
    production_web_router(
        state,
        HostOriginConfig {
            allowed_hosts: vec!["127.0.0.1:4321".into(), "localhost:4321".into()],
            allowed_origins: vec![
                "http://127.0.0.1:4321".into(),
                "http://localhost:4321".into(),
            ],
        },
        false,
        900,
        kxprov_web::WEB_SESSION_ABSOLUTE_SECS,
        RateLimiter::new(120),
    )
}

fn production_request(method: Method, uri: &str) -> Request<Body> {
    let peer: SocketAddr = "127.0.0.1:4321".parse().unwrap();
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "127.0.0.1:4321")
        .body(Body::empty())
        .unwrap();
    apply_web_connect(&mut req, peer, false);
    req
}

fn production_post(uri: &str, body: &str) -> Request<Body> {
    let peer: SocketAddr = "127.0.0.1:4321".parse().unwrap();
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::HOST, "127.0.0.1:4321")
        .header(header::ORIGIN, "http://127.0.0.1:4321")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap();
    apply_web_connect(&mut req, peer, false);
    req
}

fn n1_not_found_or_method_not_allowed(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
    )
}

#[tokio::test]
async fn missing_host_header_is_rejected_on_production_router() {
    let app = production_like_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn n1_forbidden_mode_profile_paths_return_404_or_405() {
    use kxprov_mock::FORBIDDEN_MODE_PROFILE_PATHS;
    let app = production_like_app();
    for path in FORBIDDEN_MODE_PROFILE_PATHS {
        for method in [Method::GET, Method::PUT, Method::DELETE] {
            let resp = app
                .clone()
                .oneshot(production_request(method.clone(), path))
                .await
                .unwrap();
            assert!(
                n1_not_found_or_method_not_allowed(resp.status()),
                "{} {} on {path} returned {}",
                method,
                path,
                resp.status()
            );
        }
        let post_resp = app
            .clone()
            .oneshot(production_post(path, "_csrf=x"))
            .await
            .unwrap();
        assert!(
            n1_not_found_or_method_not_allowed(post_resp.status()),
            "POST {path} returned {} (expected 404 or 405 only)",
            post_resp.status()
        );
    }
}

#[tokio::test]
async fn n1_registered_routes_exist_on_production_router() {
    let app = production_like_app();
    for route in WEB_ROUTES {
        let uri = match route.path {
            "/static/{file}" => "/static/logo.svg",
            other => other,
        };
        let method = match route.method {
            "GET" => Method::GET,
            "POST" => Method::POST,
            _ => continue,
        };
        let req = if route.method == "POST" {
            production_post(uri, "_csrf=x")
        } else {
            production_request(method, uri)
        };
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{} {} should be registered",
            route.method,
            uri
        );
    }
}

#[tokio::test]
async fn n1_approval_and_apply_http_paths_are_not_on_web_listener() {
    let app = production_like_app();
    for path in WEB_APPROVAL_APPLY_HTTP_PATHS {
        for method in [Method::GET, Method::PUT, Method::DELETE] {
            let resp = app
                .clone()
                .oneshot(production_request(method.clone(), path))
                .await
                .unwrap();
            assert!(
                n1_not_found_or_method_not_allowed(resp.status()),
                "{method} {path} returned {} (expected 404 or 405 only)",
                resp.status()
            );
        }
        let post_resp = app
            .clone()
            .oneshot(production_post(path, "_csrf=x"))
            .await
            .unwrap();
        assert!(
            n1_not_found_or_method_not_allowed(post_resp.status()),
            "{path} POST returned {} (expected 404 or 405 only)",
            post_resp.status()
        );
    }
}

#[test]
fn n1_mcp_approval_tools_are_registered() {
    let server = KxMcpServer::new(Arc::new(kxprov_mock::MockDaemon::new()));
    let names = server.registered_tool_names();
    for tool in MCP_APPROVAL_TOOLS {
        assert!(names.iter().any(|n| n == tool), "missing MCP tool {tool}");
    }
    for tool in MCP_TOOLS {
        assert!(names.iter().any(|n| n == tool), "missing MCP tool {tool}");
    }
}
