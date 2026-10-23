mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use axum::middleware::from_fn;
use axum::Router;
use http_body_util::BodyExt;
use kxprov_gw::{production_web_router, HostOriginConfig, RateLimiter};
use kxprov_mock::WEB_ROUTES;
use kxprov_web::require_web_session;
use kxprov_web::LoginRateLimiter;
use support::{
    cookie_header_from_set_cookies, form_urlencoded, merge_cookie_headers, test_web_state,
    TestVerifier,
};
use tower::ServiceExt;
use tower_sessions::cookie::time::Duration as CookieDuration;
use tower_sessions::cookie::SameSite;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

const PEER: &str = "127.0.0.1:4321";

fn with_peer(mut req: Request<Body>) -> Request<Body> {
    req.extensions_mut()
        .insert(ConnectInfo(PEER.parse::<SocketAddr>().unwrap()));
    req
}

fn production_app() -> Router {
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

fn dev_app() -> Router {
    let state = test_web_state();
    let session = SessionManagerLayer::new(MemoryStore::default())
        .with_name("__Host-kxprov.sid")
        .with_secure(true)
        .with_http_only(true)
        .with_same_site(SameSite::Strict)
        .with_expiry(Expiry::OnInactivity(CookieDuration::seconds(900)));
    kxprov_web::router(state)
        .layer(from_fn(require_web_session))
        .layer(session)
}

async fn body_string(resp: axum::response::Response) -> String {
    String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned()
}

async fn csrf_from_login(app: &Router) -> (String, String) {
    let resp = app
        .clone()
        .oneshot(with_peer(
            Request::builder()
                .uri("/login")
                .header(header::HOST, "127.0.0.1:4321")
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let cookie = cookie_header_from_set_cookies(resp.headers());
    let html = body_string(resp).await;
    let csrf = html
        .split("name=\"_csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("csrf in login form")
        .to_string();
    (cookie, csrf)
}

fn post_form(uri: &str, cookie: Option<&str>, body: &str) -> Request<Body> {
    let peer: SocketAddr = PEER.parse().unwrap();
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::HOST, "127.0.0.1:4321")
        .header(header::ORIGIN, "http://127.0.0.1:4321")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        builder = builder.header(header::COOKIE, c);
    }
    let mut req = builder.body(Body::from(body.to_string())).unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    req
}

async fn login_session(app: &Router) -> (String, String) {
    let (cookie, csrf) = csrf_from_login(app).await;
    let resp = app
        .clone()
        .oneshot(post_form(
            "/login",
            Some(&cookie),
            &format!(
                "password=test-admin-password&_csrf={}",
                form_urlencoded(&csrf)
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let session_cookie = merge_cookie_headers(&cookie, resp.headers());
    let dash = app
        .clone()
        .oneshot(with_peer(
            Request::builder()
                .uri("/")
                .header(header::HOST, "127.0.0.1:4321")
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let session_cookie = merge_cookie_headers(&session_cookie, dash.headers());
    let html = body_string(dash).await;
    let dash_csrf = html
        .split("name=\"_csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("csrf on dashboard")
        .to_string();
    (session_cookie, dash_csrf)
}

fn default_post_body(path: &str, csrf: &str) -> String {
    let token = form_urlencoded(csrf);
    match path {
        "/login" => format!("password=x&_csrf={token}"),
        "/logout" => format!("_csrf={token}"),
        "/read" => format!("table=36&record=1&_csrf={token}"),
        "/plan" | "/api/plan" => {
            format!("table=36&record=1&field=cid_number&new_value=5550100&_csrf={token}")
        }
        "/api/apply" | "/api/approval/submit" => format!("_csrf={token}"),
        other => panic!("unexpected POST path {other}"),
    }
}

async fn assert_post_csrf_rejected(app: Router, path: &str, cookie: Option<&str>) {
    for (label, csrf) in [("missing", ""), ("wrong", "not-a-valid-csrf-token")] {
        let body = default_post_body(path, csrf);
        let resp = app
            .clone()
            .oneshot(post_form(path, cookie, &body))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{path} should reject {label} CSRF token"
        );
    }
}

#[tokio::test]
async fn production_router_rejects_bad_csrf_on_every_post_route() {
    let app = production_app();
    let (login_cookie, _login_csrf) = csrf_from_login(&app).await;
    let (session_cookie, _) = login_session(&app).await;

    for route in WEB_ROUTES {
        if route.method != "POST" {
            continue;
        }
        let cookie = if route.path == "/login" {
            login_cookie.as_str()
        } else {
            session_cookie.as_str()
        };
        assert_post_csrf_rejected(app.clone(), route.path, Some(cookie)).await;
    }
}

#[tokio::test]
async fn dev_router_rejects_bad_csrf_on_post_routes() {
    let app = dev_app();
    let (login_cookie, _) = csrf_from_login(&app).await;
    let (session_cookie, _) = login_session(&app).await;

    for route in WEB_ROUTES {
        if route.method != "POST" {
            continue;
        }
        let cookie = if route.path == "/login" {
            login_cookie.as_str()
        } else {
            session_cookie.as_str()
        };
        assert_post_csrf_rejected(app.clone(), route.path, Some(cookie)).await;
    }
}
