use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use kxprov_api::{
    default_approval_url, ApiError, CallerIdentity, DaemonBackend, McpTokenIdentity, MockDaemon,
    PlanChangeRequest, Scope, ScopeSet, TokenId, WebAdminIdentity,
};
use kxprov_web::{router, WebState};
use tower::ServiceExt;
use tower_sessions::{MemoryStore, SessionManagerLayer};

fn test_app(backend: Arc<MockDaemon>) -> axum::Router {
    router(WebState { backend })
        .layer(SessionManagerLayer::new(MemoryStore::default()).with_secure(false))
}

fn comms() -> CallerIdentity {
    CallerIdentity::Mcp(McpTokenIdentity {
        token_id: TokenId("t".into()),
        agent_name: "Comms".into(),
        scopes: ScopeSet::empty().with(Scope::Plan),
    })
}

#[tokio::test]
async fn logged_out_approval_redirects_to_login_with_safe_next() {
    let backend = Arc::new(MockDaemon::new());
    let plan = backend
        .plan_change(
            &comms(),
            PlanChangeRequest {
                table: 0x24,
                record: 1,
                field: "n".into(),
                new_value: "v".into(),
                base_bytes: vec![],
                new_bytes: vec![1],
            },
        )
        .await
        .expect("plan");
    let url = default_approval_url(&plan.plan_id, &plan.diff_hash);
    let app = test_app(backend);
    let resp = app
        .oneshot(Request::builder().uri(&url).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.starts_with("/login?next="));
    assert!(loc.contains("%2Fplans%2F"));
}

#[tokio::test]
async fn login_rejects_open_redirect_in_next() {
    let app = test_app(Arc::new(MockDaemon::new()));
    let body = "password=test-admin-password&next=https%3A%2F%2Fevil.example%2F&_csrf=x";
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(loc, "/");
}

#[tokio::test]
async fn login_then_lands_on_approval_page() {
    let backend = Arc::new(MockDaemon::new());
    let plan = backend
        .plan_change(
            &comms(),
            PlanChangeRequest {
                table: 0x24,
                record: 1,
                field: "n".into(),
                new_value: "v".into(),
                base_bytes: vec![],
                new_bytes: vec![3],
            },
        )
        .await
        .expect("plan");
    let approval_path = default_approval_url(&plan.plan_id, &plan.diff_hash);
    let app = test_app(backend);
    let login_body = format!(
        "password=test-admin-password&next={}&_csrf=x",
        urlencoding::encode(&approval_path)
    );
    let login_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(login_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login_resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        login_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap(),
        approval_path
    );
    let cookie = login_resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .next()
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let page = app
        .oneshot(
            Request::builder()
                .uri(&approval_path)
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let body = to_bytes(page.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("Approve plan"));
}

#[tokio::test]
async fn expired_plan_shows_expired_page_when_authenticated() {
    let backend = Arc::new(MockDaemon::new());
    let plan = backend
        .plan_change(
            &comms(),
            PlanChangeRequest {
                table: 0x24,
                record: 1,
                field: "n".into(),
                new_value: "v".into(),
                base_bytes: vec![],
                new_bytes: vec![4],
            },
        )
        .await
        .expect("plan");
    let approval_path = default_approval_url(&plan.plan_id, &plan.diff_hash);
    backend
        .test_backdate_plan(
            plan.plan_id,
            kxprov_api::plan_storage_ttl() + time::Duration::minutes(1),
        )
        .await;
    let err = backend
        .get_plan(
            &CallerIdentity::WebAdmin(WebAdminIdentity {
                session_id: "s".into(),
            }),
            plan.plan_id,
            plan.diff_hash,
        )
        .await;
    assert!(matches!(err, Err(ApiError::PlanExpired)));
    let app = test_app(backend);
    let login_body = format!(
        "password=test-admin-password&next={}&_csrf=x",
        urlencoding::encode(&approval_path)
    );
    let login_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(login_body))
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = login_resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .next()
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let page = app
        .oneshot(
            Request::builder()
                .uri(&approval_path)
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let body = to_bytes(page.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("expired") || html.contains("Expired"),
        "expected expired approval copy, got: {html}"
    );
}

#[tokio::test]
async fn static_logo_is_served() {
    let app = test_app(Arc::new(MockDaemon::new()));
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
}
