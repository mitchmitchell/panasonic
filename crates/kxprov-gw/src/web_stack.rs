use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::header;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::Router;
use kxprov_web::{reject_authenticated_login, require_web_session, WebState};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_sessions::cookie::time::Duration as CookieDuration;
use tower_sessions::cookie::SameSite;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

use crate::host_origin::{host_origin_middleware, security_headers, HostOriginConfig};
use crate::post_origin::post_origin_middleware;
use crate::ratelimit::{rate_limit_middleware, RateLimitState, RateLimiter};

/// Web router with the same middleware ordering as the production gateway.
pub fn production_web_router(
    web_state: WebState,
    host_origin: HostOriginConfig,
    session_ttl_secs: u64,
    rate_limiter: RateLimiter,
) -> Router {
    let web_rate = RateLimitState {
        limiter: rate_limiter,
        key_from_request: Arc::new(|req: &Request<Body>| {
            req.extensions()
                .get::<String>()
                .cloned()
                .or_else(|| Some("web-anonymous".into()))
        }),
    };

    let session_layer = SessionManagerLayer::new(MemoryStore::default())
        .with_name("__Host-kxprov.sid")
        .with_secure(true)
        .with_http_only(true)
        .with_same_site(SameSite::Strict)
        .with_expiry(Expiry::OnInactivity(CookieDuration::seconds(
            session_ttl_secs as i64,
        )));

    kxprov_web::router(web_state)
        .layer(from_fn(require_web_session))
        .layer(from_fn(reject_authenticated_login))
        .layer(session_layer)
        .layer(from_fn_with_state(
            web_rate.clone(),
            web_identity_rate_limit,
        ))
        .layer(from_fn_with_state(
            host_origin.clone(),
            post_origin_middleware,
        ))
        .layer(from_fn_with_state(host_origin.clone(), host_origin_layer))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            security_headers(),
        ))
}

async fn web_identity_rate_limit(
    axum::extract::State(rate): axum::extract::State<RateLimitState>,
    mut req: Request<Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    if let Some(session_key) = req
        .extensions()
        .get::<String>()
        .cloned()
        .or_else(|| Some("web-anonymous".into()))
    {
        req.extensions_mut().insert(session_key);
    }
    rate_limit_middleware(axum::extract::State(rate), req, next).await
}

async fn host_origin_layer(
    axum::extract::State(cfg): axum::extract::State<HostOriginConfig>,
    req: Request<Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    host_origin_middleware(cfg, req, next).await
}
