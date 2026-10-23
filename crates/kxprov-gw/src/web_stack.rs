use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request};
use axum::http::header;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::Router;
use kxprov_web::{
    enforce_absolute_session_limit, reject_authenticated_login, require_web_session,
    ClientIpPolicy, WebState,
};
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
    trust_x_forwarded_for: bool,
    session_idle_secs: u64,
    session_absolute_secs: u64,
    rate_limiter: RateLimiter,
) -> Router {
    let web_rate = RateLimitState {
        limiter: rate_limiter,
        key_from_request: Arc::new(|req: &Request<Body>| req.extensions().get::<String>().cloned()),
    };

    let session_layer = SessionManagerLayer::new(MemoryStore::default())
        .with_name("__Host-kxprov.sid")
        .with_secure(true)
        .with_http_only(true)
        .with_same_site(SameSite::Strict)
        .with_expiry(Expiry::OnInactivity(CookieDuration::seconds(
            session_idle_secs as i64,
        )));

    let absolute_secs = session_absolute_secs;
    kxprov_web::router(web_state)
        .layer(from_fn(require_web_session))
        .layer(from_fn(move |session, req, next| {
            enforce_absolute_session_limit(session, req, next, absolute_secs)
        }))
        .layer(from_fn(reject_authenticated_login))
        .layer(session_layer)
        .layer(from_fn({
            move |mut req: Request<Body>, next: axum::middleware::Next| {
                let trust = trust_x_forwarded_for;
                async move {
                    req.extensions_mut().insert(ClientIpPolicy {
                        trust_x_forwarded_for: trust,
                    });
                    next.run(req).await
                }
            }
        }))
        .layer(from_fn(inject_web_rate_limit_key))
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

async fn inject_web_rate_limit_key(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request<Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if req.extensions().get::<String>().is_none() {
        req.extensions_mut().insert(format!("web-ip:{}", peer.ip()));
    }
    next.run(req).await
}

async fn web_identity_rate_limit(
    axum::extract::State(rate): axum::extract::State<RateLimitState>,
    req: Request<Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    rate_limit_middleware(axum::extract::State(rate), req, next).await
}

async fn host_origin_layer(
    axum::extract::State(cfg): axum::extract::State<HostOriginConfig>,
    req: Request<Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    host_origin_middleware(cfg, req, next).await
}
