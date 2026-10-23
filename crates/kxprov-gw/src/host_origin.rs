use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::host_match::{host_allowed, origin_allowed as origin_matches, request_host_authority};

#[derive(Clone)]
pub struct HostOriginConfig {
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
}

pub async fn host_origin_middleware(
    cfg: HostOriginConfig,
    req: Request<Body>,
    next: Next,
) -> Response {
    let Some(host) = request_host_authority(&req) else {
        return (StatusCode::BAD_REQUEST, "missing host").into_response();
    };
    if !host_allowed(&cfg.allowed_hosts, &host) {
        return (StatusCode::MISDIRECTED_REQUEST, "unknown host").into_response();
    }
    if let Some(origin) = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    {
        if !origin_matches(&cfg.allowed_origins, origin) {
            return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
        }
    }
    next.run(req).await
}

pub fn security_headers() -> HeaderValue {
    HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'; script-src 'self'")
}
