use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

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
    if let Some(host) = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
    {
        let host_lower = host.to_ascii_lowercase();
        if !cfg
            .allowed_hosts
            .iter()
            .any(|allowed| host_lower == allowed.to_ascii_lowercase())
        {
            return (StatusCode::MISDIRECTED_REQUEST, "unknown host").into_response();
        }
    }
    if let Some(origin) = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    {
        if !cfg
            .allowed_origins
            .iter()
            .any(|allowed| origin.eq_ignore_ascii_case(allowed))
        {
            return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
        }
    }
    next.run(req).await
}

pub fn security_headers() -> HeaderValue {
    HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'; script-src 'self'")
}
