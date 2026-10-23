use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::host_origin::HostOriginConfig;

/// Fail closed on state-changing requests without a matching Origin or Referer.
pub async fn post_origin_middleware(
    State(cfg): State<HostOriginConfig>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if !state_changing_method(req.method()) {
        return next.run(req).await;
    }
    let path = req.uri().path();
    if path.starts_with("/mcp") {
        return next.run(req).await;
    }
    if origin_allowed(&cfg, req.headers()) {
        return next.run(req).await;
    }
    (StatusCode::FORBIDDEN, "origin not allowed").into_response()
}

fn state_changing_method(method: &Method) -> bool {
    matches!(
        method,
        &Method::POST | &Method::PUT | &Method::PATCH | &Method::DELETE
    )
}

fn origin_allowed(cfg: &HostOriginConfig, headers: &axum::http::HeaderMap) -> bool {
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        return cfg
            .allowed_origins
            .iter()
            .any(|allowed| origin.eq_ignore_ascii_case(allowed));
    }
    if let Some(referer) = headers.get(header::REFERER).and_then(|v| v.to_str().ok()) {
        return cfg.allowed_origins.iter().any(|allowed| {
            referer
                .trim_end_matches('/')
                .eq_ignore_ascii_case(allowed.trim_end_matches('/'))
                || referer.starts_with(&format!("{allowed}/"))
        });
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn missing_origin_and_referer_is_rejected() {
        let cfg = HostOriginConfig {
            allowed_hosts: vec!["localhost".into()],
            allowed_origins: vec!["https://localhost".into()],
        };
        assert!(!origin_allowed(&cfg, &HeaderMap::new()));
    }

    #[test]
    fn referer_fallback_matches_allowed_origin() {
        let cfg = HostOriginConfig {
            allowed_hosts: vec!["127.0.0.1".into()],
            allowed_origins: vec!["https://127.0.0.1".into()],
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::REFERER,
            "https://127.0.0.1/dashboard".parse().unwrap(),
        );
        assert!(origin_allowed(&cfg, &headers));
    }
}
