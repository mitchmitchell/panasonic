use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, Method};
use axum::middleware::Next;
use axum::response::Response;

use kxprov_web::is_n1_unregistered_web_path;

use crate::host_match::origin_allowed as origin_matches;
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
    if path.starts_with("/mcp") || is_n1_unregistered_web_path(path) {
        return next.run(req).await;
    }
    if origin_allowed(&cfg, req.headers()) {
        return next.run(req).await;
    }
    kxprov_web::stale_form_page()
}

fn referer_origin(referer: &str) -> Option<String> {
    let referer = referer.trim();
    let (scheme, rest) = referer.split_once("://")?;
    let authority = rest.split('/').next()?.trim_end_matches('/');
    if authority.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{authority}"))
}

fn state_changing_method(method: &Method) -> bool {
    matches!(
        method,
        &Method::POST | &Method::PUT | &Method::PATCH | &Method::DELETE
    )
}

fn origin_allowed(cfg: &HostOriginConfig, headers: &axum::http::HeaderMap) -> bool {
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        return origin_matches(&cfg.allowed_origins, origin);
    }
    if let Some(referer) = headers.get(header::REFERER).and_then(|v| v.to_str().ok()) {
        let Some(referer_origin) = referer_origin(referer) else {
            return false;
        };
        return origin_matches(&cfg.allowed_origins, &referer_origin);
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
            allowed_hosts: vec!["localhost:8443".into()],
            allowed_origins: vec!["https://localhost:8443".into()],
        };
        assert!(!origin_allowed(&cfg, &HeaderMap::new()));
    }

    #[test]
    fn localhost_ported_origin_allowed_when_listed() {
        let cfg = HostOriginConfig {
            allowed_hosts: vec!["localhost:8080".into()],
            allowed_origins: vec!["http://localhost:8080".into()],
        };
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "http://localhost:8080".parse().unwrap());
        assert!(origin_allowed(&cfg, &headers));
    }

    #[test]
    fn referer_fallback_matches_allowed_origin() {
        let cfg = HostOriginConfig {
            allowed_hosts: vec!["127.0.0.1:8443".into()],
            allowed_origins: vec!["https://127.0.0.1:8443".into()],
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::REFERER,
            "https://127.0.0.1:8443/dashboard".parse().unwrap(),
        );
        assert!(origin_allowed(&cfg, &headers));
    }

    #[test]
    fn referer_prefix_port_spoof_rejected() {
        let cfg = HostOriginConfig {
            allowed_hosts: vec!["127.0.0.1:8443".into()],
            allowed_origins: vec!["https://127.0.0.1:8443".into()],
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::REFERER,
            "https://127.0.0.1:84430/evil".parse().unwrap(),
        );
        assert!(!origin_allowed(&cfg, &headers));
    }
}
