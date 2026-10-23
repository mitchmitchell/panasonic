//! Host / Origin allow-list matching (explicit ports; HTTPS :443 normalization).

use axum::body::Body;
use axum::extract::Request;
use axum::http::header;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostAuthorityError {
    Missing,
    Mismatch,
}

/// Effective host authority with HTTP/2 `:authority` (URI) vs `Host` consistency check.
pub fn effective_host_authority(req: &Request<Body>) -> Result<String, HostAuthorityError> {
    let uri_auth = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_ascii_lowercase());
    let header_host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase());
    match (uri_auth, header_host) {
        (Some(u), Some(h)) if !hosts_equivalent(&u, &h) => Err(HostAuthorityError::Mismatch),
        (Some(u), _) => Ok(u),
        (None, Some(h)) => Ok(h),
        (None, None) => Err(HostAuthorityError::Missing),
    }
}

pub fn host_allowed(allowed_hosts: &[String], host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    allowed_hosts
        .iter()
        .any(|allowed| hosts_equivalent(&host, &allowed.to_ascii_lowercase()))
}

pub fn origin_allowed(allowed_origins: &[String], origin: &str) -> bool {
    let origin = origin.trim();
    allowed_origins
        .iter()
        .any(|allowed| origins_equivalent(allowed, origin))
}

fn hosts_equivalent(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let (ah, ap) = split_host_port(a);
    let (bh, bp) = split_host_port(b);
    if ah != bh {
        return false;
    }
    match (ap.as_deref(), bp.as_deref()) {
        (None, Some("443")) | (Some("443"), None) => true,
        (Some(x), Some(y)) => x == y,
        (None, None) => true,
        _ => false,
    }
}

fn origins_equivalent(allowed: &str, origin: &str) -> bool {
    if origin.eq_ignore_ascii_case(allowed) {
        return true;
    }
    let Some((a_scheme, a_rest)) = allowed.split_once("://") else {
        return false;
    };
    let Some((o_scheme, o_rest)) = origin.split_once("://") else {
        return false;
    };
    if !a_scheme.eq_ignore_ascii_case(o_scheme) {
        return false;
    }
    let a_is_https = a_scheme.eq_ignore_ascii_case("https");
    let o_is_https = o_scheme.eq_ignore_ascii_case("https");
    if a_is_https != o_is_https {
        return false;
    }
    let (a_host, a_port) = split_host_port(a_rest.trim_end_matches('/'));
    let (o_host, o_port) = split_host_port(o_rest.trim_end_matches('/'));
    if !a_host.eq_ignore_ascii_case(&o_host) {
        return false;
    }
    match (a_port.as_deref(), o_port.as_deref()) {
        (None, None) => true,
        (Some("443"), None) | (None, Some("443")) if a_is_https => true,
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

fn split_host_port(authority: &str) -> (String, Option<String>) {
    if authority.starts_with('[') {
        if let Some(end) = authority.find(']') {
            let host = authority[..=end].to_string();
            let rest = &authority[end + 1..];
            let port = rest.strip_prefix(':').map(|p| p.to_string());
            return (host, port);
        }
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), Some(p.to_string()))
        }
        _ => (authority.to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;

    #[test]
    fn explicit_localhost_port_matches_only_that_port() {
        assert!(host_allowed(&["localhost:8080".into()], "localhost:8080"));
        assert!(!host_allowed(&["localhost:8080".into()], "localhost:9443"));
    }

    #[test]
    fn portless_host_matches_https_443_entry() {
        assert!(host_allowed(&["127.0.0.1:443".into()], "127.0.0.1"));
        assert!(host_allowed(&["127.0.0.1".into()], "127.0.0.1:443"));
    }

    #[test]
    fn https_origin_without_port_matches_explicit_443() {
        assert!(origin_allowed(
            &["https://127.0.0.1:443".into()],
            "https://127.0.0.1"
        ));
        assert!(origin_allowed(
            &["https://127.0.0.1".into()],
            "https://127.0.0.1:443"
        ));
    }

    #[test]
    fn http_origin_requires_explicit_port() {
        assert!(origin_allowed(
            &["http://localhost:8080".into()],
            "http://localhost:8080"
        ));
        assert!(!origin_allowed(
            &["http://localhost:8080".into()],
            "http://localhost"
        ));
    }

    #[test]
    fn http2_uses_uri_authority_when_host_header_missing() {
        let req = Request::builder()
            .uri("http://localhost:8080/login")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            effective_host_authority(&req).ok().as_deref(),
            Some("localhost:8080")
        );
    }

    #[test]
    fn host_and_uri_authority_mismatch_is_rejected() {
        let req = Request::builder()
            .uri("http://localhost:8080/login")
            .header(header::HOST, "localhost:9090")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            effective_host_authority(&req),
            Err(HostAuthorityError::Mismatch)
        );
    }
}
