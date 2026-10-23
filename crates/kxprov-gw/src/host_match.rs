//! Host / Origin allow-list matching (explicit `:authority` / Host ports).

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
        (Some(u), Some(h)) if u != h => Err(HostAuthorityError::Mismatch),
        (Some(u), _) => Ok(u),
        (None, Some(h)) => Ok(h),
        (None, None) => Err(HostAuthorityError::Missing),
    }
}

pub fn host_allowed(allowed_hosts: &[String], host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    allowed_hosts
        .iter()
        .any(|allowed| allowed.to_ascii_lowercase() == host)
}

pub fn origin_allowed(allowed_origins: &[String], origin: &str) -> bool {
    let origin = origin.trim();
    allowed_origins
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(origin))
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
    fn origin_requires_explicit_port() {
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
