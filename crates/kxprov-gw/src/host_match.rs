//! Host / Origin allow-list matching (port-less entries, HTTP/2 `:authority`).

use axum::body::Body;
use axum::extract::Request;
use axum::http::header;

/// Effective host authority: URI authority (`:authority` / HTTP/2), else `Host` header.
pub fn request_host_authority(req: &Request<Body>) -> Option<String> {
    if let Some(auth) = req.uri().authority() {
        return Some(auth.as_str().to_ascii_lowercase());
    }
    req.headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase())
}

/// `allowed` may be `localhost` or `localhost:8080`; `host` is the full authority string.
pub fn host_allowed(allowed_hosts: &[String], host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    allowed_hosts.iter().any(|allowed| {
        let allowed = allowed.to_ascii_lowercase();
        if host == allowed {
            return true;
        }
        let (allowed_host, allowed_port) = split_host_port(&allowed);
        let (req_host, req_port) = split_host_port(&host);
        if req_host == allowed_host {
            return allowed_port.is_none() || allowed_port == req_port;
        }
        false
    })
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

/// Origin allow-list: `http://localhost` matches `http://localhost:8080`.
pub fn origin_allowed(allowed_origins: &[String], origin: &str) -> bool {
    let origin = origin.trim();
    allowed_origins
        .iter()
        .any(|allowed| origin_eq_ignore_port(allowed, origin))
}

fn origin_eq_ignore_port(allowed: &str, origin: &str) -> bool {
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
    let (a_host, a_port) = split_host_port(a_rest.trim_end_matches('/'));
    let (o_host, o_port) = split_host_port(o_rest.trim_end_matches('/'));
    if a_host.to_ascii_lowercase() != o_host.to_ascii_lowercase() {
        return false;
    }
    a_port.is_none() || a_port == o_port
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;

    #[test]
    fn portless_localhost_matches_any_port() {
        assert!(host_allowed(&["localhost".into()], "localhost:8080"));
        assert!(host_allowed(&["127.0.0.1".into()], "127.0.0.1:9443"));
    }

    #[test]
    fn origin_portless_localhost_matches_ported_origin() {
        assert!(origin_allowed(
            &["http://localhost".into()],
            "http://localhost:8080"
        ));
    }

    #[test]
    fn http2_uses_uri_authority_when_host_header_missing() {
        let req = Request::builder()
            .uri("http://localhost:8080/login")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            request_host_authority(&req).as_deref(),
            Some("localhost:8080")
        );
        assert!(host_allowed(&["localhost".into()], "localhost:8080"));
    }
}
