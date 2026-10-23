//! Login client identity for rate limiting (X-Forwarded-For / Tailscale Serve).

use axum::http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

/// When set on the request (or via [`WebConnectInfo`]), the TCP peer is Tailscale Serve on loopback.
#[derive(Clone, Copy, Debug)]
pub struct ServeProxyTrusted(pub bool);

#[derive(Clone, Debug)]
pub struct WebConnectInfo {
    pub remote: SocketAddr,
    pub serve_proxy_trusted: bool,
}

impl WebConnectInfo {
    pub fn from_parts(remote: SocketAddr, serve_proxy_trusted: bool) -> Self {
        Self {
            remote,
            serve_proxy_trusted,
        }
    }
}

/// Tailscale Serve identity header (set by tailscaled when proxying tailnet traffic).
pub fn tailscale_user_login(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Tailscale-User-Login")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Last non-empty hop in `X-Forwarded-For`.
///
/// Tailscale Serve **sets** (replaces) this header with the observed client address rather than
/// appending to a client-supplied chain; with a single hop, first and last are equivalent.
pub fn x_forwarded_for_last(headers: &HeaderMap) -> Option<IpAddr> {
    let v = headers.get("x-forwarded-for")?.to_str().ok()?;
    let last = v
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .next_back()?;
    last.parse().ok()
}

/// Key for hard IP login backoff (`ip:…` / `ts-login:…` prefixes).
pub fn login_rate_ip_key(
    headers: &HeaderMap,
    peer: SocketAddr,
    trust_x_forwarded_for: bool,
    serve_proxy_trusted: bool,
) -> String {
    if !trust_x_forwarded_for {
        return format!("ip:{}", peer.ip());
    }
    if serve_proxy_trusted {
        if let Some(login) = tailscale_user_login(headers) {
            return format!("ts-login:{login}");
        }
        if let Some(ip) = x_forwarded_for_last(headers) {
            return format!("ip:{ip}");
        }
        return format!("ip:{}", peer.ip());
    }
    if peer.ip().is_loopback() {
        return format!("ip:{}", peer.ip());
    }
    if let Some(ip) = x_forwarded_for_last(headers) {
        return format!("ip:{ip}");
    }
    format!("ip:{}", peer.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn trusted_serve_prefers_tailscale_user_login_over_xff() {
        let mut headers = HeaderMap::new();
        headers.insert("Tailscale-User-Login", "alice@example.com".parse().unwrap());
        headers.insert("x-forwarded-for", "203.0.113.5".parse().unwrap());
        let peer = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(
            login_rate_ip_key(&headers, peer, true, true),
            "ts-login:alice@example.com"
        );
    }

    #[test]
    fn uses_last_xff_hop_when_serve_proxy_trusted_without_identity_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.1, 203.0.113.5".parse().unwrap(),
        );
        let peer = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(
            login_rate_ip_key(&headers, peer, true, true),
            "ip:203.0.113.5"
        );
    }

    #[test]
    fn loopback_untrusted_proxy_ignores_spoofable_xff_for_hard_limit() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.99, 203.0.113.8".parse().unwrap(),
        );
        let peer = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(
            login_rate_ip_key(&headers, peer, true, false),
            "ip:127.0.0.1"
        );
    }

    #[test]
    fn ignores_xff_when_listener_does_not_trust() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.5".parse().unwrap());
        let peer = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(
            login_rate_ip_key(&headers, peer, false, false),
            "ip:127.0.0.1"
        );
    }
}
