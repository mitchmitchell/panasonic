//! Tailscale Serve loopback trust via SO_PEERCRED (Linux).

use axum::extract::connect_info::Connected;
use axum::extract::{ConnectInfo, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum::serve::IncomingStream;
use kxprov_web::WebConnectInfo;
use std::net::SocketAddr;
use std::sync::OnceLock;
use tokio::net::{TcpListener, TcpStream};

static TAILNET_SERVE_TRUST: OnceLock<ServeTrustConfig> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeTrustConfig {
    pub trust_x_forwarded_for: bool,
    pub expected_peer_uid: u32,
}

impl ServeTrustConfig {
    pub fn evaluate(&self, peer_addr: SocketAddr, peer_uid: Option<u32>) -> bool {
        self.trust_x_forwarded_for
            && peer_addr.ip().is_loopback()
            && peer_uid == Some(self.expected_peer_uid)
    }

    pub fn web_connect_info(&self, stream: &TcpStream, peer_addr: SocketAddr) -> WebConnectInfo {
        let peer_uid = peer_connection_uid(stream);
        let serve_proxy_trusted = self.evaluate(peer_addr, peer_uid);
        WebConnectInfo::from_parts(peer_addr, serve_proxy_trusted)
    }
}

/// Installed once before the tailnet accept loop starts (production gateway startup).
pub fn install_tailnet_serve_trust(cfg: ServeTrustConfig) {
    let _ = TAILNET_SERVE_TRUST.set(cfg);
}

/// Per-connection info for the tailnet HTTP listener (SO_PEERCRED + socket peer).
#[derive(Clone, Debug)]
pub struct TailnetConnect(pub WebConnectInfo);

impl Connected<IncomingStream<'_, TcpListener>> for TailnetConnect {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        let peer = stream.remote_addr().to_owned();
        let tcp = stream.io();
        let info = TAILNET_SERVE_TRUST
            .get()
            .map(|cfg| cfg.web_connect_info(tcp, peer))
            .unwrap_or_else(|| WebConnectInfo::from_parts(peer, false));
        TailnetConnect(info)
    }
}

#[cfg(unix)]
pub fn peer_connection_uid(stream: &TcpStream) -> Option<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    let cred = getsockopt(stream, PeerCredentials).ok()?;
    Some(cred.uid())
}

#[cfg(not(unix))]
pub fn peer_connection_uid(_stream: &TcpStream) -> Option<u32> {
    None
}

/// Default Tailscale daemon user for Serve-fronted loopback HTTP.
/// Copies [`TailnetConnect`] into [`WebConnectInfo`] and [`ConnectInfo<SocketAddr>`] for shared handlers.
pub async fn inject_web_connect(
    ConnectInfo(TailnetConnect(info)): ConnectInfo<TailnetConnect>,
    mut req: Request,
    next: Next,
) -> Response {
    let peer = info.remote;
    req.extensions_mut().insert(info);
    req.extensions_mut().insert(ConnectInfo(peer));
    next.run(req).await
}

pub fn resolve_tailscaled_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        if let Ok(user) = nix::unistd::User::from_name("tailscale") {
            return user.map(|u| u.uid.as_raw());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn evaluate_serve_proxy_trust_requires_matching_uid_on_loopback() {
        let trust = ServeTrustConfig {
            trust_x_forwarded_for: true,
            expected_peer_uid: 42,
        };
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        assert!(!trust.evaluate(peer, None));
        assert!(!trust.evaluate(peer, Some(41)));
        assert!(trust.evaluate(peer, Some(42)));
        let lan = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        assert!(!trust.evaluate(lan, Some(42)));
    }

    #[test]
    fn tailnet_serve_trust_uses_config_not_test_helpers() {
        let cfg = crate::config::GatewayConfig {
            web_tailnet: crate::config::WebListenerSettings {
                trust_x_forwarded_for: true,
                serve_peer_uid: Some(999),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            cfg.tailnet_serve_trust(),
            ServeTrustConfig {
                trust_x_forwarded_for: true,
                expected_peer_uid: 999,
            }
        );
    }
}
