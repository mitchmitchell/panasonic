//! Tailscale Serve trust via Unix socket SO_PEERCRED (Linux).

use axum::extract::connect_info::Connected;
use axum::extract::{ConnectInfo, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum::serve::IncomingStream;
use kxprov_web::WebConnectInfo;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::OnceLock;
use tokio::net::{UnixListener, UnixStream};

static TAILNET_SERVE_TRUST: OnceLock<ServeTrustConfig> = OnceLock::new();

/// Placeholder socket peer for Serve-fronted HTTP (real client IP comes from XFF when trusted).
pub const SERVE_LOOPBACK_PEER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeTrustConfig {
    pub trust_x_forwarded_for: bool,
    pub expected_peer_uid: u32,
}

impl ServeTrustConfig {
    pub fn evaluate(&self, peer_uid: Option<u32>) -> bool {
        self.trust_x_forwarded_for && peer_uid == Some(self.expected_peer_uid)
    }

    pub fn web_connect_info(&self, stream: &UnixStream) -> WebConnectInfo {
        let peer_uid = peer_connection_uid(stream);
        let serve_proxy_trusted = self.evaluate(peer_uid);
        tracing::debug!(
            resolved_peer_uid = ?peer_uid,
            expected_serve_peer_uid = self.expected_peer_uid,
            serve_proxy_trusted,
            "Serve Unix SO_PEERCRED"
        );
        WebConnectInfo::from_parts(SERVE_LOOPBACK_PEER, serve_proxy_trusted)
    }
}

/// Installed once before the Serve Unix accept loop starts (production gateway startup).
pub fn install_tailnet_serve_trust(cfg: ServeTrustConfig) {
    let _ = TAILNET_SERVE_TRUST.set(cfg);
}

/// Per-connection info for the Serve Unix listener (SO_PEERCRED).
#[derive(Clone, Debug)]
pub struct TailnetConnect(pub WebConnectInfo);

impl Connected<IncomingStream<'_, UnixListener>> for TailnetConnect {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        let unix = stream.io();
        let info = TAILNET_SERVE_TRUST
            .get()
            .map(|cfg| cfg.web_connect_info(unix))
            .unwrap_or_else(|| WebConnectInfo::from_parts(SERVE_LOOPBACK_PEER, false));
        TailnetConnect(info)
    }
}

#[cfg(unix)]
pub fn peer_connection_uid(stream: &UnixStream) -> Option<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    let cred = getsockopt(stream, PeerCredentials).ok()?;
    Some(cred.uid())
}

#[cfg(not(unix))]
pub fn peer_connection_uid(_stream: &UnixStream) -> Option<u32> {
    None
}

/// Creates parent dirs, removes stale socket, binds, mode `0660`, optional group for `chown`.
pub async fn bind_web_serve_listener(
    path: &Path,
    group: Option<&str>,
) -> std::io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        if let Some(name) = group {
            if let Ok(Some(g)) = nix::unistd::Group::from_name(name) {
                use std::os::unix::io::AsRawFd;
                if let Ok(file) = std::fs::File::open(path) {
                    let _ = nix::unistd::fchown(
                        file.as_raw_fd(),
                        None,
                        Some(nix::unistd::Gid::from_raw(g.gid.as_raw())),
                    );
                }
            }
        }
    }
    Ok(listener)
}

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
