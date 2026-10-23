//! Tailscale Serve trust via Unix socket SO_PEERCRED (Linux).

use axum::extract::connect_info::Connected;
use axum::extract::{ConnectInfo, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum::serve::IncomingStream;
use kxprov_web::WebConnectInfo;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use thiserror::Error;
use tokio::net::{UnixListener, UnixStream};

static TAILNET_SERVE_TRUST: OnceLock<ServeTrustConfig> = OnceLock::new();

/// Production runtime directory for Serve socket and related state (`0750`).
pub const PROVISION_RUNTIME_DIR: &str = "/run/kx-provision";

const RUNTIME_DIR_MODE: u32 = 0o750;
const SOCKET_MODE: u32 = 0o660;
/// Umask so a newly bound socket is at most `0660` before explicit `chmod`.
const BIND_UMASK: nix::sys::stat::Mode = nix::sys::stat::Mode::from_bits_truncate(0o117);

/// Placeholder socket peer for Serve-fronted HTTP (real client IP comes from XFF when trusted).
pub const SERVE_LOOPBACK_PEER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);

#[derive(Debug, Error)]
pub enum ServeListenerError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("serve socket group {name:?} not found")]
    GroupMissing { name: String },
    #[error("serve runtime directory {path} must be mode 0750")]
    RuntimeDirMode { path: PathBuf },
    #[error("serve runtime directory {path} must be root-owned")]
    RuntimeDirOwner { path: PathBuf },
    #[error("refusing to bind: {path} is a symlink")]
    SocketSymlink { path: PathBuf },
    #[error("refusing to bind: {path} exists and is not a socket")]
    SocketNotSocket { path: PathBuf },
}

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

#[cfg(unix)]
fn enforce_root_runtime_checks() -> bool {
    nix::unistd::geteuid().is_root()
}

#[cfg(not(unix))]
fn enforce_root_runtime_checks() -> bool {
    false
}

/// Ensures `{parent}` exists with mode `0750` and (when root) root ownership.
#[cfg(unix)]
pub fn ensure_provision_runtime_dir(dir: &Path) -> Result<(), ServeListenerError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(RUNTIME_DIR_MODE))?;
    }
    let meta = std::fs::metadata(dir)?;
    if meta.mode() & 0o777 != RUNTIME_DIR_MODE {
        return Err(ServeListenerError::RuntimeDirMode {
            path: dir.to_path_buf(),
        });
    }
    if enforce_root_runtime_checks() && meta.uid() != 0 {
        return Err(ServeListenerError::RuntimeDirOwner {
            path: dir.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn ensure_provision_runtime_dir(dir: &Path) -> Result<(), ServeListenerError> {
    std::fs::create_dir_all(dir)?;
    Ok(())
}

#[cfg(unix)]
fn remove_stale_socket(path: &Path) -> Result<(), ServeListenerError> {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ServeListenerError::Io(e)),
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(ServeListenerError::SocketSymlink {
                    path: path.to_path_buf(),
                });
            }
            if !meta.file_type().is_socket() {
                return Err(ServeListenerError::SocketNotSocket {
                    path: path.to_path_buf(),
                });
            }
            std::fs::remove_file(path).map_err(ServeListenerError::Io)
        }
    }
}

#[cfg(not(unix))]
fn remove_stale_socket(_path: &Path) -> Result<(), ServeListenerError> {
    Ok(())
}

#[cfg(unix)]
fn resolve_serve_group(name: &str) -> Result<nix::unistd::Gid, ServeListenerError> {
    match nix::unistd::Group::from_name(name) {
        Ok(Some(g)) => Ok(g.gid),
        Ok(None) => Err(ServeListenerError::GroupMissing {
            name: name.to_string(),
        }),
        Err(e) => Err(ServeListenerError::Io(e.into())),
    }
}

/// Prepare runtime dir, bind Serve socket (`0660`), optional group via path `chown`.
pub async fn bind_web_serve_listener(
    path: &Path,
    group: Option<&str>,
) -> Result<UnixListener, ServeListenerError> {
    if let Some(parent) = path.parent() {
        ensure_provision_runtime_dir(parent)?;
    }
    remove_stale_socket(path)?;

    #[cfg(unix)]
    let gid = if let Some(name) = group {
        Some(resolve_serve_group(name)?)
    } else {
        None
    };

    #[cfg(unix)]
    let old_umask = nix::sys::stat::umask(BIND_UMASK);
    let bind_result = UnixListener::bind(path);
    #[cfg(unix)]
    {
        let _ = nix::sys::stat::umask(old_umask);
    }
    let listener = bind_result.map_err(ServeListenerError::Io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))?;
        let uid = if enforce_root_runtime_checks() {
            Some(nix::unistd::Uid::from_raw(0))
        } else {
            None
        };
        nix::unistd::chown(path, uid, gid).map_err(|e| ServeListenerError::Io(e.into()))?;
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
