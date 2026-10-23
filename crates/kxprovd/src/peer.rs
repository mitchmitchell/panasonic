//! SO_PEERCRED on Unix sockets (v2.3 §5b F2: daemon enforces identity, never trusts gateway).

use kxprov_api::Scope;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use thiserror::Error;
use tokio::net::UnixStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    /// Root / admin CLI: mint approvals, unlock, token admin.
    Admin,
    /// `kxprov-gw`: forwards token id; daemon re-checks scopes.
    Gateway,
    /// Direct read/dry-run only (no token forwarding path).
    ReadOnly,
}

#[derive(Debug, Error)]
pub enum PeerError {
    #[error("peer credentials unavailable: {0}")]
    Nix(#[from] nix::Error),
    #[error("peer uid {uid} is not configured")]
    UnknownPeer { uid: u32 },
    #[error("scope {need:?} not granted")]
    Denied { need: Scope },
    #[error("admin role required")]
    AdminRequired,
    #[error("gateway token required")]
    TokenRequired,
}

pub fn peer_cred(stream: &UnixStream) -> Result<PeerCred, PeerError> {
    let cred = getsockopt(stream, PeerCredentials)?;
    Ok(PeerCred {
        uid: cred.uid(),
        gid: cred.gid(),
        pid: cred.pid(),
    })
}

#[derive(Debug, Clone)]
pub struct PeerPolicy {
    gateway_uid: u32,
    admin_uid: u32,
}

impl PeerPolicy {
    pub fn new(gateway_uid: u32, admin_uid: u32) -> Self {
        Self {
            gateway_uid,
            admin_uid,
        }
    }

    pub fn role(&self, cred: PeerCred) -> PeerRole {
        if cred.uid == self.admin_uid {
            PeerRole::Admin
        } else if cred.uid == self.gateway_uid {
            PeerRole::Gateway
        } else {
            PeerRole::ReadOnly
        }
    }

    pub fn is_admin(&self, cred: PeerCred) -> bool {
        self.role(cred) == PeerRole::Admin
    }
}
