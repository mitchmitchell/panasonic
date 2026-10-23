//! SO_PEERCRED on Unix sockets (v2.3: daemon enforces identity, never trusts the gateway).

use kxprov_api::Scope;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use std::collections::HashMap;
use thiserror::Error;
use tokio::net::UnixStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

#[derive(Debug, Error)]
pub enum PeerError {
    #[error("peer credentials unavailable: {0}")]
    Nix(#[from] nix::Error),
    #[error("peer uid {uid} is not configured")]
    UnknownPeer { uid: u32 },
    #[error("scope {need:?} not granted to uid {uid}")]
    Denied { uid: u32, need: Scope },
}

pub fn peer_cred(stream: &UnixStream) -> Result<PeerCred, PeerError> {
    let cred = getsockopt(stream, PeerCredentials)?;
    Ok(PeerCred {
        uid: cred.uid(),
        gid: cred.gid(),
        pid: cred.pid(),
    })
}

/// Map uid → allowed scopes. Configured locally in `kxprovd`; the gateway cannot override.
#[derive(Debug, Clone, Default)]
pub struct PeerPolicy {
    by_uid: HashMap<u32, Vec<Scope>>,
}

impl PeerPolicy {
    pub fn new(entries: impl IntoIterator<Item = (u32, Vec<Scope>)>) -> Self {
        Self {
            by_uid: entries.into_iter().collect(),
        }
    }

    pub fn scopes_for(&self, uid: u32) -> Option<&[Scope]> {
        self.by_uid.get(&uid).map(|v| v.as_slice())
    }

    pub fn require(&self, cred: PeerCred, need: Scope) -> Result<(), PeerError> {
        let scopes = self
            .scopes_for(cred.uid)
            .ok_or(PeerError::UnknownPeer { uid: cred.uid })?;
        if scopes.contains(&need) {
            Ok(())
        } else {
            Err(PeerError::Denied {
                uid: cred.uid,
                need,
            })
        }
    }

    pub fn has(&self, cred: PeerCred, need: Scope) -> bool {
        self.require(cred, need).is_ok()
    }
}
