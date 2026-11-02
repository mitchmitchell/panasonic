//! Testing→Production table verify vs last backup (v2.8 N2).

use crate::alert::transition_alert_may_fire_utc;
use crate::audit::{AuditEntry, AuditKind, AuditLog};
use crate::backup::{BackupError, BackupStore};
use crate::config::Config;
use crate::time::now_ms;
use crate::transport::open;
use kxtd1232::tables::spec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use thiserror::Error;

const CALLER_ID_TABLES: [u8; 2] = [0x24, 0x25];

#[derive(Debug, Error)]
pub enum TransitionError {
    #[error("protocol: {0}")]
    Protocol(#[from] kxtd1232::Error),
    #[error("backup: {0}")]
    Backup(#[from] BackupError),
    #[error("transport: {0}")]
    Transport(String),
    #[error("table mismatch vs last prod backup")]
    Mismatch,
    #[error("no prod backup digest")]
    NoDigest,
    #[error("could not persist transition block: {0}")]
    BlockPersist(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransitionBlockState {
    pub active: bool,
    pub detail: String,
    #[serde(default)]
    pub alert_sent: bool,
}

pub struct TransitionBlockStore {
    path: PathBuf,
    audit: AuditLog,
}

impl TransitionBlockStore {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("transition-block.json"),
            audit: AuditLog::new(data_dir),
        }
    }

    pub fn load(&self) -> Result<TransitionBlockState, std::io::Error> {
        if !self.path.exists() {
            return Ok(TransitionBlockState::default());
        }
        let data = std::fs::read_to_string(&self.path)?;
        match serde_json::from_str(&data) {
            Ok(st) => Ok(st),
            Err(_) => Ok(TransitionBlockState {
                active: true,
                detail: "corrupt transition-block file".into(),
                alert_sent: false,
            }),
        }
    }

    pub fn set_blocked(&self, detail: impl Into<String>) -> Result<(), std::io::Error> {
        let detail = detail.into();
        let _ = self.audit.append(&AuditEntry {
            at_ms: now_ms(),
            kind: AuditKind::ModeTransitionMismatch,
            detail: detail.clone(),
        });
        crate::audit::alert_transition_mismatch(&detail);
        let st = TransitionBlockState {
            active: true,
            detail,
            alert_sent: false,
        };
        crate::atomic_write::write(&self.path, &serde_json::to_vec_pretty(&st)?)?;
        Ok(())
    }

    pub fn clear(&self) -> Result<(), std::io::Error> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }

    pub fn writes_blocked(&self) -> bool {
        match self.load() {
            Ok(s) => s.active,
            Err(_) => true,
        }
    }

    pub fn maybe_fire_alert(&self) {
        let Ok(mut st) = self.load() else {
            return;
        };
        if !st.active || st.alert_sent {
            return;
        }
        let now = chrono::Utc::now();
        if transition_alert_may_fire_utc(now) {
            tracing::warn!(detail = %st.detail, "testing→production table mismatch (Mitch)");
            st.alert_sent = true;
            if let Ok(bytes) = serde_json::to_vec_pretty(&st) {
                let _ = std::fs::write(&self.path, bytes);
            }
        }
    }
}

pub fn caller_id_wire_digest(wire: &std::collections::HashMap<u8, Vec<u8>>) -> String {
    let mut h = Sha256::new();
    for t in CALLER_ID_TABLES {
        if let Some(w) = wire.get(&t) {
            h.update(w);
        }
    }
    hex::encode(h.finalize())
}

pub fn live_caller_id_digest(
    config: &Config,
    port: &crate::port::DeviceArbiter,
    holder: &str,
) -> Result<String, TransitionError> {
    let transport = open(config, port, holder).map_err(TransitionError::Transport)?;
    let mut client = crate::transport::client(config, transport, kxtd1232::frame::Access::ReadOnly);
    crate::transport::login(&mut client, &config.password)?;
    let mut wire = std::collections::HashMap::new();
    for t in CALLER_ID_TABLES {
        let _ = spec(t).ok_or(TransitionError::Mismatch)?;
        wire.insert(t, client.read_table(t)?);
    }
    let _ = client.end_binary();
    Ok(caller_id_wire_digest(&wire))
}

/// Prefix of the port-lease holder id for the enter-Production live caller-id check.
pub const SET_MODE_HOLDER: &str = "set-mode-production-verify";

/// Returns a fresh per-request lease holder id for an enter-Production check, so the lease
/// journal can tell concurrent or repeated requests apart (#74).
pub fn set_mode_holder() -> String {
    format!("{SET_MODE_HOLDER}-{}", crate::queue::next_job_id())
}

/// N2: entering Production — compare live 0x24/0x25 to latest **Production-mode** backup.
pub fn verify_enter_production(
    config: &Config,
    port: &crate::port::DeviceArbiter,
    backups: &BackupStore,
) -> Result<(), TransitionError> {
    let expected = backups
        .latest_prod_caller_id_digest()
        .ok_or(TransitionError::NoDigest)?;
    let live = live_caller_id_digest(config, port, &set_mode_holder())?;
    if live != expected {
        return Err(TransitionError::Mismatch);
    }
    Ok(())
}

pub fn verify_enter_production_or_block(
    config: &Config,
    port: &crate::port::DeviceArbiter,
    backups: &BackupStore,
    transition: &TransitionBlockStore,
) -> Result<(), TransitionError> {
    match verify_enter_production(config, port, backups) {
        Ok(()) => Ok(()),
        Err(e @ TransitionError::Mismatch) => {
            transition
                .set_blocked("live caller-id tables differ from last prod backup")
                .map_err(|io| TransitionError::BlockPersist(io.to_string()))?;
            Err(e)
        }
        Err(e @ TransitionError::NoDigest) => {
            transition
                .set_blocked("no production-mode backup for transition verify")
                .map_err(|io| TransitionError::BlockPersist(io.to_string()))?;
            Err(e)
        }
        Err(e @ TransitionError::Protocol(_)) | Err(e @ TransitionError::Transport(_)) => {
            transition
                .set_blocked("live read failed during transition verify")
                .map_err(|io| TransitionError::BlockPersist(io.to_string()))?;
            Err(e)
        }
        Err(e @ TransitionError::Backup(_)) => {
            transition
                .set_blocked("backup read failed during transition verify")
                .map_err(|io| TransitionError::BlockPersist(io.to_string()))?;
            Err(e)
        }
        Err(e @ TransitionError::BlockPersist(_)) => Err(e),
    }
}

#[cfg(test)]
mod holder_tests {
    use super::{set_mode_holder, SET_MODE_HOLDER};
    use crate::api::{apply_preflight_holder, APPLY_PREFLIGHT_HOLDER};

    #[test]
    fn lease_holders_outside_the_worker_are_unique_per_request() {
        let (a, b) = (set_mode_holder(), set_mode_holder());
        assert_ne!(a, b);
        assert!(a.starts_with(SET_MODE_HOLDER), "{a}");
        let (c, d) = (apply_preflight_holder(), apply_preflight_holder());
        assert_ne!(c, d);
        assert!(c.starts_with(APPLY_PREFLIGHT_HOLDER), "{c}");
    }
}
