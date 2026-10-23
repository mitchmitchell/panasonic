//! Testing→Production table verify vs last backup (v2.8 N2).

use crate::alert::transition_alert_may_fire_utc;
use crate::audit::{AuditEntry, AuditKind, AuditLog};
use crate::backup::{BackupError, BackupStore};
use crate::config::Config;
use crate::time::now_ms;
use crate::transport::open;
use kxtd1232::tables::spec;
use kxtd1232::Client;
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
        Ok(serde_json::from_str(&data).unwrap_or_default())
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
        std::fs::write(&self.path, serde_json::to_vec_pretty(&st)?)?;
        Ok(())
    }

    pub fn clear(&self) -> Result<(), std::io::Error> {
        if self.path.exists() {
            let _ = std::fs::remove_file(&self.path);
        }
        Ok(())
    }

    pub fn writes_blocked(&self) -> bool {
        self.load().ok().is_some_and(|s| s.active)
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

pub fn live_caller_id_digest(config: &Config) -> Result<String, TransitionError> {
    let transport = open(config).map_err(TransitionError::Transport)?;
    let mut client = Client::with(transport, kxtd1232::frame::Access::ReadOnly, config.timing);
    client.login(&config.password)?;
    let mut wire = std::collections::HashMap::new();
    for t in CALLER_ID_TABLES {
        let _ = spec(t).ok_or(TransitionError::Mismatch)?;
        wire.insert(t, client.read_table(t)?);
    }
    let _ = client.end_binary();
    Ok(caller_id_wire_digest(&wire))
}

pub fn verify_testing_to_production(
    config: &Config,
    backups: &BackupStore,
) -> Result<(), TransitionError> {
    let expected = backups
        .latest_caller_id_digest()
        .ok_or(TransitionError::NoDigest)?;
    let live = live_caller_id_digest(config)?;
    if live != expected {
        return Err(TransitionError::Mismatch);
    }
    Ok(())
}
