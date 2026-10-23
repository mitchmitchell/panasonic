//! Persisted LOCKED state (cleared only via root `kxprov unlock`).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LockedError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LockedState {
    pub locked: bool,
    pub since_ms: u64,
    pub reason: String,
    pub job_id: Option<String>,
}

pub struct LockedStore {
    path: PathBuf,
}

impl LockedStore {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("locked.json"),
        }
    }

    pub fn load(&self) -> Result<LockedState, LockedError> {
        if !self.path.exists() {
            return Ok(LockedState::default());
        }
        Ok(serde_json::from_slice(&std::fs::read(&self.path)?)?)
    }

    pub fn set_locked(
        &self,
        reason: &str,
        job_id: Option<&str>,
        now_ms: u64,
    ) -> Result<(), LockedError> {
        let st = LockedState {
            locked: true,
            since_ms: now_ms,
            reason: reason.to_string(),
            job_id: job_id.map(str::to_string),
        };
        std::fs::write(&self.path, serde_json::to_vec_pretty(&st)?)?;
        Ok(())
    }

    pub fn clear(&self) -> Result<(), LockedError> {
        std::fs::write(
            &self.path,
            serde_json::to_vec_pretty(&LockedState::default())?,
        )?;
        Ok(())
    }
}
