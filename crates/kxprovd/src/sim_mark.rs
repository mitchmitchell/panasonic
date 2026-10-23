//! Simulator test pass marker per build hash (v2.7 F1).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const BUILD_HASH: &str = env!("KXPROV_BUILD_HASH");

#[derive(Debug, Error)]
pub enum SimMarkError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimMarkFile {
    pub build_hash: String,
    pub marked_at_ms: u64,
}

pub struct SimMarkStore {
    path: PathBuf,
}

impl SimMarkStore {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("sim-mark.json"),
        }
    }

    pub fn current_build_hash() -> &'static str {
        BUILD_HASH
    }

    /// Load marker if present and still valid for this build.
    pub fn load_valid(&self) -> Result<Option<SimMarkFile>, SimMarkError> {
        if !self.path.exists() {
            return Ok(None);
        }
        let mark: SimMarkFile = serde_json::from_slice(&std::fs::read(&self.path)?)?;
        if mark.build_hash != BUILD_HASH {
            let _ = std::fs::remove_file(&self.path);
            return Ok(None);
        }
        Ok(Some(mark))
    }

    pub fn write(&self, marked_at_ms: u64) -> Result<SimMarkFile, SimMarkError> {
        let mark = SimMarkFile {
            build_hash: BUILD_HASH.to_string(),
            marked_at_ms,
        };
        std::fs::write(&self.path, serde_json::to_vec_pretty(&mark)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(mark)
    }

    pub fn clear_if_stale(&self) -> Result<(), SimMarkError> {
        if !self.path.exists() {
            return Ok(());
        }
        let mark: SimMarkFile = serde_json::from_slice(&std::fs::read(&self.path)?)?;
        if mark.build_hash != BUILD_HASH {
            let _ = std::fs::remove_file(&self.path);
        }
        Ok(())
    }
}
