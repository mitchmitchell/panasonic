//! Simulator test pass marker per build hash (v2.7 F1).

use kxprov_api::{production_layout, sim_passed_path};
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
    #[error("sim-passed.json must be a root-owned regular file mode 0600")]
    InsecureMarker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimMarkFile {
    pub build_hash: String,
    pub marked_at_ms: u64,
}

pub struct SimMarkStore {
    path: PathBuf,
    require_root_owner: bool,
}

impl SimMarkStore {
    pub fn new(state_base: &Path) -> Self {
        Self {
            path: sim_passed_path(state_base),
            require_root_owner: production_layout(state_base),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn current_build_hash() -> &'static str {
        BUILD_HASH
    }

    #[cfg(unix)]
    fn validate_marker_metadata(&self, path: &Path) -> Result<(), SimMarkError> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.is_file() {
            return Err(SimMarkError::InsecureMarker);
        }
        if self.require_root_owner && meta.uid() != 0 {
            return Err(SimMarkError::InsecureMarker);
        }
        if meta.mode() & 0o777 != 0o600 {
            return Err(SimMarkError::InsecureMarker);
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn validate_marker_metadata(&self, _path: &Path) -> Result<(), SimMarkError> {
        Ok(())
    }

    /// Load marker if present, secure on disk, and still valid for this build.
    pub fn load_valid(&self) -> Result<Option<SimMarkFile>, SimMarkError> {
        if !self.path.exists() {
            return Ok(None);
        }
        match self.validate_marker_metadata(&self.path) {
            Ok(()) => {}
            Err(SimMarkError::InsecureMarker) => return Ok(None),
            Err(e) => return Err(e),
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
        if self.validate_marker_metadata(&self.path).is_err() {
            let _ = std::fs::remove_file(&self.path);
            return Ok(());
        }
        let mark: SimMarkFile = serde_json::from_slice(&std::fs::read(&self.path)?)?;
        if mark.build_hash != BUILD_HASH {
            let _ = std::fs::remove_file(&self.path);
        }
        Ok(())
    }
}
