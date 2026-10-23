//! Append-only audit log (v2.6 F1).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    ModeMissing,
    ModeCorrupt,
    ModeBadSignature,
    ModeCounterRollback,
    ModeTestingInvalidProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at_ms: u64,
    pub kind: AuditKind,
    pub detail: String,
}

pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("audit.jsonl"),
        }
    }

    pub fn append(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let line = serde_json::to_string(entry)?;
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{line}")?;
        Ok(())
    }

    pub fn load(&self) -> Result<Vec<AuditEntry>, AuditError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let data = std::fs::read_to_string(&self.path)?;
        let mut out = Vec::new();
        for line in data.lines() {
            if line.trim().is_empty() {
                continue;
            }
            out.push(serde_json::from_str(line)?);
        }
        Ok(out)
    }
}

pub fn alert_mode_failure(kind: &AuditKind, detail: &str) {
    tracing::warn!(?kind, detail, "mode.json alert (fail-closed to Production)");
}
