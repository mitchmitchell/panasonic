//! Write-ahead journal for crash recovery (replay before any job on startup).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("orphan temp backup")]
    OrphanTemp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JournalEntry {
    BackupStart {
        job_id: String,
        temp_path: String,
    },
    BackupCommit {
        job_id: String,
        backup_id: String,
    },
    ApplyStart {
        job_id: String,
        plan_id: String,
        diff_hash: String,
        backup_id: String,
    },
    ApplyAbort {
        job_id: String,
    },
}

pub struct Journal {
    path: PathBuf,
}

impl Journal {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("journal.jsonl"),
        }
    }

    pub fn append(&self, entry: &JournalEntry) -> Result<(), JournalError> {
        let line = serde_json::to_string(entry)?;
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{line}")?;
        Ok(())
    }

    pub fn load(&self) -> Result<Vec<JournalEntry>, JournalError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let data = std::fs::read_to_string(&self.path)?;
        let mut out = Vec::new();
        for line in data.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str(line) {
                Ok(e) => out.push(e),
                Err(e) => {
                    let is_last = data.lines().last() == Some(line);
                    if is_last {
                        tracing::warn!("journal: ignoring truncated final line");
                    } else {
                        return Err(e.into());
                    }
                }
            }
        }
        Ok(out)
    }

    pub fn truncate(&self) -> Result<(), JournalError> {
        if self.path.exists() {
            std::fs::write(&self.path, b"")?;
        }
        Ok(())
    }

    /// Replay incomplete operations before serving jobs.
    pub fn replay(&self, data_dir: &Path) -> Result<(), JournalError> {
        let backups_dir = data_dir.join("backups");
        let entries = self.load()?;
        let mut pending_backup: Option<(String, String)> = None;
        let mut pending_apply: Option<(String, String, String)> = None;
        for e in &entries {
            match e {
                JournalEntry::BackupStart { job_id, temp_path } => {
                    pending_backup = Some((job_id.clone(), temp_path.clone()));
                }
                JournalEntry::BackupCommit { .. } => pending_backup = None,
                JournalEntry::ApplyStart {
                    job_id,
                    plan_id,
                    diff_hash,
                    ..
                } => {
                    pending_apply = Some((job_id.clone(), plan_id.clone(), diff_hash.clone()));
                }
                JournalEntry::ApplyAbort { .. } => pending_apply = None,
            }
        }
        if let Some((_job, temp)) = pending_backup {
            let p = PathBuf::from(temp);
            if p.exists() {
                std::fs::remove_file(p)?;
            }
            self.append(&JournalEntry::ApplyAbort {
                job_id: "recovery".into(),
            })?;
        }
        if let Some((job_id, _, _)) = pending_apply {
            let locked = crate::locked::LockedStore::new(data_dir);
            let _ = locked.set_locked(
                "recovered incomplete apply after restart",
                Some(&job_id),
                crate::time::now_ms(),
            );
            self.append(&JournalEntry::ApplyAbort {
                job_id: "recovery".into(),
            })?;
        }
        let _ = backups_dir;
        self.truncate()?;
        Ok(())
    }
}
