//! Immutable, content-addressed write plans (v2.3).

use kxtd1232::plan::{ChunkWrite, WritePlan};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredWrite {
    table: u8,
    record: u16,
    word: u16,
    base: Vec<u8>,
    new: Vec<u8>,
}

impl From<&ChunkWrite> for StoredWrite {
    fn from(w: &ChunkWrite) -> Self {
        Self {
            table: w.table,
            record: w.record,
            word: w.word,
            base: w.base.clone(),
            new: w.new.clone(),
        }
    }
}
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlanError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("plan id mismatch")]
    IdMismatch,
    #[error("plan not found")]
    NotFound,
    #[error("plan already exists with different content")]
    AlreadyExists,
}

/// On-disk snapshot; bytes are fixed at creation time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanSnapshot {
    pub table: u8,
    pub record_size: usize,
    pub writes: Vec<StoredWrite>,
    pub diff: Vec<String>,
}

impl From<&WritePlan> for PlanSnapshot {
    fn from(p: &WritePlan) -> Self {
        Self {
            table: p.table,
            record_size: p.record_size,
            writes: p.writes.iter().map(StoredWrite::from).collect(),
            diff: p.diff(),
        }
    }
}

pub fn diff_hash(diff: &[String]) -> String {
    let mut h = Sha256::new();
    for line in diff {
        h.update(line.as_bytes());
        h.update([0u8]);
    }
    hex::encode(h.finalize())
}

pub fn plan_id(snapshot: &PlanSnapshot) -> String {
    let canonical = serde_json::to_vec(snapshot).expect("plan snapshot serializes");
    hex::encode(Sha256::digest(canonical))
}

pub struct PlanStore {
    dir: PathBuf,
}

impl PlanStore {
    pub fn new(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Store once; refuse to overwrite with different content.
    pub fn put(&self, snapshot: &PlanSnapshot) -> Result<(String, String), PlanError> {
        let id = plan_id(snapshot);
        let dh = diff_hash(&snapshot.diff);
        let path = self.path(&id);
        if path.exists() {
            let existing = self.get(&id)?;
            if existing != *snapshot {
                return Err(PlanError::AlreadyExists);
            }
            return Ok((id, dh));
        }
        let data = serde_json::to_vec_pretty(snapshot)?;
        std::fs::write(&path, data)?;
        Ok((id, dh))
    }

    pub fn get(&self, id: &str) -> Result<PlanSnapshot, PlanError> {
        let path = self.path(id);
        if !path.exists() {
            return Err(PlanError::NotFound);
        }
        let data = std::fs::read(path)?;
        let snap: PlanSnapshot = serde_json::from_slice(&data)?;
        if plan_id(&snap) != id {
            return Err(PlanError::IdMismatch);
        }
        Ok(snap)
    }

    pub fn verify_diff_hash(&self, id: &str, expected_diff_hash: &str) -> Result<(), PlanError> {
        let snap = self.get(id)?;
        if diff_hash(&snap.diff) != expected_diff_hash {
            return Err(PlanError::IdMismatch);
        }
        Ok(())
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_address_stable() {
        let snap = PlanSnapshot {
            table: 0x24,
            record_size: 6,
            writes: vec![],
            diff: vec!["T24 +0x0000: 00 -> 01".into()],
        };
        let a = plan_id(&snap);
        let b = plan_id(&snap);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }
}
