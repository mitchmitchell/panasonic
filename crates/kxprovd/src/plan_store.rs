//! Immutable server-side plans (v2.3 §5b F7): random PlanId, canonical DiffHash, token-bound.

use kxprov_api::{diff_hash, CanonicalPlan, CanonicalWrite, PLAN_EXPIRY_SECS};
use kxprov_api::{DiffHash, PlanId, Profile, TokenId};
use kxtd1232::plan::{ChunkWrite, WritePlan};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlanError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("plan not found")]
    NotFound,
    #[error("plan expired")]
    Expired,
    #[error("plan id mismatch")]
    IdMismatch,
    #[error("diff hash mismatch")]
    DiffMismatch,
    #[error("token mismatch")]
    TokenMismatch,
    #[error("random plan id")]
    Random,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredWrite {
    pub table: u8,
    pub record: u16,
    pub word: u16,
    pub base: Vec<u8>,
    pub new: Vec<u8>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanRecord {
    pub id: PlanId,
    pub diff_hash: DiffHash,
    pub profile: Profile,
    pub creator_token: TokenId,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub table: u8,
    pub record_size: usize,
    pub writes: Vec<StoredWrite>,
    pub diff: Vec<String>,
}

pub struct PlanStore {
    dir: PathBuf,
}

impl PlanStore {
    pub fn new(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self, id: &PlanId) -> PathBuf {
        self.dir.join(format!("{}.json", id.as_str()))
    }

    pub fn put(
        &self,
        profile: Profile,
        creator: &TokenId,
        snap: &PlanSnapshot,
        now_ms: u64,
    ) -> Result<PlanRecord, PlanError> {
        let id = PlanId::new_random().map_err(|_| PlanError::Random)?;
        let dh = compute_diff_hash(profile, snap);
        let rec = PlanRecord {
            id: id.clone(),
            diff_hash: dh,
            profile,
            creator_token: creator.clone(),
            created_at_ms: now_ms,
            expires_at_ms: now_ms + u64::from(PLAN_EXPIRY_SECS) * 1000,
            table: snap.table,
            record_size: snap.record_size,
            writes: snap.writes.clone(),
            diff: snap.diff.clone(),
        };
        let data = serde_json::to_vec_pretty(&rec)?;
        std::fs::write(self.path(&id), data)?;
        Ok(rec)
    }

    pub fn get(&self, id: &PlanId) -> Result<PlanRecord, PlanError> {
        let path = self.path(id);
        if !path.exists() {
            return Err(PlanError::NotFound);
        }
        let rec: PlanRecord = serde_json::from_slice(&std::fs::read(path)?)?;
        if rec.id != *id {
            return Err(PlanError::IdMismatch);
        }
        Ok(rec)
    }

    pub fn verify_for_apply(
        &self,
        id: &PlanId,
        expected: &DiffHash,
        profile: Profile,
        token: &TokenId,
        now_ms: u64,
    ) -> Result<PlanRecord, PlanError> {
        let rec = self.get(id)?;
        if now_ms >= rec.expires_at_ms {
            return Err(PlanError::Expired);
        }
        if rec.diff_hash != *expected {
            return Err(PlanError::DiffMismatch);
        }
        if rec.profile != profile {
            return Err(PlanError::IdMismatch);
        }
        if rec.creator_token != *token {
            return Err(PlanError::TokenMismatch);
        }
        let recomputed = compute_diff_hash(profile, &PlanSnapshot::from_record(&rec));
        if recomputed != rec.diff_hash {
            return Err(PlanError::DiffMismatch);
        }
        Ok(rec)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

impl PlanSnapshot {
    fn from_record(rec: &PlanRecord) -> Self {
        Self {
            table: rec.table,
            record_size: rec.record_size,
            writes: rec.writes.clone(),
            diff: rec.diff.clone(),
        }
    }
}

/// Recompute DiffHash using live table bytes as write bases (v2.6 F1 apply gate).
pub fn diff_hash_with_live_table(
    profile: Profile,
    rec: &PlanRecord,
    table_image: &[u8],
) -> Result<DiffHash, PlanError> {
    let writes: Vec<CanonicalWrite<'_>> = rec
        .writes
        .iter()
        .map(|w| {
            let start = w.record as usize * rec.record_size + 2 * w.word as usize;
            let end = start + w.new.len();
            if end > table_image.len() {
                return Err(PlanError::DiffMismatch);
            }
            Ok(CanonicalWrite {
                table: w.table,
                record: w.record,
                word: w.word,
                base: &table_image[start..end],
                new: &w.new,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(diff_hash(&CanonicalPlan {
        profile,
        table: rec.table,
        record_size: rec.record_size,
        writes,
    }))
}

pub fn compute_diff_hash(profile: Profile, snap: &PlanSnapshot) -> DiffHash {
    let writes: Vec<CanonicalWrite<'_>> = snap
        .writes
        .iter()
        .map(|w| CanonicalWrite {
            table: w.table,
            record: w.record,
            word: w.word,
            base: &w.base,
            new: &w.new,
        })
        .collect();
    diff_hash(&CanonicalPlan {
        profile,
        table: snap.table,
        record_size: snap.record_size,
        writes,
    })
}
