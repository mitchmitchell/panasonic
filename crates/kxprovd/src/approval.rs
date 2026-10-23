//! Per-plan approvals (v2.3 §5b F1): minted only by the daemon, single-use, TTL 10 min.

use kxprov_api::APPROVAL_TTL_SECS;
use kxprov_api::{Approval, DiffHash, PlanId, Profile};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApprovalError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("not found")]
    NotFound,
    #[error("already consumed")]
    Consumed,
    #[error("expired")]
    Expired,
    #[error("profile mismatch")]
    ProfileMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ApprovalStore {
    items: Vec<Approval>,
}

pub struct ApprovalBook {
    path: PathBuf,
}

impl ApprovalBook {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("approvals.json"),
        }
    }

    fn load(&self) -> Result<ApprovalStore, ApprovalError> {
        if !self.path.exists() {
            return Ok(ApprovalStore::default());
        }
        let data = std::fs::read(&self.path)?;
        Ok(serde_json::from_slice(&data)?)
    }

    fn save(&self, store: &ApprovalStore) -> Result<(), ApprovalError> {
        std::fs::write(&self.path, serde_json::to_vec_pretty(store)?)?;
        Ok(())
    }

    pub fn mint(
        &self,
        plan_id: PlanId,
        diff_hash: DiffHash,
        profile: Profile,
        now_ms: u64,
    ) -> Result<Approval, ApprovalError> {
        let mut store = self.load()?;
        let approval = Approval {
            plan_id,
            diff_hash,
            profile,
            expires_at_ms: now_ms + u64::from(APPROVAL_TTL_SECS) * 1000,
            consumed: false,
        };
        store.items.push(approval.clone());
        self.save(&store)?;
        Ok(approval)
    }

    pub fn consume(
        &self,
        plan_id: &PlanId,
        diff_hash: &DiffHash,
        profile: Profile,
        now_ms: u64,
    ) -> Result<(), ApprovalError> {
        let mut store = self.load()?;
        let idx = store
            .items
            .iter()
            .position(|a| a.matches(plan_id, diff_hash, profile))
            .ok_or(ApprovalError::NotFound)?;
        let a = &mut store.items[idx];
        if a.consumed {
            return Err(ApprovalError::Consumed);
        }
        if !a.active(now_ms, profile) {
            return Err(ApprovalError::Expired);
        }
        a.consumed = true;
        self.save(&store)?;
        Ok(())
    }

    pub fn has_active(
        &self,
        plan_id: &PlanId,
        diff_hash: &DiffHash,
        profile: Profile,
        now_ms: u64,
    ) -> bool {
        self.load().ok().is_some_and(|s| {
            s.items
                .iter()
                .any(|a| a.matches(plan_id, diff_hash, profile) && a.active(now_ms, profile))
        })
    }
}
