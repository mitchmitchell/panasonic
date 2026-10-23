//! Per-plan approvals via submit_approval (v2.6 F1).

use kxprov_api::{Approval, DiffHash, PlanId, Profile, TokenId};
use kxprov_api::{APPROVAL_SUBMIT_LIMIT_DAY, APPROVAL_SUBMIT_LIMIT_HOUR, APPROVAL_TTL_SECS};
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
    #[error("same approver as requester")]
    SameApprover,
    #[error("rate limit")]
    RateLimit,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ApprovalStore {
    items: Vec<Approval>,
    #[serde(default)]
    submit_log: Vec<SubmitRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubmitRecord {
    approver: TokenId,
    at_ms: u64,
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
        crate::atomic_write::write(&self.path, &serde_json::to_vec_pretty(store)?)?;
        Ok(())
    }

    fn check_rate_limit(
        store: &ApprovalStore,
        approver: &TokenId,
        now_ms: u64,
    ) -> Result<(), ApprovalError> {
        let hour_ago = now_ms.saturating_sub(3_600_000);
        let day_ago = now_ms.saturating_sub(86_400_000);
        let hour_count = store
            .submit_log
            .iter()
            .filter(|r| r.approver == *approver && r.at_ms >= hour_ago)
            .count();
        let day_count = store
            .submit_log
            .iter()
            .filter(|r| r.approver == *approver && r.at_ms >= day_ago)
            .count();
        if hour_count >= APPROVAL_SUBMIT_LIMIT_HOUR as usize {
            return Err(ApprovalError::RateLimit);
        }
        if day_count >= APPROVAL_SUBMIT_LIMIT_DAY as usize {
            return Err(ApprovalError::RateLimit);
        }
        Ok(())
    }

    pub fn submit(
        &self,
        plan_id: PlanId,
        diff_hash: DiffHash,
        profile: Profile,
        requester: &TokenId,
        approver: TokenId,
        now_ms: u64,
    ) -> Result<Approval, ApprovalError> {
        if requester == &approver {
            return Err(ApprovalError::SameApprover);
        }
        let mut store = self.load()?;
        Self::check_rate_limit(&store, &approver, now_ms)?;
        let approval = Approval {
            plan_id,
            diff_hash,
            profile,
            approver_token: approver.clone(),
            expires_at_ms: now_ms + u64::from(APPROVAL_TTL_SECS) * 1000,
            consumed: false,
        };
        store.items.push(approval.clone());
        store.submit_log.push(SubmitRecord {
            approver,
            at_ms: now_ms,
        });
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
            .position(|a| {
                a.matches(plan_id, diff_hash, profile)
                    && !a.consumed
                    && a.active(now_ms, profile)
            })
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use kxprov_api::{DiffHash, PlanId};

    #[test]
    fn same_approver_as_requester_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let book = ApprovalBook::new(dir.path());
        let err = book
            .submit(
                PlanId("p".into()),
                DiffHash("d".into()),
                Profile::Sim,
                &TokenId("writer".into()),
                TokenId("writer".into()),
                0,
            )
            .unwrap_err();
        assert!(matches!(err, ApprovalError::SameApprover));
    }
}
