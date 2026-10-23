use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::plan::{DiffHash, PlanId};
use crate::profile::Profile;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApprovalId(pub String);

impl Default for ApprovalId {
    fn default() -> Self {
        Self::new()
    }
}

impl ApprovalId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

/// Per-plan approval minted only by the daemon (F1/F2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub id: ApprovalId,
    pub plan_id: PlanId,
    pub diff_hash: DiffHash,
    pub profile: Profile,
    pub expires_at: OffsetDateTime,
    pub single_use: bool,
}

impl Approval {
    pub fn new(plan_id: PlanId, diff_hash: DiffHash, profile: Profile) -> Self {
        Self {
            id: ApprovalId::new(),
            plan_id,
            diff_hash,
            profile,
            expires_at: OffsetDateTime::now_utc() + approval_ttl(),
            single_use: true,
        }
    }
}

pub fn approval_ttl() -> Duration {
    Duration::minutes(10)
}

pub fn plan_storage_ttl() -> Duration {
    Duration::minutes(30)
}

pub fn default_approval_url(plan_id: &PlanId, diff_hash: &DiffHash) -> String {
    format!(
        "/plans/{}/approve?diff={}",
        plan_id.to_hex(),
        diff_hash.to_hex()
    )
}
