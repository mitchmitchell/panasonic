use rand::RngCore;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::plan::{DiffHash, PlanId};
use crate::profile::Profile;
use crate::token_id::TokenId;

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

/// Opaque challenge returned with `approval_required`; approver echoes it in `submit_approval`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalChallenge(pub String);

impl ApprovalChallenge {
    pub fn fresh() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }
}

/// Per-plan approval recorded by the daemon after MCP `submit_approval` (F1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub id: ApprovalId,
    pub plan_id: PlanId,
    pub diff_hash: DiffHash,
    pub profile: Profile,
    pub approver_token_id: TokenId,
    pub expires_at: OffsetDateTime,
    pub single_use: bool,
}

impl Approval {
    pub fn new(
        plan_id: PlanId,
        diff_hash: DiffHash,
        profile: Profile,
        approver_token_id: TokenId,
    ) -> Self {
        Self {
            id: ApprovalId::new(),
            plan_id,
            diff_hash,
            profile,
            approver_token_id,
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

pub const APPROVAL_SUBMIT_LIMIT_PER_HOUR: u32 = 5;
pub const APPROVAL_SUBMIT_LIMIT_PER_DAY: u32 = 20;
