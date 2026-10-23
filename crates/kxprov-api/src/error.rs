use crate::approval::ApprovalChallenge;
use crate::plan::{DiffHash, PlanId};

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ApiError {
    #[error("forbidden: insufficient scope")]
    ForbiddenScope,
    #[error("forbidden: admin web session required")]
    ForbiddenAdmin,
    #[error("unauthorized")]
    Unauthorized,
    #[error("approval required")]
    ApprovalRequired {
        plan_id: PlanId,
        diff_hash: DiffHash,
        summary: String,
        challenge: ApprovalChallenge,
    },
    #[error("rollback approval required")]
    RollbackApprovalRequired { job_id: String },
    #[error("approval invalid or expired")]
    InvalidApproval,
    #[error("approver must differ from plan requester")]
    ApproverMustDiffer,
    #[error("approval submit rate limit exceeded")]
    ApprovalRateLimited,
    #[error("invalid scope combination")]
    InvalidScopeSet,
    #[error("plan not found")]
    PlanNotFound,
    #[error("plan or approval window expired")]
    PlanExpired,
    #[error("live writes not approved")]
    LiveWritesBlocked,
    #[error("job not found")]
    JobNotFound,
    #[error("invalid request: {0}")]
    BadRequest(&'static str),
    #[error("re-authentication failed")]
    ReauthFailed,
}
