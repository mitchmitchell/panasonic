//! Shared daemon API types and the backend trait (`kxprovd` implements in A3).

mod approval;
mod backend;
mod error;
mod identity;
mod mock;
mod mode;
mod plan;
mod profile;
mod scope;
mod token_id;
mod types;

pub use approval::{
    approval_ttl, plan_storage_ttl, Approval, ApprovalId, APPROVAL_SUBMIT_LIMIT_PER_DAY,
    APPROVAL_SUBMIT_LIMIT_PER_HOUR,
};
pub use backend::DaemonBackend;
pub use error::ApiError;
pub use identity::{CallerIdentity, McpTokenIdentity, WebAdminIdentity};
pub use mock::MockDaemon;
pub use mode::Mode;
pub use plan::{canonical_plan_bytes, DiffHash, ImmutablePlan, PlanId};
pub use profile::Profile;
pub use scope::{scopes_for_role, Scope, ScopeSet};
pub use token_id::TokenId;
pub use types::{
    ApplyJob, BackupInfo, BackupList, DaemonStatus, FieldValue, JobId, JobState, PlanChangeRequest,
    PlanSummary, ReadFieldsRequest, ReadFieldsResponse, RequestedBy,
};
