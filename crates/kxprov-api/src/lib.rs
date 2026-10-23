//! Shared daemon API types and the backend trait (`kxprovd` implements in A3).

mod approval;
mod backend;
mod error;
mod identity;
mod mock;
mod mode;
mod plan;
mod profile;
mod route_table;
mod scope;
mod token_id;
mod types;
mod write_gates;

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
pub use route_table::{
    http_route_mutates_mode_or_profile, mcp_tool_mutates_mode_or_profile, HttpRoute,
    FORBIDDEN_MODE_PROFILE_PATHS, MCP_TOOLS, WEB_ROUTES,
};
pub use scope::{scopes_for_role, Scope, ScopeSet};
pub use token_id::TokenId;
pub use types::{
    ApplyApprovalRequiredResult, ApplyJob, ApplyPlanAwaitingStatus, BackupInfo, BackupList,
    DaemonStatus, FieldValue, JobId, JobRef, JobState, PlanChangeRequest, PlanSummary,
    ReadFieldsRequest, ReadFieldsResponse, RequestedBy, SubmitApprovalParams,
};
pub use write_gates::prod_profile_write_gates_active;
