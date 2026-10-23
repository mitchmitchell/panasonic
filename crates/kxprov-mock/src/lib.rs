//! In-memory daemon backend for gateway integration tests and local preview.

mod backend;
mod error;
mod identity;
mod mock;
mod plan;
mod route_table;
mod scope;
mod types;
mod write_gates;

pub use backend::DaemonBackend;
pub use error::BackendError;
pub use identity::{CallerIdentity, McpTokenIdentity, WebSessionIdentity};
pub use mock::{MockDaemon, APPROVAL_SUBMIT_LIMIT_PER_DAY, APPROVAL_SUBMIT_LIMIT_PER_HOUR};
pub use plan::{canonical_diff_hash, diff_hash_from_hex, plan_id_from_hex};
pub use route_table::{
    http_route_mutates_mode_or_profile, mcp_tool_mutates_mode_or_profile, HttpRoute,
    FORBIDDEN_MODE_PROFILE_PATHS, MCP_APPROVAL_TOOLS, MCP_TOOLS, WEB_ROUTES,
};
pub use scope::{scopes_for_role, ScopeSet};
pub use types::{
    ApplyJob, BackupInfo, BackupList, DaemonStatus, FieldValue, JobId, JobState, PlanChangeRequest,
    PlanSummary, ReadFieldsRequest, ReadFieldsResponse,
};
pub use write_gates::prod_profile_write_gates_active;
