use serde::{Deserialize, Serialize};

use crate::mode::Mode;
use crate::plan::{DiffHash, PlanId};
use crate::profile::Profile;
use crate::token_id::TokenId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub profile: String,
    pub simulator: bool,
    pub mode: Mode,
    pub locked: bool,
    pub live_writes_approved: bool,
    pub queue_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupInfo {
    pub id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupList {
    pub backups: Vec<BackupInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadFieldsRequest {
    pub table: u8,
    pub record: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldValue {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadFieldsResponse {
    pub fields: Vec<FieldValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanChangeRequest {
    pub table: u8,
    pub record: u16,
    pub field: String,
    pub new_value: String,
    #[serde(default)]
    pub base_bytes: Vec<u8>,
    #[serde(default)]
    pub new_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanSummary {
    pub plan_id: PlanId,
    pub diff_hash: DiffHash,
    pub summary: String,
    pub expires_at: String,
    pub requested_by: Option<RequestedBy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestedBy {
    pub agent: String,
    pub token_id: TokenId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyJob {
    pub job_id: JobId,
    pub state: JobState,
    pub message: String,
}

/// MCP / API success body for `apply_plan` (v2.11, matches A3 `JobRef`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRef {
    pub job_id: String,
}

/// Returned when apply is blocked pending approval (v2.11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyApprovalRequiredResult {
    pub plan_id: PlanId,
    pub diff_hash: DiffHash,
    pub status: ApplyPlanAwaitingStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyPlanAwaitingStatus {
    ApprovalRequired,
}

/// MCP `submit_approval` request (v2.11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitApprovalParams {
    /// Full 32-hex plan id or exactly 8-hex prefix (v2.11).
    pub plan_id: String,
    pub diff_hash: DiffHash,
    pub profile: Profile,
}
