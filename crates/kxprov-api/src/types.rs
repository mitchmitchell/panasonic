use crate::ids::{Approval, DiffHash, PlanId, TokenId};
use serde::{Deserialize, Serialize};

pub use crate::ids::Profile;

/// Daemon operating mode (design §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonMode {
    ReadOnly,
    DryRun,
    Simulator,
}

/// Operational mode from mode.json (v2.7 F1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalMode {
    Testing,
    Production,
}

/// Caller capability enforced in `kxprovd` from SO_PEERCRED + token store (v2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Read,
    Plan,
    Write,
    Approve,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateFlags {
    pub live_writes_approved: bool,
    pub locked: bool,
}

/// LOCKED alert timing (v2.4: held until 08:00 America/Chicago).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedAlertStatus {
    /// Alert suppressed until quiet hours end.
    pub held: bool,
    /// At or after 08:00 Central; notification may fire.
    pub may_fire: bool,
    /// Notification already emitted for this LOCKED episode.
    pub sent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResponse {
    pub profile: Profile,
    pub mode: DaemonMode,
    pub operational_mode: OperationalMode,
    pub transport: String,
    pub gates: GateFlags,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_alert: Option<LockedAlertStatus>,
    pub queue_depth: u32,
    pub active_job: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKindWire {
    CidName,
    CidNumber,
    ExtName,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadFieldsParams {
    pub kind: FieldKindWire,
    pub first: u16,
    pub count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldRow {
    pub index: u32,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadFieldsResult {
    pub rows: Vec<FieldRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanChangeParams {
    pub kind: FieldKindWire,
    pub index: u16,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanChangeResult {
    pub plan_id: PlanId,
    pub diff_hash: DiffHash,
    pub table: u8,
    pub writes: u32,
    pub diff: Vec<String>,
    pub expires_at_ms: u64,
}

/// Gateway forwards the MCP token id; daemon validates against its token store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestAuth {
    pub token_id: TokenId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitApprovalParams {
    /// Full 32-hex plan id or exactly 8-hex prefix (v2.11).
    pub plan_id: String,
    pub diff_hash: DiffHash,
    pub profile: Profile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitApprovalResult {
    pub approval: Approval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetModeParams {
    pub mode: OperationalMode,
    pub profile: Profile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetModeResult {
    pub mode: OperationalMode,
    pub profile: Profile,
    pub counter: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupInfo {
    pub id: String,
    pub created_at_ms: u64,
    pub bytes: u64,
    pub sha256: String,
    pub goliath: GoliathCopyStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoliathCopyStatus {
    Pending,
    Ok,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListBackupsResult {
    pub backups: Vec<BackupInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupNowResult {
    pub backup: BackupInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyPlanParams {
    pub plan_id: PlanId,
    pub diff_hash: DiffHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockParams {
    pub job_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockResult {
    pub unlocked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum RequestBody {
    Status,
    ReadFields { params: ReadFieldsParams },
    PlanChange { params: PlanChangeParams },
    SubmitApproval { params: SubmitApprovalParams },
    SetMode { params: SetModeParams },
    BackupNow,
    ListBackups,
    ApplyPlan { params: ApplyPlanParams },
    Unlock { params: UnlockParams },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<RequestAuth>,
    #[serde(flatten)]
    pub body: RequestBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseResult {
    Status(StatusResponse),
    ReadFields(ReadFieldsResult),
    PlanChange(PlanChangeResult),
    SubmitApproval(SubmitApprovalResult),
    SetMode(SetModeResult),
    ListBackups(ListBackupsResult),
    BackupNow(BackupNowResult),
    Job(JobRef),
    ApplyApprovalRequired(ApplyApprovalRequiredResult),
    Unlock(UnlockResult),
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ResponseResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiErrorBody>,
}

impl Response {
    pub fn into_result(self) -> Result<ResponseResult, ApiErrorBody> {
        if self.ok {
            self.result.ok_or(ApiErrorBody {
                code: "internal".into(),
                message: "missing result".into(),
            })
        } else {
            Err(self.error.unwrap_or(ApiErrorBody {
                code: "unknown".into(),
                message: "request failed".into(),
            }))
        }
    }
}
