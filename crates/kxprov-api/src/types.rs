use serde::{Deserialize, Serialize};

/// Profile banner shown in status (SIM / TEST / PROD).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Sim,
    Test,
    Prod,
}

/// Daemon operating mode (design §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonMode {
    ReadOnly,
    DryRun,
    Simulator,
}

/// Caller capability enforced in `kxprovd` from SO_PEERCRED (v2.3: never trust the gateway).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Read,
    Plan,
    Write,
    /// Bind a single-use arm to one plan id + diff hash (Mitch re-auth at the gateway; daemon verifies peer).
    Arm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateFlags {
    pub live_writes_approved: bool,
    /// True when an unused, unexpired arm matches a plan (detail in `arm` when present).
    pub armed: bool,
    pub locked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmStatus {
    pub plan_id: String,
    pub diff_hash: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResponse {
    pub profile: Profile,
    pub mode: DaemonMode,
    pub transport: String,
    pub gates: GateFlags,
    /// Active single-use arm, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arm: Option<ArmStatus>,
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

/// Immutable plan reference (content-addressed id + diff hash for arming).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanChangeResult {
    pub plan_id: String,
    pub diff_hash: String,
    pub table: u8,
    pub writes: u32,
    pub diff: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmPlanParams {
    pub plan_id: String,
    pub diff_hash: String,
    /// Wall-clock expiry chosen by the approver; daemon clamps to configured max TTL.
    pub ttl_secs: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmPlanResult {
    pub arm: ArmStatus,
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
    pub plan_id: String,
    pub diff_hash: String,
    pub confirm: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum RequestBody {
    Status,
    ReadFields { params: ReadFieldsParams },
    PlanChange { params: PlanChangeParams },
    ArmPlan { params: ArmPlanParams },
    BackupNow,
    ListBackups,
    ApplyPlan { params: ApplyPlanParams },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub id: String,
    #[serde(flatten)]
    pub body: RequestBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseResult {
    Status(StatusResponse),
    ReadFields(ReadFieldsResult),
    PlanChange(PlanChangeResult),
    ArmPlan(ArmPlanResult),
    ListBackups(ListBackupsResult),
    BackupNow(BackupNowResult),
    Job(JobRef),
    ApplyDeferred(ApplyDeferredResult),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRef {
    pub job_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyDeferredResult {
    pub message: String,
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
