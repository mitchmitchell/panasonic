use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use kxprov_api::{
    ApiClient, ApiError, ApplyApprovalRequiredResult, ApplyPlanAwaitingStatus, Approval, DiffHash,
    FieldKindWire, JobRef, PlanId, Profile, RequestAuth, RequestBody, ResponseResult,
    StatusResponse,
};
use kxprov_mock::{
    ApplyJob, BackendError, BackupInfo, BackupList, CallerIdentity, DaemonBackend, DaemonStatus,
    JobId, JobState, PlanChangeRequest, PlanSummary, ReadFieldsRequest, ReadFieldsResponse,
};
use kxtd1232::FieldKind;
use time::OffsetDateTime;
use tokio::sync::Mutex;

pub struct DaemonClient {
    client: Mutex<ApiClient>,
}

impl DaemonClient {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Arc<Self>, ApiError> {
        let client = ApiClient::connect(path).await?;
        Ok(Arc::new(Self {
            client: Mutex::new(client),
        }))
    }

    async fn call(
        &self,
        caller: &CallerIdentity,
        body: RequestBody,
    ) -> Result<ResponseResult, BackendError> {
        let auth = caller
            .token_id()
            .cloned()
            .map(|token_id| RequestAuth { token_id });
        let mut guard = self.client.lock().await;
        guard.call_auth(body, auth).await.map_err(map_api_error)
    }
}

fn map_api_error(err: ApiError) -> BackendError {
    match err {
        ApiError::Remote { code, message } => map_remote_error(&code, &message),
        ApiError::Unexpected => BackendError::BadRequest("daemon"),
        ApiError::Io(_) | ApiError::Json(_) => BackendError::BadRequest("daemon"),
    }
}

fn map_remote_error(code: &str, message: &str) -> BackendError {
    let lower = message.to_ascii_lowercase();
    match code {
        "forbidden" | "scope" => BackendError::ForbiddenScope,
        "approval_required" => BackendError::ApprovalRequired(ApplyApprovalRequiredResult {
            plan_id: PlanId(String::new()),
            diff_hash: DiffHash(String::new()),
            status: ApplyPlanAwaitingStatus::ApprovalRequired,
        }),
        "not_found" if lower.contains("plan") => BackendError::PlanNotFound,
        "not_found" if lower.contains("job") => BackendError::JobNotFound,
        "expired" => BackendError::PlanExpired,
        "rate_limited" => BackendError::ApprovalRateLimited,
        _ if lower.contains("live write") => BackendError::LiveWritesBlocked,
        _ => BackendError::BadRequest("daemon"),
    }
}

fn field_kind_wire(kind: FieldKind) -> FieldKindWire {
    match kind {
        FieldKind::CidName => FieldKindWire::CidName,
        FieldKind::CidNumber => FieldKindWire::CidNumber,
        FieldKind::ExtName => FieldKindWire::ExtName,
    }
}

fn status_from_response(status: StatusResponse) -> DaemonStatus {
    DaemonStatus {
        profile: status.profile,
        operational_mode: status.operational_mode,
        locked: status.gates.locked,
        live_writes_approved: status.gates.live_writes_approved,
        queue_depth: status.queue_depth,
    }
}

fn expires_at_rfc3339(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|dt| {
            dt.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| ms.to_string())
}

fn backup_from_api(b: kxprov_api::BackupInfo) -> BackupInfo {
    BackupInfo {
        id: b.id,
        created_at: expires_at_rfc3339(b.created_at_ms),
    }
}

#[async_trait]
impl DaemonBackend for DaemonClient {
    async fn status(&self, caller: &CallerIdentity) -> Result<DaemonStatus, BackendError> {
        match self.call(caller, RequestBody::Status).await? {
            ResponseResult::Status(s) => Ok(status_from_response(s)),
            _ => Err(BackendError::BadRequest("daemon")),
        }
    }

    async fn list_backups(&self, caller: &CallerIdentity) -> Result<BackupList, BackendError> {
        match self.call(caller, RequestBody::ListBackups).await? {
            ResponseResult::ListBackups(r) => Ok(BackupList {
                backups: r.backups.into_iter().map(backup_from_api).collect(),
            }),
            _ => Err(BackendError::BadRequest("daemon")),
        }
    }

    async fn backup_now(&self, caller: &CallerIdentity) -> Result<BackupInfo, BackendError> {
        match self.call(caller, RequestBody::BackupNow).await? {
            ResponseResult::BackupNow(r) => Ok(backup_from_api(r.backup)),
            _ => Err(BackendError::BadRequest("daemon")),
        }
    }

    async fn read_fields(
        &self,
        caller: &CallerIdentity,
        req: ReadFieldsRequest,
    ) -> Result<ReadFieldsResponse, BackendError> {
        let mut fields = Vec::new();
        for kind in FieldKind::ALL
            .into_iter()
            .filter(|k| k.table() == req.table)
        {
            let wire = field_kind_wire(kind);
            let result = self
                .call(
                    caller,
                    RequestBody::ReadFields {
                        params: kxprov_api::ReadFieldsParams {
                            kind: wire,
                            first: req.record,
                            count: 1,
                        },
                    },
                )
                .await?;
            let ResponseResult::ReadFields(r) = result else {
                return Err(BackendError::BadRequest("daemon"));
            };
            for row in r.rows {
                fields.push(kxprov_mock::FieldValue {
                    name: kind.name().into(),
                    value: row.value,
                });
            }
        }
        Ok(ReadFieldsResponse { fields })
    }

    async fn plan_change(
        &self,
        caller: &CallerIdentity,
        req: PlanChangeRequest,
    ) -> Result<PlanSummary, BackendError> {
        let kind = req
            .field
            .parse::<FieldKind>()
            .map_err(|_| BackendError::BadRequest("field"))?;
        if kind.table() != req.table {
            return Err(BackendError::BadRequest("field"));
        }
        let table = req.table;
        let record = req.record;
        let field = req.field.clone();
        let new_value = req.new_value.clone();
        let result = self
            .call(
                caller,
                RequestBody::PlanChange {
                    params: kxprov_api::PlanChangeParams {
                        kind: field_kind_wire(kind),
                        index: record,
                        value: new_value.clone(),
                    },
                },
            )
            .await?;
        let ResponseResult::PlanChange(r) = result else {
            return Err(BackendError::BadRequest("daemon"));
        };
        let summary = if r.diff.is_empty() {
            format!("Plan {} (table {table}, record {record})", r.plan_id.0)
        } else {
            r.diff.join("; ")
        };
        Ok(PlanSummary {
            plan_id: r.plan_id,
            diff_hash: r.diff_hash,
            summary,
            table: r.table,
            record,
            field,
            old_value: String::new(),
            new_value,
            expires_at: expires_at_rfc3339(r.expires_at_ms),
        })
    }

    async fn submit_approval(
        &self,
        caller: &CallerIdentity,
        plan_id_or_prefix: &str,
        diff_hash: DiffHash,
        profile: Profile,
    ) -> Result<Approval, BackendError> {
        match self
            .call(
                caller,
                RequestBody::SubmitApproval {
                    params: kxprov_api::SubmitApprovalParams {
                        plan_id: plan_id_or_prefix.into(),
                        diff_hash,
                        profile,
                    },
                },
            )
            .await?
        {
            ResponseResult::SubmitApproval(r) => Ok(r.approval),
            _ => Err(BackendError::BadRequest("daemon")),
        }
    }

    async fn apply_plan(
        &self,
        caller: &CallerIdentity,
        plan_id: PlanId,
        diff_hash: DiffHash,
    ) -> Result<ApplyJob, BackendError> {
        match self
            .call(
                caller,
                RequestBody::ApplyPlan {
                    params: kxprov_api::ApplyPlanParams { plan_id, diff_hash },
                },
            )
            .await?
        {
            ResponseResult::Job(JobRef { job_id }) => Ok(ApplyJob {
                job_id: JobId(job_id),
                state: JobState::Queued,
                message: String::new(),
            }),
            ResponseResult::ApplyApprovalRequired(r) => Err(BackendError::ApprovalRequired(r)),
            _ => Err(BackendError::BadRequest("daemon")),
        }
    }

    async fn rollback(
        &self,
        caller: &CallerIdentity,
        job_id: JobId,
    ) -> Result<ApplyJob, BackendError> {
        let job_id_str = job_id.0.clone();
        match self
            .call(
                caller,
                RequestBody::Unlock {
                    params: kxprov_api::UnlockParams {
                        job_id: job_id_str,
                        reason: "rollback".into(),
                    },
                },
            )
            .await?
        {
            ResponseResult::Unlock(_) => Ok(ApplyJob {
                job_id,
                state: JobState::Succeeded,
                message: "rollback submitted".into(),
            }),
            ResponseResult::Job(JobRef { job_id }) => Ok(ApplyJob {
                job_id: JobId(job_id),
                state: JobState::Queued,
                message: String::new(),
            }),
            _ => Err(BackendError::BadRequest("daemon")),
        }
    }
}
