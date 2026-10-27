use std::path::{Path, PathBuf};
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
    socket_path: PathBuf,
    client: Mutex<ApiClient>,
    gateway_bearer: String,
}

impl DaemonClient {
    pub async fn connect(
        path: impl AsRef<Path>,
        gateway_bearer: String,
    ) -> Result<Arc<Self>, ApiError> {
        let socket_path = path.as_ref().to_path_buf();
        let client = ApiClient::connect(&socket_path).await?;
        Ok(Arc::new(Self {
            socket_path,
            client: Mutex::new(client),
            gateway_bearer,
        }))
    }

    async fn call(
        &self,
        caller: &CallerIdentity,
        body: RequestBody,
    ) -> Result<ResponseResult, BackendError> {
        let (auth, audit) = daemon_auth(caller, &self.gateway_bearer);
        let mut guard = self.client.lock().await;
        match guard
            .call_auth_audit(body.clone(), Some(auth.clone()), audit.clone())
            .await
        {
            Ok(r) => Ok(r),
            Err(e @ ApiError::Io(_)) => {
                drop(guard);
                if body.is_mutating() {
                    if let Ok(fresh) = ApiClient::connect(&self.socket_path).await {
                        let mut guard = self.client.lock().await;
                        *guard = fresh;
                    }
                    return Err(map_api_error(e));
                }
                let fresh = ApiClient::connect(&self.socket_path)
                    .await
                    .map_err(map_api_error)?;
                let mut guard = self.client.lock().await;
                *guard = fresh;
                guard
                    .call_auth_audit(body, Some(auth), audit)
                    .await
                    .map_err(map_api_error)
            }
            Err(e) => Err(map_api_error(e)),
        }
    }
}

fn daemon_auth(caller: &CallerIdentity, gateway_bearer: &str) -> (RequestAuth, Option<String>) {
    match caller {
        CallerIdentity::Web(w) => (
            RequestAuth {
                bearer: gateway_bearer.to_string(),
            },
            Some(format!("web-session:{}", w.session_key)),
        ),
        CallerIdentity::Mcp(t) => (
            RequestAuth {
                bearer: t.bearer.clone(),
            },
            Some(format!("mcp:{}:{}", t.token_id.0, t.agent_name)),
        ),
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
        "gate" if lower.contains("live_write") => BackendError::LiveWritesBlocked,
        "locked" => BackendError::ForbiddenScope,
        "transition_blocked" => BackendError::ForbiddenScope,
        _ if lower.contains("live write") || lower.contains("live_write") => {
            BackendError::LiveWritesBlocked
        }
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
        _caller: &CallerIdentity,
        _job_id: JobId,
    ) -> Result<ApplyJob, BackendError> {
        // kxprovd has no job-scoped rollback RPC yet; Unlock only clears the global lock
        // and ignores job_id — do not map MCP rollback to it.
        Err(BackendError::BadRequest("rollback not supported by daemon"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kxprov_api::{ApplyPlanParams, DiffHash, PlanId, Profile};
    use kxprov_mock::BackendError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn mutating_requests_are_classified() {
        assert!(!RequestBody::Status.is_mutating());
        assert!(!RequestBody::ListBackups.is_mutating());
        assert!(!RequestBody::Whoami.is_mutating());
        assert!(RequestBody::BackupNow.is_mutating());
        assert!(RequestBody::PlanChange {
            params: kxprov_api::PlanChangeParams {
                kind: FieldKindWire::CidName,
                index: 0,
                value: "x".into(),
            },
        }
        .is_mutating());
        assert!(RequestBody::ApplyPlan {
            params: ApplyPlanParams {
                plan_id: PlanId("p".into()),
                diff_hash: DiffHash("h".into()),
            },
        }
        .is_mutating());
        assert!(RequestBody::SubmitApproval {
            params: kxprov_api::SubmitApprovalParams {
                plan_id: "p".into(),
                diff_hash: DiffHash("h".into()),
                profile: Profile::Sim,
            },
        }
        .is_mutating());
        assert!(RequestBody::Unlock {
            params: kxprov_api::UnlockParams {
                job_id: "j".into(),
                reason: "x".into(),
            },
        }
        .is_mutating());
    }

    #[tokio::test]
    async fn rollback_fail_closed_without_daemon_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("kxprovd.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let lines = Arc::new(AtomicUsize::new(0));
        let lines_in = Arc::clone(&lines);
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            loop {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut reader = tokio::io::BufReader::new(&mut stream);
                let mut line = String::new();
                if reader.read_line(&mut line).await.is_ok() && !line.is_empty() {
                    lines_in.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        let client = DaemonClient::connect(&sock, "gw-bearer".into())
            .await
            .expect("connect");
        let caller = kxprov_mock::CallerIdentity::Mcp(kxprov_mock::McpTokenIdentity {
            token_id: kxprov_api::TokenId("t".into()),
            agent_name: "test".into(),
            scopes: kxprov_mock::ScopeSet::empty(),
            bearer: "b".into(),
        });
        let before = lines.load(Ordering::SeqCst);
        let err = client
            .rollback(&caller, JobId("job-1".into()))
            .await
            .expect_err("rollback must not call daemon");
        assert_eq!(
            err,
            BackendError::BadRequest("rollback not supported by daemon")
        );
        assert_eq!(
            lines.load(Ordering::SeqCst),
            before,
            "rollback must not send a daemon RPC line"
        );
    }

    #[tokio::test]
    async fn apply_plan_io_sends_exactly_one_request_and_reconnects() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        use kxprov_api::{
            DaemonMode, DiffHash, GateFlags, OperationalMode, PlanId, Profile, Scope,
        };
        use kxprov_mock::{McpTokenIdentity, ScopeSet};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("kxprovd.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let reqs = Arc::clone(&requests);
        tokio::spawn(async move {
            while reqs.load(Ordering::SeqCst) < 2 {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let n = reqs.fetch_add(1, Ordering::SeqCst);
                let mut line = String::new();
                let mut reader = tokio::io::BufReader::new(&mut stream);
                let _ = reader.read_line(&mut line).await;
                if n == 0 {
                    drop(stream);
                    continue;
                }
                let id = serde_json::from_str::<serde_json::Value>(&line)
                    .ok()
                    .and_then(|v| v.get("id").and_then(|id| id.as_str().map(String::from)))
                    .unwrap_or_else(|| "1".into());
                let resp = kxprov_api::Response {
                    id,
                    ok: true,
                    result: Some(kxprov_api::ResponseResult::Status(
                        kxprov_api::StatusResponse {
                            profile: Profile::Sim,
                            mode: DaemonMode::ReadOnly,
                            operational_mode: OperationalMode::Testing,
                            transport: "test".into(),
                            gates: GateFlags {
                                locked: false,
                                live_writes_approved: false,
                            },
                            locked_alert: None,
                            queue_depth: 0,
                            active_job: None,
                        },
                    )),
                    error: None,
                };
                let out = serde_json::to_string(&resp).unwrap() + "\n";
                let _ = stream.write_all(out.as_bytes()).await;
            }
        });

        let client = DaemonClient::connect(&sock, "gw-bearer".into())
            .await
            .expect("connect");
        let caller = CallerIdentity::Mcp(McpTokenIdentity {
            token_id: kxprov_api::TokenId("t".into()),
            agent_name: "test".into(),
            scopes: ScopeSet::empty().with(Scope::Write),
            bearer: "b".into(),
        });
        let apply_err = client
            .apply_plan(&caller, PlanId("plan".into()), DiffHash("hash".into()))
            .await;
        assert!(apply_err.is_err(), "expected I/O error after dropped read");
        assert_eq!(requests.load(Ordering::SeqCst), 1, "single mutating send");

        client
            .status(&caller)
            .await
            .expect("status after reconnect");
        assert_eq!(
            requests.load(Ordering::SeqCst),
            2,
            "read-only call uses fresh connection"
        );
    }
}
