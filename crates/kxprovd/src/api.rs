use crate::arm;
use crate::backup::BackupStore;
use crate::gates::GateState;
use crate::peer::{peer_cred, PeerError, PeerPolicy};
use crate::plan_store::PlanStore;
use crate::queue::{JobKind, JobOutcome, JobQueue};
use crate::worker::backup_info;
use kxprov_api::{
    ApiErrorBody, ApplyPlanParams, ArmPlanParams, ArmPlanResult, ArmStatus, DaemonMode, Profile,
    RequestBody, RequestEnvelope, Response, ResponseResult, Scope, StatusResponse,
};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::RwLock;

pub struct ApiState {
    pub profile: Profile,
    pub mode: DaemonMode,
    pub transport_label: String,
    pub gates: Arc<RwLock<GateState>>,
    pub peer_policy: PeerPolicy,
    pub queue: Arc<JobQueue>,
    pub backups: BackupStore,
    pub plans: PlanStore,
    pub goliath: crate::goliath::GoliathQueue,
}

pub async fn serve(listener: UnixListener, state: Arc<ApiState>) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, st).await {
                tracing::debug!("connection closed: {e}");
            }
        });
    }
}

async fn handle_conn(
    stream: tokio::net::UnixStream,
    state: Arc<ApiState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cred = peer_cred(&stream).map_err(|e| e.to_string())?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        let env: RequestEnvelope = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(e) => {
                let resp = Response {
                    id: "0".into(),
                    ok: false,
                    result: None,
                    error: Some(api_err("bad_request", &e.to_string())),
                };
                write_response(&mut write_half, &resp).await?;
                continue;
            }
        };
        let resp = dispatch(&state, cred, &env).await;
        write_response(&mut write_half, &resp).await?;
    }
    Ok(())
}

async fn write_response(
    w: &mut tokio::net::unix::OwnedWriteHalf,
    resp: &Response,
) -> std::io::Result<()> {
    let line = serde_json::to_string(resp)?;
    w.write_all(line.as_bytes()).await?;
    w.write_all(b"\n").await?;
    w.flush().await
}

fn api_err(code: &str, message: &str) -> ApiErrorBody {
    ApiErrorBody {
        code: code.into(),
        message: message.into(),
    }
}

fn peer_denied(e: PeerError) -> ApiErrorBody {
    api_err("forbidden", &e.to_string())
}

async fn dispatch(
    state: &ApiState,
    cred: crate::peer::PeerCred,
    env: &RequestEnvelope,
) -> Response {
    let id = env.id.clone();
    let result = match &env.body {
        RequestBody::Status => Ok(ResponseResult::Status(status_snapshot(state).await)),
        RequestBody::ReadFields { params } => {
            if let Err(e) = state.peer_policy.require(cred, Scope::Read) {
                return err_response(id, peer_denied(e));
            }
            run_job(
                state,
                cred,
                Scope::Read,
                JobKind::ReadFields {
                    params: params.clone(),
                },
            )
            .await
        }
        RequestBody::PlanChange { params } => {
            if let Err(e) = state.peer_policy.require(cred, Scope::Plan) {
                return err_response(id, peer_denied(e));
            }
            run_job(
                state,
                cred,
                Scope::Plan,
                JobKind::PlanChange {
                    params: params.clone(),
                },
            )
            .await
        }
        RequestBody::ArmPlan { params } => {
            if let Err(e) = state.peer_policy.require(cred, Scope::Arm) {
                return err_response(id, peer_denied(e));
            }
            arm_plan(state, params.clone()).await
        }
        RequestBody::BackupNow => {
            if let Err(e) = state.peer_policy.require(cred, Scope::Read) {
                return err_response(id, peer_denied(e));
            }
            run_job(state, cred, Scope::Read, JobKind::BackupNow).await
        }
        RequestBody::ListBackups => {
            if let Err(e) = state.peer_policy.require(cred, Scope::Read) {
                return err_response(id, peer_denied(e));
            }
            list_backups(state).await
        }
        RequestBody::ApplyPlan { params } => {
            if let Err(e) = state.peer_policy.require(cred, Scope::Write) {
                return err_response(id, peer_denied(e));
            }
            apply_plan(state, params).await
        }
    };
    match result {
        Ok(r) => Response {
            id,
            ok: true,
            result: Some(r),
            error: None,
        },
        Err(e) => err_response(id, e),
    }
}

fn err_response(id: String, e: ApiErrorBody) -> Response {
    Response {
        id,
        ok: false,
        result: None,
        error: Some(e),
    }
}

async fn status_snapshot(state: &ApiState) -> StatusResponse {
    let gates = state.gates.read().await;
    let arm = gates
        .arm
        .as_ref()
        .filter(|a| a.active())
        .map(|a| ArmStatus {
            plan_id: a.plan_id.clone(),
            diff_hash: a.diff_hash.clone(),
            expires_at_ms: a.expires_at_ms,
        });
    StatusResponse {
        profile: state.profile,
        mode: state.mode,
        transport: state.transport_label.clone(),
        gates: kxprov_api::GateFlags {
            live_writes_approved: gates.config.live_writes_approved,
            armed: gates.armed(),
            locked: gates.locked,
        },
        arm,
        queue_depth: state.queue.depth().await,
        active_job: state.queue.active().await,
    }
}

async fn list_backups(state: &ApiState) -> Result<ResponseResult, ApiErrorBody> {
    let list = state
        .backups
        .list()
        .map_err(|e| api_err("io", &e.to_string()))?;
    let backups = list
        .into_iter()
        .map(|m| backup_info(&m, &state.goliath))
        .collect();
    Ok(ResponseResult::ListBackups(kxprov_api::ListBackupsResult {
        backups,
    }))
}

async fn arm_plan(state: &ApiState, params: ArmPlanParams) -> Result<ResponseResult, ApiErrorBody> {
    state
        .plans
        .verify_diff_hash(&params.plan_id, &params.diff_hash)
        .map_err(|e| api_err("plan", &e.to_string()))?;
    let grant = arm::ArmGrant::new(
        params.plan_id,
        params.diff_hash,
        params.ttl_secs,
        state.gates.read().await.config.max_arm_ttl_secs,
    );
    let arm = ArmStatus {
        plan_id: grant.plan_id.clone(),
        diff_hash: grant.diff_hash.clone(),
        expires_at_ms: grant.expires_at_ms,
    };
    state.gates.write().await.arm = Some(grant);
    Ok(ResponseResult::ArmPlan(ArmPlanResult { arm }))
}

async fn apply_plan(
    state: &ApiState,
    params: &ApplyPlanParams,
) -> Result<ResponseResult, ApiErrorBody> {
    if !params.confirm {
        return Err(api_err("confirm", "confirm must be true"));
    }
    state
        .plans
        .verify_diff_hash(&params.plan_id, &params.diff_hash)
        .map_err(|e| api_err("plan", &e.to_string()))?;
    let mut gates = state.gates.write().await;
    if gates.locked {
        return Err(api_err("locked", "daemon is LOCKED"));
    }
    if !gates.config.live_writes_approved {
        return Err(api_err("gate", "live_writes_approved is false"));
    }
    if !gates.take_arm_for_apply(&params.plan_id, &params.diff_hash) {
        return Err(api_err("arm", "no matching single-use arm for this plan"));
    }
    drop(gates);
    Ok(ResponseResult::ApplyDeferred(
        kxprov_api::ApplyDeferredResult {
            message: "apply execution is milestone A5; authorization checks passed".into(),
        },
    ))
}

async fn run_job(
    state: &ApiState,
    _cred: crate::peer::PeerCred,
    need: Scope,
    kind: JobKind,
) -> Result<ResponseResult, ApiErrorBody> {
    let (_job_id, rx) = state
        .queue
        .enqueue(need, kind)
        .await
        .map_err(|_| api_err("queue", "daemon shutting down"))?;
    let outcome = rx.await.map_err(|_| api_err("queue", "job dropped"))?;
    map_outcome(outcome)
}

fn map_outcome(outcome: JobOutcome) -> Result<ResponseResult, ApiErrorBody> {
    match outcome {
        JobOutcome::ReadFields(r) => Ok(ResponseResult::ReadFields(r)),
        JobOutcome::PlanChange(r) => Ok(ResponseResult::PlanChange(r)),
        JobOutcome::ArmPlan(r) => Ok(ResponseResult::ArmPlan(r)),
        JobOutcome::BackupNow(r) => Ok(ResponseResult::BackupNow(r)),
        JobOutcome::ApplyDeferred(r) => Ok(ResponseResult::ApplyDeferred(r)),
        JobOutcome::Err { code, message } => Err(api_err(&code, &message)),
    }
}
