use crate::approval::ApprovalBook;
use crate::backup::BackupStore;
use crate::gates::GateState;
use crate::locked::LockedStore;
use crate::peer::{PeerPolicy, PeerRole};
use crate::plan_store::PlanStore;
use crate::queue::{JobKind, JobOutcome, JobQueue};
use crate::time::now_ms;
use crate::tokens::TokenStore;
use crate::worker::backup_info;
use kxprov_api::{
    ApiErrorBody, ApplyPlanParams, MintApprovalParams, MintApprovalResult, PlanChangeParams,
    Profile, RequestAuth, RequestBody, RequestEnvelope, Response, ResponseResult, Scope, TokenId,
    UnlockParams, UnlockResult,
};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::RwLock;

pub struct ApiState {
    pub profile: Profile,
    pub transport_label: String,
    pub gates: Arc<RwLock<GateState>>,
    pub peer_policy: PeerPolicy,
    pub tokens: TokenStore,
    pub queue: Arc<JobQueue>,
    pub backups: BackupStore,
    pub plans: PlanStore,
    pub approvals: ApprovalBook,
    pub locked: LockedStore,
    pub goliath: crate::goliath::GoliathQueue,
    pub approval_url_base: String,
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
    let cred = crate::peer::peer_cred(&stream).map_err(|e| e.to_string())?;
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
                    error: Some(api_err("bad_request", &e.to_string(), None)),
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

fn api_err(code: &str, message: &str, approval_url: Option<String>) -> ApiErrorBody {
    ApiErrorBody {
        code: code.into(),
        message: message.into(),
        approval_url,
    }
}

fn approval_url(base: &str, plan_id: &str) -> String {
    format!("{base}/{plan_id}/approve")
}

async fn dispatch(
    state: &ApiState,
    cred: crate::peer::PeerCred,
    env: &RequestEnvelope,
) -> Response {
    let id = env.id.clone();
    let role = state.peer_policy.role(cred);
    let locked = state.locked.load().ok().is_some_and(|s| s.locked);

    let result = match &env.body {
        RequestBody::Status => Ok(ResponseResult::Status(status_snapshot(state, locked).await)),
        RequestBody::ReadFields { params } => {
            if let Err(e) = require_access(state, role, &env.auth, Scope::Read) {
                return err_response(id, e);
            }
            run_job(
                state,
                JobKind::ReadFields {
                    params: params.clone(),
                },
            )
            .await
        }
        RequestBody::PlanChange { params } => {
            let token = match require_access(state, role, &env.auth, Scope::Plan) {
                Ok(t) => t,
                Err(e) => return err_response(id, e),
            };
            run_plan(state, params.clone(), token).await
        }
        RequestBody::MintApproval { params } => mint_approval(state, cred, params.clone()).await,
        RequestBody::BackupNow => {
            if let Err(e) = require_access(state, role, &env.auth, Scope::Read) {
                return err_response(id, e);
            }
            run_job(state, JobKind::BackupNow).await
        }
        RequestBody::ListBackups => {
            if let Err(e) = require_access(state, role, &env.auth, Scope::Read) {
                return err_response(id, e);
            }
            list_backups(state).await
        }
        RequestBody::ApplyPlan { params } => {
            if locked {
                return err_response(id, api_err("locked", "daemon is LOCKED", None));
            }
            let token = match require_access(state, role, &env.auth, Scope::Write) {
                Ok(t) => t,
                Err(e) => return err_response(id, e),
            };
            apply_plan(state, params, token).await
        }
        RequestBody::Unlock { params } => unlock(state, cred, params.clone()).await,
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

fn require_access(
    state: &ApiState,
    role: PeerRole,
    auth: &Option<RequestAuth>,
    need: Scope,
) -> Result<TokenId, ApiErrorBody> {
    match role {
        PeerRole::Admin | PeerRole::Gateway => {
            let Some(auth) = auth else {
                if role == PeerRole::Admin && need == Scope::Read {
                    return Ok(TokenId("admin".into()));
                }
                return Err(api_err("token_required", "token id required", None));
            };
            if !state.tokens.require_scope(&auth.token_id, need) {
                return Err(api_err("forbidden", "token scope denied", None));
            }
            Ok(auth.token_id.clone())
        }
        PeerRole::ReadOnly => {
            if need == Scope::Read || need == Scope::Plan {
                Ok(TokenId("local".into()))
            } else {
                Err(api_err("forbidden", "read-only peer", None))
            }
        }
    }
}

async fn status_snapshot(state: &ApiState, locked: bool) -> kxprov_api::StatusResponse {
    let gates = state.gates.read().await;
    kxprov_api::StatusResponse {
        profile: state.profile,
        mode: kxprov_api::DaemonMode::Simulator,
        transport: state.transport_label.clone(),
        gates: kxprov_api::GateFlags {
            live_writes_approved: gates.config.live_writes_approved,
            locked,
        },
        queue_depth: state.queue.depth().await,
        active_job: state.queue.active().await,
    }
}

async fn list_backups(state: &ApiState) -> Result<ResponseResult, ApiErrorBody> {
    let list = state
        .backups
        .list()
        .map_err(|e| api_err("io", &e.to_string(), None))?;
    let backups = list
        .into_iter()
        .map(|m| backup_info(&m, &state.goliath))
        .collect();
    Ok(ResponseResult::ListBackups(kxprov_api::ListBackupsResult {
        backups,
    }))
}

async fn run_plan(
    state: &ApiState,
    params: PlanChangeParams,
    token: TokenId,
) -> Result<ResponseResult, ApiErrorBody> {
    let (_job_id, rx) = state
        .queue
        .enqueue(JobKind::PlanChange {
            params,
            token_id: token,
        })
        .await
        .map_err(|_| api_err("queue", "daemon shutting down", None))?;
    map_outcome(
        rx.await
            .map_err(|_| api_err("queue", "job dropped", None))?,
    )
}

async fn mint_approval(
    state: &ApiState,
    cred: crate::peer::PeerCred,
    params: MintApprovalParams,
) -> Result<ResponseResult, ApiErrorBody> {
    if !state.peer_policy.is_admin(cred) {
        return Err(api_err(
            "forbidden",
            "admin role required to mint approval",
            None,
        ));
    }
    if params.admin_reauth_proof.is_empty() {
        return Err(api_err("reauth", "admin re-auth proof required", None));
    }
    if !state.gates.read().await.config.live_writes_approved && params.profile == Profile::Prod {
        return Err(api_err("gate", "live_writes_approved is false", None));
    }
    let rec = state
        .plans
        .get(&params.plan_id)
        .map_err(|e| api_err("plan", &e.to_string(), None))?;
    if rec.diff_hash != params.diff_hash || rec.profile != params.profile {
        return Err(api_err("plan", "plan id / diff / profile mismatch", None));
    }
    let approval = state
        .approvals
        .mint(params.plan_id, params.diff_hash, params.profile, now_ms())
        .map_err(|e| api_err("approval", &e.to_string(), None))?;
    Ok(ResponseResult::MintApproval(MintApprovalResult {
        approval,
    }))
}

async fn apply_plan(
    state: &ApiState,
    params: &ApplyPlanParams,
    token: TokenId,
) -> Result<ResponseResult, ApiErrorBody> {
    let now = now_ms();
    if !state.gates.read().await.config.live_writes_approved && state.profile == Profile::Prod {
        return Err(api_err("gate", "live_writes_approved is false", None));
    }
    state
        .plans
        .verify_for_apply(
            &params.plan_id,
            &params.diff_hash,
            state.profile,
            &token,
            now,
        )
        .map_err(|e| api_err("plan", &e.to_string(), None))?;

    if !state
        .approvals
        .has_active(&params.plan_id, &params.diff_hash, state.profile, now)
    {
        return Err(api_err(
            "approval_required",
            "no active approval for this plan",
            Some(approval_url(
                &state.approval_url_base,
                params.plan_id.as_str(),
            )),
        ));
    }

    state
        .approvals
        .consume(&params.plan_id, &params.diff_hash, state.profile, now)
        .map_err(|e| api_err("approval", &e.to_string(), None))?;

    Ok(ResponseResult::ApplyDeferred(
        kxprov_api::ApplyDeferredResult {
            message: "apply execution is milestone A5; approval consumed".into(),
        },
    ))
}

async fn unlock(
    state: &ApiState,
    cred: crate::peer::PeerCred,
    params: UnlockParams,
) -> Result<ResponseResult, ApiErrorBody> {
    if !state.peer_policy.is_admin(cred) {
        return Err(api_err("forbidden", "root admin required", None));
    }
    let _ = params.reason;
    let _ = params.job_id;
    state
        .locked
        .clear()
        .map_err(|e| api_err("io", &e.to_string(), None))?;
    Ok(ResponseResult::Unlock(UnlockResult { unlocked: true }))
}

async fn run_job(state: &ApiState, kind: JobKind) -> Result<ResponseResult, ApiErrorBody> {
    let (_job_id, rx) = state
        .queue
        .enqueue(kind)
        .await
        .map_err(|_| api_err("queue", "daemon shutting down", None))?;
    let outcome = rx
        .await
        .map_err(|_| api_err("queue", "job dropped", None))?;
    map_outcome(outcome)
}

fn map_outcome(outcome: JobOutcome) -> Result<ResponseResult, ApiErrorBody> {
    match outcome {
        JobOutcome::ReadFields(r) => Ok(ResponseResult::ReadFields(r)),
        JobOutcome::PlanChange(r) => Ok(ResponseResult::PlanChange(r)),
        JobOutcome::BackupNow(r) => Ok(ResponseResult::BackupNow(r)),
        JobOutcome::ApplyDeferred(r) => Ok(ResponseResult::ApplyDeferred(r)),
        JobOutcome::Err { code, message } => Err(api_err(&code, &message, None)),
    }
}
