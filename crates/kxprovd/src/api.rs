use crate::approval::ApprovalBook;
use crate::backup::BackupStore;
use crate::config::Config;
use crate::gates::{prod_write_gate, GateState, ProdWriteGate};
use crate::job_principal::JobPrincipal;
use crate::locked::LockedStore;
use crate::mode::{write_approval_required, ModeStore};
#[cfg(feature = "sim-fault-triggers")]
use crate::peer::PeerCred;
use crate::peer::{PeerPolicy, PeerRole};
use crate::plan_live::verify_live_diff_hash;
use crate::plan_store::PlanStore;
use crate::queue::QueueError;
use crate::queue::{JobKind, JobOutcome, JobQueue};
use crate::time::now_ms;
use crate::tokens::{TokenError, TokenStore};
use crate::worker::backup_info;
use kxprov_api::{
    ApiErrorBody, ApplyPlanParams, OperationalMode, PlanChangeParams, Profile, RequestAuth,
    RequestBody, RequestEnvelope, Response, ResponseResult, Scope, SetModeParams, SetModeResult,
    SubmitApprovalParams, SubmitApprovalResult, TokenId, UnlockParams, UnlockResult, WhoamiResult,
};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::RwLock;

pub struct ApiState {
    pub config: Config,
    pub port: Arc<crate::port::DeviceArbiter>,
    pub profile: Arc<tokio::sync::RwLock<Profile>>,
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
    pub mode: ModeStore,
    pub transition: crate::transition::TransitionBlockStore,
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

async fn dispatch(
    state: &ApiState,
    cred: crate::peer::PeerCred,
    env: &RequestEnvelope,
) -> Response {
    let id = env.id.clone();
    if let Some(ref audit) = env.audit {
        tracing::info!(%audit, "gateway audit (not used for authorization)");
    }
    let role = state.peer_policy.role(cred);
    let locked = state.locked.load().ok().is_some_and(|s| s.locked);

    let result = match &env.body {
        RequestBody::Status => Ok(ResponseResult::Status(status_snapshot(state, locked).await)),
        RequestBody::ReadFields { params } => {
            let token = match require_access(state, cred, role, &env.auth, Scope::Read) {
                Ok(t) => t,
                Err(e) => return err_response(id, e),
            };
            run_job(
                state,
                JobKind::ReadFields {
                    params: params.clone(),
                },
                Some(token),
            )
            .await
        }
        RequestBody::PlanChange { params } => {
            let token = match require_access(state, cred, role, &env.auth, Scope::Plan) {
                Ok(t) => t,
                Err(e) => return err_response(id, e),
            };
            let token = match require_bearer_token(token) {
                Ok(t) => t,
                Err(e) => return err_response(id, e),
            };
            run_plan(state, params.clone(), token).await
        }
        RequestBody::SubmitApproval { params } => {
            let approver = match require_access(state, cred, role, &env.auth, Scope::Approve) {
                Ok(t) => t,
                Err(e) => return err_response(id, e),
            };
            let approver = match require_bearer_token(approver) {
                Ok(t) => t,
                Err(e) => return err_response(id, e),
            };
            submit_approval(state, params, approver).await
        }
        RequestBody::SetMode { params } => set_mode(state, cred, params.clone()).await,
        RequestBody::BackupNow => {
            if let Err(e) = require_backup_access(state, cred, role, &env.auth) {
                return err_response(id, e);
            }
            let mode = state
                .mode
                .read_stored_mode()
                .unwrap_or(OperationalMode::Production);
            run_job(
                state,
                JobKind::BackupNow {
                    operational_mode: mode,
                },
                None,
            )
            .await
        }
        RequestBody::ListBackups => {
            if let Err(e) = require_access(state, cred, role, &env.auth, Scope::Read) {
                return err_response(id, e);
            }
            list_backups(state).await
        }
        RequestBody::ApplyPlan { params } => {
            let token = match require_access(state, cred, role, &env.auth, Scope::Write) {
                Ok(t) => t,
                Err(e) => return err_response(id, e),
            };
            let token = match require_bearer_token(token) {
                Ok(t) => t,
                Err(e) => return err_response(id, e),
            };
            apply_plan(state, params, token, locked).await
        }
        RequestBody::Unlock { params } => unlock(state, cred, params.clone()).await,
        RequestBody::Whoami => whoami(state, role, &env.auth).await,
        #[cfg(feature = "sim-fault-triggers")]
        RequestBody::SimTriggerBusy { params } => {
            sim_trigger_busy(state, cred, role, &env.auth, params).await
        }
        #[cfg(feature = "sim-fault-triggers")]
        RequestBody::SimTriggerGoliathCopyFail => {
            sim_trigger_goliath_copy_fail(state, cred, role, &env.auth).await
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

async fn whoami(
    state: &ApiState,
    role: PeerRole,
    auth: &Option<RequestAuth>,
) -> Result<ResponseResult, ApiErrorBody> {
    if role == PeerRole::ReadOnly {
        return Err(api_err("forbidden", "read-only peer"));
    }
    let auth = auth
        .as_ref()
        .ok_or_else(|| api_err("token_required", "bearer required"))?;
    let now = now_ms();
    let verified = state
        .tokens
        .verify_bearer_identity(&auth.bearer, now)
        .map_err(token_error_to_api)?;
    Ok(ResponseResult::Whoami(WhoamiResult {
        token_id: verified.id,
        scopes: verified.scopes,
    }))
}

#[cfg(feature = "sim-fault-triggers")]
async fn sim_runtime_allowed(state: &ApiState) -> Result<(), ApiErrorBody> {
    if state.config.transport != crate::config::TransportKind::Sim {
        return Err(api_err("forbidden", "sim transport only"));
    }
    let profile = *state.profile.read().await;
    if profile != Profile::Sim && profile != Profile::Test {
        return Err(api_err("forbidden", "sim/test profile only"));
    }
    Ok(())
}

#[cfg(feature = "sim-fault-triggers")]
async fn sim_trigger_busy(
    state: &ApiState,
    cred: PeerCred,
    role: PeerRole,
    auth: &Option<RequestAuth>,
    params: &kxprov_api::SimTriggerBusyParams,
) -> Result<ResponseResult, ApiErrorBody> {
    sim_trigger_access(state, cred, role, auth).await?;
    let Some(pbx) = state.config.sim_pbx.as_ref() else {
        return Err(api_err("forbidden", "no sim transport"));
    };
    if params.frames == 0 {
        return Err(api_err("bad_request", "frames must be > 0"));
    }
    pbx.lock()
        .expect("sim pbx lock")
        .inject(kxtd1232_sim::Fault::Busy {
            frames: params.frames,
        });
    Ok(ResponseResult::SimTrigger(kxprov_api::SimTriggerResult {
        ok: true,
    }))
}

#[cfg(feature = "sim-fault-triggers")]
async fn sim_trigger_goliath_copy_fail(
    state: &ApiState,
    cred: PeerCred,
    role: PeerRole,
    auth: &Option<RequestAuth>,
) -> Result<ResponseResult, ApiErrorBody> {
    sim_trigger_access(state, cred, role, auth).await?;
    state.goliath.trigger_next_copy_fail();
    Ok(ResponseResult::SimTrigger(kxprov_api::SimTriggerResult {
        ok: true,
    }))
}

#[cfg(feature = "sim-fault-triggers")]
async fn sim_trigger_access(
    state: &ApiState,
    cred: PeerCred,
    role: PeerRole,
    auth: &Option<RequestAuth>,
) -> Result<(), ApiErrorBody> {
    sim_runtime_allowed(state).await?;
    if state.peer_policy.is_admin(cred) {
        return Ok(());
    }
    require_access(state, cred, role, auth, Scope::Write).map(|_| ())
}

fn verify_bearer(
    state: &ApiState,
    auth: &RequestAuth,
    need: Scope,
) -> Result<TokenId, ApiErrorBody> {
    let now = now_ms();
    state
        .tokens
        .verify_bearer(&auth.bearer, now, need)
        .map(|v| v.id)
        .map_err(token_error_to_api)
}

fn token_error_to_api(e: TokenError) -> ApiErrorBody {
    match e {
        TokenError::Unauthorized | TokenError::Revoked | TokenError::Expired => {
            api_err("unauthorized", "invalid bearer")
        }
        TokenError::ScopeDenied => api_err("forbidden", "token scope denied"),
        TokenError::StoreUnavailable => api_err("token", "token store unavailable"),
        TokenError::InsecurePermissions | TokenError::Invalid(_) => {
            api_err("token", "invalid tokens configuration")
        }
        TokenError::Io(err) => api_err("token", &err.to_string()),
        TokenError::Json(err) => api_err("token", &err.to_string()),
    }
}

fn require_access(
    state: &ApiState,
    cred: crate::peer::PeerCred,
    role: PeerRole,
    auth: &Option<RequestAuth>,
    need: Scope,
) -> Result<JobPrincipal, ApiErrorBody> {
    match role {
        PeerRole::Gateway => {
            let auth = auth
                .as_ref()
                .ok_or_else(|| api_err("token_required", "bearer required"))?;
            verify_bearer(state, auth, need).map(JobPrincipal::Token)
        }
        PeerRole::Admin => {
            if need == Scope::Read && auth.is_none() {
                return Ok(JobPrincipal::SyntheticRoot);
            }
            let auth = auth
                .as_ref()
                .ok_or_else(|| api_err("token_required", "bearer required"))?;
            verify_bearer(state, auth, need).map(JobPrincipal::Token)
        }
        PeerRole::ReadOnly => {
            if need != Scope::Read {
                return Err(api_err("forbidden", "read-only peer"));
            }
            Ok(JobPrincipal::SyntheticLocal { uid: cred.uid })
        }
    }
}

fn require_bearer_token(principal: JobPrincipal) -> Result<TokenId, ApiErrorBody> {
    match principal {
        JobPrincipal::Token(id) => Ok(id),
        _ => Err(api_err("token_required", "bearer required")),
    }
}

fn require_backup_access(
    state: &ApiState,
    cred: crate::peer::PeerCred,
    role: PeerRole,
    auth: &Option<RequestAuth>,
) -> Result<(), ApiErrorBody> {
    if role == PeerRole::Admin && auth.is_none() {
        return Ok(());
    }
    require_access(state, cred, role, auth, Scope::Write)
        .and_then(require_bearer_token)
        .map(|_| ())
}

async fn status_snapshot(state: &ApiState, locked: bool) -> kxprov_api::StatusResponse {
    let gates = state.gates.read().await;
    state.transition.maybe_fire_alert();
    let profile = *state.profile.read().await;
    let effective = state.mode.effective(profile);
    let locked_alert = if locked {
        let st = state.locked.load().ok().unwrap_or_default();
        let now = chrono::Utc::now();
        let may_fire = crate::alert::locked_alert_may_fire_utc(now);
        if may_fire && !st.alert_sent {
            let _ = state.locked.mark_alert_sent();
            tracing::warn!(
                reason = %st.reason,
                job_id = ?st.job_id,
                "LOCKED alert (quiet hours ended)"
            );
        }
        let st = state.locked.load().ok().unwrap_or(st);
        Some(kxprov_api::LockedAlertStatus {
            held: !may_fire,
            may_fire,
            sent: st.alert_sent,
        })
    } else {
        None
    };
    kxprov_api::StatusResponse {
        profile,
        mode: kxprov_api::DaemonMode::Simulator,
        operational_mode: effective.operational,
        transport: state.transport_label.clone(),
        gates: kxprov_api::GateFlags {
            live_writes_approved: gates.config.live_writes_approved,
            locked,
        },
        locked_alert,
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

async fn run_plan(
    state: &ApiState,
    params: PlanChangeParams,
    token: TokenId,
) -> Result<ResponseResult, ApiErrorBody> {
    let now = now_ms();
    let (_job_id, rx) = state
        .queue
        .enqueue(
            JobKind::PlanChange {
                params,
                token_id: token.clone(),
            },
            Some(JobPrincipal::Token(token)),
            now,
        )
        .await
        .map_err(queue_err)?;
    map_outcome(rx.await.map_err(|_| api_err("queue", "job dropped"))?)
}

async fn submit_approval(
    state: &ApiState,
    params: &SubmitApprovalParams,
    approver: TokenId,
) -> Result<ResponseResult, ApiErrorBody> {
    let plan_id = state
        .plans
        .resolve_plan_ref(&params.plan_id)
        .map_err(|e| match e {
            crate::plan_store::PlanError::AmbiguousPrefix => {
                api_err("ambiguous_prefix", "plan prefix matches more than one plan")
            }
            crate::plan_store::PlanError::InvalidRef => api_err(
                "invalid_plan_id",
                "plan_id must be 32-hex id or 8-hex prefix",
            ),
            _ => api_err("plan", &e.to_string()),
        })?;
    let rec = state
        .plans
        .get(&plan_id)
        .map_err(|e| api_err("plan", &e.to_string()))?;
    if rec.diff_hash != params.diff_hash {
        return Err(api_err("plan", "diff hash mismatch"));
    }
    let runtime_profile = *state.profile.read().await;
    if params.profile != runtime_profile {
        return Err(api_err("profile", "profile mismatch"));
    }
    if rec.profile != params.profile {
        return Err(api_err("plan", "plan profile mismatch"));
    }
    let now = now_ms();
    let approval = state
        .approvals
        .submit(
            plan_id,
            params.diff_hash.clone(),
            params.profile,
            &rec.creator_token,
            approver,
            now,
        )
        .map_err(|e| api_err("approval", &e.to_string()))?;
    Ok(ResponseResult::SubmitApproval(SubmitApprovalResult {
        approval,
    }))
}

pub const APPLY_PREFLIGHT_HOLDER: &str = "apply-preflight-diff-verify";

async fn set_mode(
    state: &ApiState,
    cred: crate::peer::PeerCred,
    params: SetModeParams,
) -> Result<ResponseResult, ApiErrorBody> {
    if !state.peer_policy.is_admin(cred) {
        return Err(api_err("forbidden", "root admin required"));
    }
    if !state.queue.is_idle().await {
        return Err(api_err("busy", "daemon not idle"));
    }
    if params.mode == OperationalMode::Production {
        if let Err(e) = crate::transition::verify_enter_production_or_block(
            &state.config,
            &state.port,
            &state.backups,
            &state.transition,
        ) {
            let code = match e {
                crate::transition::TransitionError::Mismatch => "transition_mismatch",
                crate::transition::TransitionError::NoDigest => "transition_no_backup",
                _ => "transition",
            };
            return Err(api_err(code, &e.to_string()));
        }
        let _ = state.transition.clear();
    }
    let (effective, profile, counter) = state
        .mode
        .set_operational(params.mode, params.profile, true)
        .map_err(|e| api_err("mode", &e.to_string()))?;
    *state.profile.write().await = profile;
    Ok(ResponseResult::SetMode(SetModeResult {
        mode: effective.operational,
        profile,
        counter,
    }))
}

async fn apply_plan(
    state: &ApiState,
    params: &ApplyPlanParams,
    token: TokenId,
    locked: bool,
) -> Result<ResponseResult, ApiErrorBody> {
    let now = now_ms();
    let profile = *state.profile.read().await;
    let live_writes = state.gates.read().await.config.live_writes_approved;
    if let Some(gate) = prod_write_gate(
        profile,
        locked,
        live_writes,
        state.transition.writes_blocked(),
    ) {
        let (code, message) = match gate {
            ProdWriteGate::LiveWrites => ("gate", "live_writes_approved is false"),
            ProdWriteGate::Locked => ("locked", "daemon is LOCKED"),
            ProdWriteGate::TransitionMismatch => (
                "transition_blocked",
                "writes blocked after testing→production mismatch",
            ),
        };
        return Err(api_err(code, message));
    }
    state
        .plans
        .verify_for_apply(&params.plan_id, &params.diff_hash, profile, &token, now)
        .map_err(|e| api_err("plan", &e.to_string()))?;

    verify_live_diff_hash(
        &state.config,
        &state.port,
        APPLY_PREFLIGHT_HOLDER,
        profile,
        &state.plans,
        &params.plan_id,
        &params.diff_hash,
    )
    .map_err(|_| api_err("diff", "live base diff hash mismatch"))?;

    let operational = state.mode.effective(profile).operational;
    let needs_approval = write_approval_required(profile, operational);
    if needs_approval
        && !state
            .approvals
            .has_active(&params.plan_id, &params.diff_hash, profile, now)
    {
        return Ok(ResponseResult::ApplyApprovalRequired(
            kxprov_api::ApplyApprovalRequiredResult {
                plan_id: params.plan_id.clone(),
                diff_hash: params.diff_hash.clone(),
                status: kxprov_api::ApplyPlanAwaitingStatus::ApprovalRequired,
            },
        ));
    }

    let mut approval_lease = None;
    if needs_approval {
        approval_lease = Some(
            state
                .approvals
                .consume(&params.plan_id, &params.diff_hash, profile, now)
                .map_err(|e| api_err("approval", &e.to_string()))?,
        );
    }

    let enqueue_result = state
        .queue
        .enqueue(
            JobKind::ApplyPlan {
                plan_id: params.plan_id.clone(),
                diff_hash: params.diff_hash.clone(),
                token_id: token.clone(),
            },
            Some(JobPrincipal::Token(token)),
            now,
        )
        .await;

    if let (Some(lease), Err(e)) = (approval_lease, &enqueue_result) {
        return Err(rollback_apply_approval_after_enqueue_fail(
            &state.approvals,
            lease,
            *e,
        ));
    }

    let (job_id, _rx) = enqueue_result.map_err(queue_err)?;

    Ok(ResponseResult::Job(kxprov_api::JobRef { job_id }))
}

async fn unlock(
    state: &ApiState,
    cred: crate::peer::PeerCred,
    params: UnlockParams,
) -> Result<ResponseResult, ApiErrorBody> {
    if !state.peer_policy.is_admin(cred) {
        return Err(api_err("forbidden", "root admin required"));
    }
    let _ = params.reason;
    let _ = params.job_id;
    state
        .locked
        .clear()
        .map_err(|e| api_err("io", &e.to_string()))?;
    Ok(ResponseResult::Unlock(UnlockResult { unlocked: true }))
}

fn queue_err_message(e: QueueError) -> &'static str {
    match e {
        QueueError::RateLimit => "per-token queue or rate cap exceeded",
        QueueError::Shutdown => "daemon shutting down",
    }
}

fn queue_err(e: QueueError) -> ApiErrorBody {
    api_err(
        match e {
            QueueError::RateLimit => "rate_limit",
            QueueError::Shutdown => "queue",
        },
        queue_err_message(e),
    )
}

fn rollback_apply_approval_after_enqueue_fail(
    approvals: &ApprovalBook,
    lease: crate::approval::ConsumedApproval,
    queue: QueueError,
) -> ApiErrorBody {
    if let Err(e) = approvals.release_consumed(lease) {
        tracing::error!(error = %e, "approval rollback failed after enqueue failure");
        return api_err(
            "queue",
            &format!(
                "{}; approval rollback failed: {e}",
                queue_err_message(queue)
            ),
        );
    }
    queue_err(queue)
}

async fn run_job(
    state: &ApiState,
    kind: JobKind,
    principal: Option<JobPrincipal>,
) -> Result<ResponseResult, ApiErrorBody> {
    let (_job_id, rx) = state
        .queue
        .enqueue(kind, principal, now_ms())
        .await
        .map_err(queue_err)?;
    let outcome = rx.await.map_err(|_| api_err("queue", "job dropped"))?;
    map_outcome(outcome)
}

fn map_outcome(outcome: JobOutcome) -> Result<ResponseResult, ApiErrorBody> {
    match outcome {
        JobOutcome::ReadFields(r) => Ok(ResponseResult::ReadFields(r)),
        JobOutcome::PlanChange(r) => Ok(ResponseResult::PlanChange(r)),
        JobOutcome::BackupNow(r) => Ok(ResponseResult::BackupNow(r)),
        JobOutcome::ApplyPlan { .. } => Err(api_err("internal", "apply uses job_id response")),
        JobOutcome::Err { code, message } => Err(api_err(&code, &message)),
    }
}

#[cfg(all(test, feature = "test-util"))]
mod apply_plan_tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::approval::ApprovalBook;
    use crate::backup::BackupStore;
    use crate::config::Config;
    use crate::gates::GateState;
    use crate::goliath::GoliathQueue;
    use crate::mode::ModeStore;
    use crate::peer::PeerPolicy;
    use crate::plan_store::{PlanSnapshot, PlanStore};
    use crate::test_util;
    use crate::transport::open;
    use kxprov_api::{ApplyPlanParams, Profile, TokenId};
    use kxtd1232::frame::Access;
    use kxtd1232::{build_plan, field_patch, FieldKind, Granularity};
    use std::sync::Arc;
    use tokio::sync::{mpsc, RwLock};

    fn test_api_state(tmp: &tempfile::TempDir, queue: Arc<JobQueue>) -> ApiState {
        let data = tmp.path().to_path_buf();
        std::fs::create_dir_all(data.join("plans")).unwrap();
        std::fs::create_dir_all(data.join("backups")).unwrap();
        test_util::write_integration_tokens(&data.join("tokens.json"));
        let mut cfg = Config::sim_test(data.clone(), data.join("kxprovd.sock"), 1000);
        cfg.profile = Profile::Prod;
        cfg.gates.live_writes_approved = true;
        ApiState {
            port: crate::transport::device_arbiter(&cfg),
            config: cfg.clone(),
            profile: Arc::new(RwLock::new(Profile::Prod)),
            transport_label: "sim".into(),
            gates: Arc::new(RwLock::new(GateState { config: cfg.gates })),
            peer_policy: PeerPolicy::new(1001, 1000),
            tokens: TokenStore::load_insecure(cfg.tokens_path.clone()).unwrap(),
            queue,
            backups: BackupStore::new(data.join("backups")).unwrap(),
            plans: PlanStore::new(data.join("plans")).unwrap(),
            approvals: ApprovalBook::new(&data),
            locked: LockedStore::new(&data),
            goliath: GoliathQueue::new(data.join("goliath")).unwrap(),
            mode: ModeStore::new(&data, Profile::Prod),
            transition: crate::transition::TransitionBlockStore::new(&data),
        }
    }

    #[test]
    fn rollback_enqueue_fail_surfaces_release_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let book = ApprovalBook::new(tmp.path());
        let plan_id = kxprov_api::PlanId("p".into());
        let diff = kxprov_api::DiffHash("d".into());
        book.submit(
            plan_id.clone(),
            diff.clone(),
            Profile::Prod,
            &TokenId("writer".into()),
            TokenId("approver".into()),
            0,
        )
        .unwrap();
        let lease = book.consume(&plan_id, &diff, Profile::Prod, 0).unwrap();
        std::fs::write(tmp.path().join("approvals.json"), b"{\"items\":[]}").unwrap();
        let err = rollback_apply_approval_after_enqueue_fail(&book, lease, QueueError::Shutdown);
        assert_eq!(err.code, "queue");
        assert!(
            err.message.contains("daemon shutting down"),
            "{}",
            err.message
        );
        assert!(
            err.message.contains("approval rollback failed"),
            "{}",
            err.message
        );
    }

    #[tokio::test]
    async fn apply_plan_keeps_approval_when_enqueue_shuts_down() {
        let tmp = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::channel(8);
        drop(rx);
        let state = test_api_state(&tmp, Arc::new(JobQueue::new(tx)));
        let token = TokenId("writer".into());
        let kind = FieldKind::CidName;
        let pwd = state.config.password.clone();
        let rec = {
            let transport = open(&state.config, &state.port, "api-test").unwrap();
            let mut client = crate::transport::client(&state.config, transport, Access::ReadOnly);
            client.login(&pwd).unwrap();
            let base = client.read_table(kind.table()).unwrap();
            let patch = field_patch(kind, 4, "AP").unwrap();
            let plan = build_plan(kind.table(), &base, &[patch], Granularity::Chunk).unwrap();
            let _ = client.end_binary();
            let snap = PlanSnapshot::from(&plan);
            let now = now_ms();
            state
                .plans
                .put(Profile::Prod, &token, &snap, now)
                .expect("plan")
        };
        let now = now_ms();
        state
            .approvals
            .submit(
                rec.id.clone(),
                rec.diff_hash.clone(),
                Profile::Prod,
                &token,
                TokenId("approver".into()),
                now,
            )
            .expect("approval");
        let err = apply_plan(
            &state,
            &ApplyPlanParams {
                plan_id: rec.id.clone(),
                diff_hash: rec.diff_hash.clone(),
            },
            token,
            false,
        )
        .await
        .expect_err("enqueue must fail");
        assert_eq!(err.code, "queue");
        assert!(
            state
                .approvals
                .has_active(&rec.id, &rec.diff_hash, Profile::Prod, now),
            "approval must not be consumed when enqueue fails"
        );
    }

    async fn prod_plan_with_approval(
        state: &ApiState,
    ) -> (kxprov_api::PlanId, kxprov_api::DiffHash, TokenId) {
        let token = TokenId("writer".into());
        let kind = FieldKind::CidName;
        let pwd = state.config.password.clone();
        let rec = {
            let transport = open(&state.config, &state.port, "api-test").unwrap();
            let mut client = crate::transport::client(&state.config, transport, Access::ReadOnly);
            client.login(&pwd).unwrap();
            let base = client.read_table(kind.table()).unwrap();
            let patch = field_patch(kind, 5, "C").unwrap();
            let plan = build_plan(kind.table(), &base, &[patch], Granularity::Chunk).unwrap();
            let _ = client.end_binary();
            let snap = PlanSnapshot::from(&plan);
            let now = now_ms();
            state
                .plans
                .put(Profile::Prod, &token, &snap, now)
                .expect("plan")
        };
        let now = now_ms();
        state
            .approvals
            .submit(
                rec.id.clone(),
                rec.diff_hash.clone(),
                Profile::Prod,
                &token,
                TokenId("approver".into()),
                now,
            )
            .expect("approval");
        (rec.id, rec.diff_hash, token)
    }

    #[tokio::test]
    async fn apply_plan_second_submit_needs_fresh_approval() {
        let tmp = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::channel(8);
        let state = test_api_state(&tmp, Arc::new(JobQueue::new(tx)));
        let (plan_id, diff_hash, token) = prod_plan_with_approval(&state).await;
        let first = apply_plan(
            &state,
            &ApplyPlanParams {
                plan_id: plan_id.clone(),
                diff_hash: diff_hash.clone(),
            },
            token.clone(),
            false,
        )
        .await
        .expect("first apply");
        assert!(matches!(first, ResponseResult::Job(_)));
        let resp = apply_plan(
            &state,
            &ApplyPlanParams { plan_id, diff_hash },
            token,
            false,
        )
        .await
        .expect("second apply response");
        assert!(matches!(resp, ResponseResult::ApplyApprovalRequired(_)));
    }

    #[tokio::test]
    async fn apply_plan_concurrent_single_approval() {
        use std::sync::Arc;
        use tokio::sync::Barrier;

        let tmp = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::channel(8);
        let state = Arc::new(test_api_state(&tmp, Arc::new(JobQueue::new(tx))));
        let (plan_id, diff_hash, token) = prod_plan_with_approval(&state).await;
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            let plan_id = plan_id.clone();
            let diff_hash = diff_hash.clone();
            let token = token.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                apply_plan(
                    &state,
                    &ApplyPlanParams { plan_id, diff_hash },
                    token,
                    false,
                )
                .await
            }));
        }
        let mut jobs = 0u32;
        let mut approval_blocks = 0u32;
        for h in handles {
            match h.await.unwrap() {
                Ok(ResponseResult::Job(_)) => jobs += 1,
                Ok(ResponseResult::ApplyApprovalRequired(_)) => approval_blocks += 1,
                Err(e) if e.code == "approval" => approval_blocks += 1,
                other => panic!("unexpected: {other:?}"),
            }
        }
        assert_eq!(jobs, 1, "exactly one apply may consume the approval");
        assert_eq!(
            approval_blocks, 1,
            "second concurrent apply must not enqueue"
        );
    }
}
