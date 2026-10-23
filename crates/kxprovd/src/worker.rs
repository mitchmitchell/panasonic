use crate::backup::{wire_to_dbh, BackupStore};
use crate::config::Config;
use crate::gates::GateState;
use crate::journal::{Journal, JournalEntry};
use crate::plan_store::{PlanSnapshot, PlanStore};
use crate::queue::{field_kind_wire, JobKind, JobOutcome, JobRequest, JobState};
use crate::transport::{open, AnyTransport};
use kxprov_api::{ArmStatus, BackupInfo, FieldRow, PlanChangeResult};
use kxtd1232::{build_plan, field_patch, Client, Granularity};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct WorkerCtx {
    pub config: Config,
    pub gates: Arc<RwLock<GateState>>,
    pub plans: PlanStore,
    pub backups: BackupStore,
    pub journal: Journal,
    pub goliath: crate::goliath::GoliathQueue,
}

pub async fn run_worker(
    mut rx: tokio::sync::mpsc::Receiver<JobRequest>,
    ctx: Arc<WorkerCtx>,
    queue_jobs: Arc<crate::queue::JobQueue>,
) {
    while let Some(job) = rx.recv().await {
        queue_jobs.set_state(&job.id, JobState::Running).await;
        let outcome = execute_job(&ctx, job.kind).await;
        let failed = matches!(
            &outcome,
            Err(JobOutcome::Err { .. }) | Ok(JobOutcome::Err { .. })
        );
        queue_jobs
            .set_state(
                &job.id,
                if failed {
                    JobState::Failed
                } else {
                    JobState::Done
                },
            )
            .await;
        let msg = match outcome {
            Ok(o) => o,
            Err(o) => o,
        };
        let _ = job.reply.send(msg);
    }
}

async fn execute_job(ctx: &WorkerCtx, kind: JobKind) -> Result<JobOutcome, JobOutcome> {
    match kind {
        JobKind::ReadFields { params } => run_read(ctx, params).await,
        JobKind::PlanChange { params } => run_plan(ctx, params).await,
        JobKind::ArmPlan { params } => run_arm(ctx, params).await,
        JobKind::BackupNow => run_backup(ctx).await,
        JobKind::ApplyPlan { params: _ } => {
            Ok(JobOutcome::ApplyDeferred(kxprov_api::ApplyDeferredResult {
                message: "live apply is milestone A5; plan and arm verified only".into(),
            }))
        }
    }
}

fn with_client<T>(
    ctx: &WorkerCtx,
    f: impl FnOnce(&mut Client<AnyTransport>) -> Result<T, kxtd1232::Error>,
) -> Result<T, JobOutcome> {
    let transport =
        open(ctx.config.transport, &ctx.config.serial_device).map_err(|e| JobOutcome::Err {
            code: "transport".into(),
            message: e,
        })?;
    let mut client = Client::new(transport);
    f(&mut client).map_err(|e| JobOutcome::Err {
        code: "protocol".into(),
        message: e.to_string(),
    })
}

async fn run_read(
    ctx: &WorkerCtx,
    params: kxprov_api::ReadFieldsParams,
) -> Result<JobOutcome, JobOutcome> {
    let kind = field_kind_wire(params.kind);
    if u32::from(params.first) + u32::from(params.count) > u32::from(kind.records()) {
        return Err(JobOutcome::Err {
            code: "range".into(),
            message: "record range out of bounds".into(),
        });
    }
    let pwd = ctx.config.password.clone();
    let first = params.first;
    let count = params.count;
    let rows = with_client(ctx, |c| {
        c.login(&pwd)?;
        let raw = c.read_records(kind.table(), first, count)?;
        let _ = c.end_binary();
        Ok(raw)
    })?;
    let size = kind.record_size();
    let mut out = Vec::new();
    for (i, rec) in rows.chunks(size).enumerate() {
        let v = kind.decode(rec).map_err(|e| JobOutcome::Err {
            code: "field".into(),
            message: e.to_string(),
        })?;
        out.push(FieldRow {
            index: u32::from(first) + i as u32,
            value: v,
        });
    }
    Ok(JobOutcome::ReadFields(kxprov_api::ReadFieldsResult {
        rows: out,
    }))
}

async fn run_plan(
    ctx: &WorkerCtx,
    params: kxprov_api::PlanChangeParams,
) -> Result<JobOutcome, JobOutcome> {
    let kind = field_kind_wire(params.kind);
    let patch = field_patch(kind, params.index, &params.value).map_err(|e| JobOutcome::Err {
        code: "plan".into(),
        message: e.to_string(),
    })?;
    kxtd1232::tables::check_writable_table(kind.table()).map_err(|e| JobOutcome::Err {
        code: "not_allowed".into(),
        message: e.to_string(),
    })?;
    let pwd = ctx.config.password.clone();
    let plan = with_client(ctx, |c| {
        c.login(&pwd)?;
        let base = c.read_table(kind.table())?;
        let plan = build_plan(kind.table(), &base, &[patch], Granularity::Chunk)?;
        let _ = c.end_binary();
        Ok(plan)
    })?;
    let snap = PlanSnapshot::from(&plan);
    let (plan_id, diff_hash) = ctx.plans.put(&snap).map_err(|e| JobOutcome::Err {
        code: "plan_store".into(),
        message: e.to_string(),
    })?;
    Ok(JobOutcome::PlanChange(PlanChangeResult {
        plan_id,
        diff_hash,
        table: plan.table,
        writes: plan.writes.len() as u32,
        diff: snap.diff,
    }))
}

async fn run_arm(
    ctx: &WorkerCtx,
    params: kxprov_api::ArmPlanParams,
) -> Result<JobOutcome, JobOutcome> {
    ctx.plans
        .verify_diff_hash(&params.plan_id, &params.diff_hash)
        .map_err(|e| JobOutcome::Err {
            code: "plan".into(),
            message: e.to_string(),
        })?;
    let grant = crate::arm::ArmGrant::new(
        params.plan_id,
        params.diff_hash,
        params.ttl_secs,
        ctx.gates.read().await.config.max_arm_ttl_secs,
    );
    let arm = ArmStatus {
        plan_id: grant.plan_id.clone(),
        diff_hash: grant.diff_hash.clone(),
        expires_at_ms: grant.expires_at_ms,
    };
    ctx.gates.write().await.arm = Some(grant);
    Ok(JobOutcome::ArmPlan(kxprov_api::ArmPlanResult { arm }))
}

async fn run_backup(ctx: &WorkerCtx) -> Result<JobOutcome, JobOutcome> {
    let job_id = crate::queue::next_job_id();
    let temp = ctx.config.data_dir.join(format!("{job_id}.partial.dbh"));
    let _ = ctx.journal.append(&JournalEntry::BackupStart {
        job_id: job_id.clone(),
        temp_path: temp.display().to_string(),
    });
    let pwd = ctx.config.password.clone();
    let transport =
        open(ctx.config.transport, &ctx.config.serial_device).map_err(|e| JobOutcome::Err {
            code: "transport".into(),
            message: e,
        })?;
    let mut client = Client::new(transport);
    let wire = BackupStore::read_full_backup(&mut client, &pwd).map_err(|e| JobOutcome::Err {
        code: "backup".into(),
        message: e.to_string(),
    })?;
    let dbh = wire_to_dbh(&wire).map_err(|e| JobOutcome::Err {
        code: "dbh".into(),
        message: e.to_string(),
    })?;
    std::fs::write(&temp, &dbh).map_err(|e| JobOutcome::Err {
        code: "io".into(),
        message: e.to_string(),
    })?;
    let meta = ctx
        .backups
        .save_verified(&dbh, &ctx.goliath)
        .map_err(|e| JobOutcome::Err {
            code: "backup".into(),
            message: e.to_string(),
        })?;
    let _ = ctx.journal.append(&JournalEntry::BackupCommit {
        job_id,
        backup_id: meta.id.clone(),
    });
    let _ = std::fs::remove_file(&temp);
    let _ = ctx.journal.truncate();
    Ok(JobOutcome::BackupNow(kxprov_api::BackupNowResult {
        backup: backup_info(&meta, &ctx.goliath),
    }))
}

pub fn backup_info(
    meta: &crate::backup::BackupMeta,
    goliath: &crate::goliath::GoliathQueue,
) -> BackupInfo {
    BackupInfo {
        id: meta.id.clone(),
        created_at_ms: meta.created_at_ms,
        bytes: meta.bytes,
        sha256: meta.sha256.clone(),
        goliath: crate::backup::goliath_status(meta, goliath),
    }
}
