use crate::backup::{wire_to_dbh, BackupStore};
use crate::config::Config;
use crate::journal::{Journal, JournalEntry};
use crate::plan_store::{PlanSnapshot, PlanStore};
use crate::queue::{field_kind_wire, JobKind, JobOutcome, JobRequest, JobState};
use crate::time::now_ms;
use crate::transport::{open, AnyTransport};
use kxprov_api::{BackupInfo, FieldRow, PlanChangeResult, TokenId};
use kxtd1232::{build_plan, field_patch, Client, Granularity};
use std::sync::Arc;

pub struct WorkerCtx {
    pub config: Config,
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
        let failed = matches!(&outcome, JobOutcome::Err { .. });
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
        let _ = job.reply.send(outcome);
    }
}

async fn execute_job(ctx: &WorkerCtx, kind: JobKind) -> JobOutcome {
    match kind {
        JobKind::ReadFields { params } => run_read(ctx, params).await,
        JobKind::PlanChange { params, token_id } => run_plan(ctx, params, token_id).await,
        JobKind::BackupNow => run_backup(ctx).await,
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

async fn run_read(ctx: &WorkerCtx, params: kxprov_api::ReadFieldsParams) -> JobOutcome {
    let kind = field_kind_wire(params.kind);
    if u32::from(params.first) + u32::from(params.count) > u32::from(kind.records()) {
        return JobOutcome::Err {
            code: "range".into(),
            message: "record range out of bounds".into(),
        };
    }
    let pwd = ctx.config.password.clone();
    let first = params.first;
    let count = params.count;
    let rows = match with_client(ctx, |c| {
        c.login(&pwd)?;
        let raw = c.read_records(kind.table(), first, count)?;
        let _ = c.end_binary();
        Ok(raw)
    }) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let size = kind.record_size();
    let mut out = Vec::new();
    for (i, rec) in rows.chunks(size).enumerate() {
        let v = match kind.decode(rec) {
            Ok(v) => v,
            Err(e) => {
                return JobOutcome::Err {
                    code: "field".into(),
                    message: e.to_string(),
                };
            }
        };
        out.push(FieldRow {
            index: u32::from(first) + i as u32,
            value: v,
        });
    }
    JobOutcome::ReadFields(kxprov_api::ReadFieldsResult { rows: out })
}

async fn run_plan(
    ctx: &WorkerCtx,
    params: kxprov_api::PlanChangeParams,
    token_id: TokenId,
) -> JobOutcome {
    let kind = field_kind_wire(params.kind);
    let patch = match field_patch(kind, params.index, &params.value) {
        Ok(p) => p,
        Err(e) => {
            return JobOutcome::Err {
                code: "plan".into(),
                message: e.to_string(),
            };
        }
    };
    if let Err(e) = kxtd1232::tables::check_writable_table(kind.table()) {
        return JobOutcome::Err {
            code: "not_allowed".into(),
            message: e.to_string(),
        };
    }
    let pwd = ctx.config.password.clone();
    let plan = match with_client(ctx, |c| {
        c.login(&pwd)?;
        let base = c.read_table(kind.table())?;
        let plan = build_plan(kind.table(), &base, &[patch], Granularity::Chunk)?;
        let _ = c.end_binary();
        Ok(plan)
    }) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let snap = PlanSnapshot::from(&plan);
    let now = now_ms();
    let rec = match ctx.plans.put(ctx.config.profile, &token_id, &snap, now) {
        Ok(r) => r,
        Err(e) => {
            return JobOutcome::Err {
                code: "plan_store".into(),
                message: e.to_string(),
            };
        }
    };
    JobOutcome::PlanChange(PlanChangeResult {
        plan_id: rec.id,
        diff_hash: rec.diff_hash,
        table: plan.table,
        writes: plan.writes.len() as u32,
        diff: snap.diff,
        expires_at_ms: rec.expires_at_ms,
    })
}

async fn run_backup(ctx: &WorkerCtx) -> JobOutcome {
    let job_id = crate::queue::next_job_id();
    let temp = ctx.config.data_dir.join(format!("{job_id}.partial.dbh"));
    let _ = ctx.journal.append(&JournalEntry::BackupStart {
        job_id: job_id.clone(),
        temp_path: temp.display().to_string(),
    });
    let pwd = ctx.config.password.clone();
    let transport = match open(ctx.config.transport, &ctx.config.serial_device) {
        Ok(t) => t,
        Err(e) => {
            return JobOutcome::Err {
                code: "transport".into(),
                message: e,
            };
        }
    };
    let mut client = Client::new(transport);
    let wire = match BackupStore::read_full_backup(&mut client, &pwd) {
        Ok(w) => w,
        Err(e) => {
            return JobOutcome::Err {
                code: "backup".into(),
                message: e.to_string(),
            };
        }
    };
    let dbh = match wire_to_dbh(&wire) {
        Ok(d) => d,
        Err(e) => {
            return JobOutcome::Err {
                code: "dbh".into(),
                message: e.to_string(),
            };
        }
    };
    if std::fs::write(&temp, &dbh).is_err() {
        return JobOutcome::Err {
            code: "io".into(),
            message: "temp backup write failed".into(),
        };
    }
    let meta = match ctx.backups.save_verified(&dbh, &ctx.goliath) {
        Ok(m) => m,
        Err(e) => {
            return JobOutcome::Err {
                code: "backup".into(),
                message: e.to_string(),
            };
        }
    };
    let _ = ctx.journal.append(&JournalEntry::BackupCommit {
        job_id,
        backup_id: meta.id.clone(),
    });
    let _ = std::fs::remove_file(&temp);
    let _ = ctx.journal.truncate();
    JobOutcome::BackupNow(kxprov_api::BackupNowResult {
        backup: backup_info(&meta, &ctx.goliath),
    })
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
