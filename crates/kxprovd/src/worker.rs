use crate::apply::{lock_on_apply_failure, run_apply};
use crate::backup::{wire_to_dbh, BackupStore};
use crate::config::Config;
use crate::journal::{Journal, JournalEntry};
use crate::locked::LockedStore;
use crate::plan_store::{PlanSnapshot, PlanStore};
use crate::queue::{field_kind_wire, JobKind, JobOutcome, JobRequest, JobState};
use crate::time::now_ms;
use crate::tokens::TokenStore;
use crate::transport::{open, AnyTransport};
use kxprov_api::{BackupInfo, FieldRow, OperationalMode, PlanChangeResult, Profile, TokenId};
use kxtd1232::frame::Access;
use kxtd1232::{build_plan, field_patch, Client, Granularity};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct WorkerCtx {
    pub config: Config,
    pub profile: Arc<RwLock<Profile>>,
    pub plans: PlanStore,
    pub backups: BackupStore,
    pub journal: Journal,
    pub goliath: crate::goliath::GoliathQueue,
    pub locked: LockedStore,
}

pub async fn run_worker(
    mut rx: tokio::sync::mpsc::Receiver<JobRequest>,
    ctx: Arc<WorkerCtx>,
    queue_jobs: Arc<crate::queue::JobQueue>,
    tokens: TokenStore,
) {
    while let Some(job) = rx.recv().await {
        if let Some(ref principal) = job.principal {
            if let Some(tid) = principal.token_id() {
                let stale = job.token_epoch < queue_jobs.token_epoch(tid);
                match tokens.is_revoked(tid) {
                    Ok(revoked) if stale || revoked => {
                        queue_jobs.set_state(&job.id, JobState::Failed).await;
                        queue_jobs.release_token(job.principal.as_ref()).await;
                        let _ = job.reply.send(JobOutcome::Err {
                            code: "token_revoked".into(),
                            message: "bearer token was revoked".into(),
                        });
                        continue;
                    }
                    Err(crate::tokens::TokenError::StoreUnavailable) => {
                        queue_jobs.set_state(&job.id, JobState::Failed).await;
                        queue_jobs.release_token(job.principal.as_ref()).await;
                        let _ = job.reply.send(JobOutcome::Err {
                            code: "token".into(),
                            message: "token store unavailable".into(),
                        });
                        continue;
                    }
                    Ok(_) => {}
                    Err(_) => {
                        queue_jobs.set_state(&job.id, JobState::Failed).await;
                        queue_jobs.release_token(job.principal.as_ref()).await;
                        let _ = job.reply.send(JobOutcome::Err {
                            code: "token".into(),
                            message: "token store unavailable".into(),
                        });
                        continue;
                    }
                }
            }
        }
        queue_jobs.set_state(&job.id, JobState::Running).await;
        let outcome = execute_job(&ctx, &job.id, job.kind).await;
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
        queue_jobs.release_token(job.principal.as_ref()).await;
        let _ = job.reply.send(outcome);
    }
}

async fn execute_job(ctx: &WorkerCtx, job_id: &str, kind: JobKind) -> JobOutcome {
    match kind {
        JobKind::ReadFields { params } => run_read(ctx, params).await,
        JobKind::PlanChange { params, token_id } => run_plan(ctx, params, token_id).await,
        JobKind::BackupNow { operational_mode } => run_backup(ctx, operational_mode).await,
        JobKind::ApplyPlan {
            plan_id,
            diff_hash,
            token_id,
        } => run_apply_job(ctx, job_id, plan_id, diff_hash, token_id).await,
    }
}

fn open_client(ctx: &WorkerCtx, access: Access) -> Result<Client<AnyTransport>, JobOutcome> {
    let transport = open(&ctx.config).map_err(|e| JobOutcome::Err {
        code: "transport".into(),
        message: e,
    })?;
    Ok(Client::with(transport, access, ctx.config.timing))
}

fn with_client<T>(
    ctx: &WorkerCtx,
    f: impl FnOnce(&mut Client<AnyTransport>) -> Result<T, kxtd1232::Error>,
) -> Result<T, JobOutcome> {
    let mut client = open_client(ctx, Access::ReadOnly)?;
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
    let profile = *ctx.profile.read().await;
    let rec = match ctx.plans.put(profile, &token_id, &snap, now) {
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

async fn run_backup(ctx: &WorkerCtx, operational_mode: OperationalMode) -> JobOutcome {
    let job_id = crate::queue::next_job_id();
    let temp = ctx.config.data_dir.join(format!("{job_id}.partial.dbh"));
    let _ = ctx.journal.append(&JournalEntry::BackupStart {
        job_id: job_id.clone(),
        temp_path: temp.display().to_string(),
    });
    let pwd = ctx.config.password.clone();
    let transport = match open(&ctx.config) {
        Ok(t) => t,
        Err(e) => {
            return JobOutcome::Err {
                code: "transport".into(),
                message: e,
            };
        }
    };
    let header_tail = match ctx.backups.pre_write_header_tail(&transport) {
        Ok(t) => t,
        Err(e) => {
            return JobOutcome::Err {
                code: "backup".into(),
                message: e.to_string(),
            };
        }
    };
    let mut client = Client::with(transport, Access::ReadOnly, ctx.config.timing);
    let wire = match BackupStore::read_full_backup(&mut client, &pwd) {
        Ok(w) => w,
        Err(e) => {
            return JobOutcome::Err {
                code: "backup".into(),
                message: e.to_string(),
            };
        }
    };
    let dbh = match wire_to_dbh(&wire, &header_tail) {
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
    let digest = Some(crate::transition::caller_id_wire_digest(&wire));
    let meta = match ctx
        .backups
        .save_verified(&dbh, &ctx.goliath, digest, operational_mode)
    {
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

async fn run_apply_job(
    ctx: &WorkerCtx,
    job_id: &str,
    plan_id: kxprov_api::PlanId,
    diff_hash: kxprov_api::DiffHash,
    token_id: kxprov_api::TokenId,
) -> JobOutcome {
    let backup_id = match ctx.backups.list() {
        Ok(list) => list.first().map(|b| b.id.clone()).unwrap_or_default(),
        Err(e) => {
            return JobOutcome::Err {
                code: "backup".into(),
                message: e.to_string(),
            };
        }
    };
    if let Err(e) = ctx.journal.append(&JournalEntry::ApplyStart {
        job_id: job_id.to_string(),
        plan_id: plan_id.as_str().to_string(),
        diff_hash: diff_hash.0.clone(),
        backup_id,
    }) {
        return JobOutcome::Err {
            code: "journal".into(),
            message: format!("ApplyStart not persisted: {e}"),
        };
    }
    let profile = *ctx.profile.read().await;
    match run_apply(
        &ctx.config,
        profile,
        &ctx.plans,
        &ctx.backups,
        &plan_id,
        &diff_hash,
        &token_id,
    ) {
        Ok(_blocks) => {
            if let Err(e) = ctx.plans.mark_applied(&plan_id, now_ms()) {
                let msg = format!("mark_applied failed: {e}");
                let _ = lock_on_apply_failure(&ctx.locked, &msg, job_id);
                return JobOutcome::Err {
                    code: "apply".into(),
                    message: msg,
                };
            }
            if let Err(e) = ctx.journal.truncate() {
                let msg = format!("journal truncate failed: {e}");
                let _ = lock_on_apply_failure(&ctx.locked, &msg, job_id);
                return JobOutcome::Err {
                    code: "apply".into(),
                    message: msg,
                };
            }
            JobOutcome::ApplyPlan { plan_id, diff_hash }
        }
        Err(e) => {
            if matches!(e, crate::apply::ApplyError::NotSim) {
                if let Err(je) = ctx.journal.append(&JournalEntry::ApplyAbort {
                    job_id: job_id.to_string(),
                }) {
                    return JobOutcome::Err {
                        code: "journal".into(),
                        message: format!("ApplyAbort not persisted: {je}"),
                    };
                }
                return JobOutcome::Err {
                    code: "apply".into(),
                    message: e.to_string(),
                };
            }
            if lock_on_apply_failure(&ctx.locked, &e.to_string(), job_id).is_err() {
                return JobOutcome::Err {
                    code: "locked".into(),
                    message: "apply failed and LOCKED could not be persisted".into(),
                };
            }
            if let Err(je) = ctx.journal.append(&JournalEntry::ApplyAbort {
                job_id: job_id.to_string(),
            }) {
                return JobOutcome::Err {
                    code: "journal".into(),
                    message: format!("ApplyAbort not persisted: {je}"),
                };
            }
            JobOutcome::Err {
                code: "apply".into(),
                message: e.to_string(),
            }
        }
    }
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
