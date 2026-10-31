use crate::apply::{lock_on_apply_failure, run_apply};
use crate::approval::ApprovalBook;
use crate::backup::{wire_to_dbh, BackupStore};
use crate::config::Config;
use crate::gates::{prod_write_gate, GateState, ProdWriteGate};
use crate::journal::{Journal, JournalEntry};
use crate::locked::LockedStore;
use crate::mode::write_approval_required;
use crate::plan_store::{PlanSnapshot, PlanStore};
use crate::queue::{field_kind_wire, JobKind, JobOutcome, JobRequest, JobState};
use crate::time::now_ms;
use crate::tokens::TokenStore;
use crate::transition::TransitionBlockStore;
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
    pub gates: Arc<RwLock<GateState>>,
    pub transition: TransitionBlockStore,
    pub approvals: ApprovalBook,
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
    let label = kind.label();
    let outcome = execute_job_inner(ctx, job_id, kind).await;
    if let JobOutcome::Err { code, message } = &outcome {
        log_job_failure(job_id, label, code, message);
    }
    outcome
}

pub(crate) fn log_job_failure(job_id: &str, label: &str, code: &str, message: &str) {
    tracing::warn!(
        job_id,
        job = label,
        code,
        message_bytes = message.len(),
        "job failed"
    );
}

pub(crate) fn log_pbx_error(e: &kxtd1232::Error) {
    tracing::warn!(error_kind = e.kind(), "pbx error");
}

async fn execute_job_inner(ctx: &WorkerCtx, job_id: &str, kind: JobKind) -> JobOutcome {
    match kind {
        JobKind::ReadFields { params } => run_read(ctx, job_id, params).await,
        JobKind::PlanChange { params, token_id } => run_plan(ctx, job_id, params, token_id).await,
        JobKind::BackupNow { operational_mode } => run_backup(ctx, job_id, operational_mode).await,
        JobKind::ApplyPlan {
            plan_id,
            diff_hash,
            token_id,
        } => run_apply_job(ctx, job_id, plan_id, diff_hash, token_id).await,
    }
}

fn open_client(
    ctx: &WorkerCtx,
    job_id: &str,
    access: Access,
) -> Result<Client<AnyTransport>, JobOutcome> {
    let transport = open(&ctx.config, job_id).map_err(|e| JobOutcome::Err {
        code: "transport".into(),
        message: e,
    })?;
    Ok(crate::transport::client(&ctx.config, transport, access))
}

fn with_client<T>(
    ctx: &WorkerCtx,
    job_id: &str,
    f: impl FnOnce(&mut Client<AnyTransport>) -> Result<T, kxtd1232::Error>,
) -> Result<T, JobOutcome> {
    let mut client = open_client(ctx, job_id, Access::ReadOnly)?;
    f(&mut client).map_err(|e| {
        log_pbx_error(&e);
        JobOutcome::Err {
            code: "protocol".into(),
            message: e.to_string(),
        }
    })
}

async fn run_read(
    ctx: &WorkerCtx,
    job_id: &str,
    params: kxprov_api::ReadFieldsParams,
) -> JobOutcome {
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
    let rows = match with_client(ctx, job_id, |c| {
        crate::transport::login(c, &pwd)?;
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
    job_id: &str,
    params: kxprov_api::PlanChangeParams,
    token_id: TokenId,
) -> JobOutcome {
    #[cfg(feature = "test-util")]
    crate::test_util::plan_change_hold_if_armed().await;
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
    let plan = match with_client(ctx, job_id, |c| {
        crate::transport::login(c, &pwd)?;
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

async fn run_backup(
    ctx: &WorkerCtx,
    worker_job_id: &str,
    operational_mode: OperationalMode,
) -> JobOutcome {
    let job_id = crate::queue::next_job_id();
    let temp = ctx
        .config
        .profile_data_dir()
        .join(format!("{job_id}.partial.dbh"));
    let _ = ctx.journal.append(&JournalEntry::BackupStart {
        job_id: job_id.clone(),
        temp_path: temp.display().to_string(),
    });
    let pwd = ctx.config.password.clone();
    let transport = match open(&ctx.config, worker_job_id) {
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
    let mut client = crate::transport::client(&ctx.config, transport, Access::ReadOnly);
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

fn apply_job_approval_gate(
    ctx: &WorkerCtx,
    profile: Profile,
    plan_id: &kxprov_api::PlanId,
    diff_hash: &kxprov_api::DiffHash,
) -> Option<JobOutcome> {
    if !write_approval_required(profile, OperationalMode::Production) {
        return None;
    }
    if ctx
        .approvals
        .is_consumed_for_apply(plan_id, diff_hash, profile)
    {
        return None;
    }
    Some(JobOutcome::Err {
        code: "approval".into(),
        message: "apply approval was not consumed before job ran".into(),
    })
}

fn apply_job_prod_gate(ctx: &WorkerCtx, profile: Profile) -> Option<JobOutcome> {
    let locked = ctx.locked.load().map(|s| s.locked).unwrap_or(true);
    let live_writes = ctx
        .gates
        .try_read()
        .map(|g| g.config.live_writes_approved)
        .unwrap_or(false);
    let gate = prod_write_gate(
        profile,
        locked,
        live_writes,
        ctx.transition.writes_blocked(),
    )?;
    let (code, message) = match gate {
        ProdWriteGate::LiveWrites => ("gate", "live_writes_approved is false"),
        ProdWriteGate::Locked => ("locked", "daemon is LOCKED"),
        ProdWriteGate::TransitionMismatch => (
            "transition_blocked",
            "writes blocked after testing→production mismatch",
        ),
    };
    Some(JobOutcome::Err {
        code: code.into(),
        message: message.into(),
    })
}

async fn run_apply_job(
    ctx: &WorkerCtx,
    job_id: &str,
    plan_id: kxprov_api::PlanId,
    diff_hash: kxprov_api::DiffHash,
    token_id: kxprov_api::TokenId,
) -> JobOutcome {
    let profile = *ctx.profile.read().await;
    if let Some(outcome) = apply_job_prod_gate(ctx, profile) {
        return outcome;
    }
    if let Some(outcome) = apply_job_approval_gate(ctx, profile, &plan_id, &diff_hash) {
        return outcome;
    }
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
    match run_apply(
        &ctx.config,
        profile,
        &ctx.plans,
        &ctx.backups,
        crate::apply::ApplyJob {
            job_id,
            plan_id: &plan_id,
            diff_hash: &diff_hash,
            token: &token_id,
        },
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

#[cfg(all(test, feature = "test-util"))]
mod prod_gate_tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::backup::BackupStore;
    use crate::config::Config;
    use crate::gates::GateConfig;
    use crate::goliath::GoliathQueue;
    use crate::journal::Journal;
    use crate::plan_store::PlanStore;

    fn test_worker_ctx(tmp: &tempfile::TempDir, locked: bool) -> WorkerCtx {
        let data = tmp.path().to_path_buf();
        std::fs::create_dir_all(data.join("plans")).unwrap();
        std::fs::create_dir_all(data.join("backups")).unwrap();
        let locked_store = LockedStore::new(&data);
        if locked {
            locked_store
                .set_locked("test", Some("j1"), 1)
                .expect("set locked");
        }
        let cfg = Config::sim_test(data.clone(), data.join("kxprovd.sock"), 1000);
        WorkerCtx {
            config: cfg,
            profile: Arc::new(RwLock::new(Profile::Prod)),
            plans: PlanStore::new(data.join("plans")).expect("plans"),
            backups: BackupStore::new(data.join("backups")).expect("backups"),
            journal: Journal::new(&data),
            goliath: GoliathQueue::new(data.join("goliath")).expect("goliath"),
            locked: locked_store,
            gates: Arc::new(RwLock::new(GateState {
                config: GateConfig {
                    live_writes_approved: true,
                },
            })),
            transition: TransitionBlockStore::new(&data),
            approvals: ApprovalBook::new(&data),
        }
    }

    #[tokio::test]
    async fn backup_login_failure_logs_the_login_trace() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = test_worker_ctx(&tmp, false);
        ctx.config.password = "not-the-sim-password".into();
        let (cap, guard) = super::log_redaction_tests::capture();
        let outcome = run_backup(&ctx, "job-test", OperationalMode::Testing).await;
        drop(guard);
        let out = cap.text();
        assert!(
            matches!(outcome, JobOutcome::Err { ref code, .. } if code == "backup"),
            "{outcome:?}"
        );
        assert!(out.contains("login failed"), "{out}");
        assert!(out.contains("dtr_cycled="), "{out}");
        assert!(!out.contains("not-the-sim-password"), "{out}");
    }

    #[tokio::test]
    async fn apply_job_approval_gate_blocks_without_consumed() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_worker_ctx(&tmp, false);
        let plan_id = kxprov_api::PlanId("p1".into());
        let diff = kxprov_api::DiffHash("d".into());
        let outcome =
            apply_job_approval_gate(&ctx, Profile::Prod, &plan_id, &diff).expect("blocked");
        assert!(
            matches!(outcome, JobOutcome::Err { ref code, .. } if code == "approval"),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn apply_job_prod_gate_blocks_locked_at_execution() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_worker_ctx(&tmp, true);
        let outcome = apply_job_prod_gate(&ctx, Profile::Prod).expect("blocked");
        assert!(
            matches!(outcome, JobOutcome::Err { ref code, .. } if code == "locked"),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn apply_job_prod_gate_skipped_for_non_prod_profile() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_worker_ctx(&tmp, true);
        assert!(apply_job_prod_gate(&ctx, Profile::Sim).is_none());
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "a failed test setup step should panic the test"
)]
mod log_redaction_tests {
    use super::{log_job_failure, log_pbx_error};
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    pub(super) struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Capture {
        pub(super) fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    pub(super) fn capture() -> (Capture, tracing::subscriber::DefaultGuard) {
        let cap = Capture::default();
        let writer = cap.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (cap, guard)
    }

    fn captured(f: impl FnOnce()) -> String {
        let (cap, guard) = capture();
        f();
        drop(guard);
        cap.text()
    }

    #[test]
    fn reply_bearing_error_logs_no_payload_bytes() {
        let payload = vec![0xDEu8, 0xAD, 0xBE, 0xEF, 0x31, 0x32, 0x33, 0x34];
        let err = kxtd1232::Error::UnexpectedReply(format!("{payload:?}"));
        let message = err.to_string();
        let out = captured(|| {
            log_pbx_error(&err);
            log_job_failure("job-1", "read_fields", "protocol", &message);
        });
        assert!(out.contains("pbx error"), "{out}");
        assert!(out.contains("error_kind=\"UnexpectedReply\""), "{out}");
        assert!(out.contains("job failed"), "{out}");
        assert!(out.contains("code=\"protocol\""), "{out}");
        assert!(
            out.contains(&format!("message_bytes={}", message.len())),
            "{out}"
        );
        assert!(!out.contains(&message), "{out}");
        assert!(!out.contains("222"), "{out}");
        assert!(!out.contains("173"), "{out}");
        assert!(!out.contains("unexpected reply"), "{out}");
    }
}
