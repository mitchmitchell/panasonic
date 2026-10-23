use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::sync::RwLock;

use crate::approval::{
    plan_storage_ttl, Approval, APPROVAL_SUBMIT_LIMIT_PER_DAY, APPROVAL_SUBMIT_LIMIT_PER_HOUR,
};
use crate::backend::DaemonBackend;
use crate::error::ApiError;
use crate::identity::CallerIdentity;
use crate::mode::Mode;
use crate::plan::{DiffHash, ImmutablePlan, PlanId};
use crate::profile::Profile;
use crate::scope::Scope;
use crate::types::{
    ApplyJob, BackupInfo, BackupList, DaemonStatus, FieldValue, JobId, JobState, PlanChangeRequest,
    PlanSummary, ReadFieldsRequest, ReadFieldsResponse, RequestedBy,
};

struct StoredApproval {
    approval: Approval,
    consumed: bool,
}

struct SubmitRateState {
    hour_window: Instant,
    hour_count: u32,
    day_window: Instant,
    day_count: u32,
}

struct Inner {
    profile: Profile,
    mode: Mode,
    plans: HashMap<String, ImmutablePlan>,
    plan_approvals: HashMap<String, StoredApproval>,
    submit_rates: HashMap<String, SubmitRateState>,
    backups: Vec<BackupInfo>,
    next_job: u64,
    live_writes_approved: bool,
}

pub struct MockDaemon {
    inner: Arc<RwLock<Inner>>,
    admin_hash: String,
}

impl MockDaemon {
    pub fn new() -> Self {
        Self::with_admin_password("test-admin-password")
    }

    pub fn with_admin_password(password: &str) -> Self {
        Self::with_mode_and_password(Mode::DryRun, password)
    }

    pub fn with_mode(mode: Mode) -> Self {
        Self::with_mode_and_password(mode, "test-admin-password")
    }

    pub fn with_mode_and_password(mode: Mode, password: &str) -> Self {
        let salt = SaltString::generate(&mut rand::thread_rng());
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .expect("hash")
            .to_string();
        Self {
            admin_hash: hash,
            inner: Arc::new(RwLock::new(Inner {
                profile: Profile::test(),
                mode,
                plans: HashMap::new(),
                plan_approvals: HashMap::new(),
                submit_rates: HashMap::new(),
                backups: vec![BackupInfo {
                    id: "sim-initial".into(),
                    created_at: "2026-01-01T00:00:00Z".into(),
                }],
                next_job: 0,
                live_writes_approved: false,
            })),
        }
    }

    fn require_scope(caller: &CallerIdentity, scope: Scope) -> Result<(), ApiError> {
        if caller.scopes().contains(scope) {
            Ok(())
        } else {
            Err(ApiError::ForbiddenScope)
        }
    }

    fn verify_password(hash: &str, password: &str) -> bool {
        let parsed = match PasswordHash::new(hash) {
            Ok(p) => p,
            Err(_) => return false,
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    }

    fn plan_key(id: &PlanId) -> String {
        id.to_hex()
    }

    fn resolve_plan_id(
        plans: &HashMap<String, ImmutablePlan>,
        plan_id_or_prefix: &str,
    ) -> Result<PlanId, ApiError> {
        let id = plan_id_or_prefix.trim();
        if id.len() == 32 {
            return PlanId::from_hex(id);
        }
        if id.len() == 8 {
            let matches: Vec<&String> = plans.keys().filter(|k| k.starts_with(id)).collect();
            return match matches.len() {
                0 => Err(ApiError::PlanNotFound),
                1 => PlanId::from_hex(matches[0]),
                _ => Err(ApiError::AmbiguousPlanPrefix),
            };
        }
        Err(ApiError::BadRequest("plan_id"))
    }

    fn validate_plan_approval(
        stored: &StoredApproval,
        plan_id: PlanId,
        diff_hash: &DiffHash,
        profile: &Profile,
    ) -> Result<(), ApiError> {
        if stored.consumed {
            return Err(ApiError::InvalidApproval);
        }
        if stored.approval.expires_at < OffsetDateTime::now_utc() {
            return Err(ApiError::InvalidApproval);
        }
        if stored.approval.plan_id != plan_id
            || stored.approval.diff_hash != *diff_hash
            || stored.approval.profile != *profile
        {
            return Err(ApiError::InvalidApproval);
        }
        Ok(())
    }

    fn check_submit_rate(state: &mut SubmitRateState) -> Result<(), ApiError> {
        let now = Instant::now();
        if now.duration_since(state.hour_window) >= StdDuration::from_secs(3600) {
            state.hour_window = now;
            state.hour_count = 0;
        }
        if now.duration_since(state.day_window) >= StdDuration::from_secs(86_400) {
            state.day_window = now;
            state.day_count = 0;
        }
        if state.hour_count >= APPROVAL_SUBMIT_LIMIT_PER_HOUR
            || state.day_count >= APPROVAL_SUBMIT_LIMIT_PER_DAY
        {
            return Err(ApiError::ApprovalRateLimited);
        }
        state.hour_count += 1;
        state.day_count += 1;
        Ok(())
    }

    /// Test helper: backdate a stored plan so the approval window appears expired.
    pub async fn test_backdate_plan(&self, plan_id: PlanId, by: time::Duration) {
        let mut inner = self.inner.write().await;
        if let Some(plan) = inner.plans.get_mut(&Self::plan_key(&plan_id)) {
            plan.stored_at -= by;
        }
    }
}

impl Default for MockDaemon {
    fn default() -> Self {
        Self::new()
    }
}

fn plan_summary_from(
    plan_id: &PlanId,
    diff_hash: &DiffHash,
    summary_text: &str,
    requested_by: &Option<RequestedBy>,
    plan: &ImmutablePlan,
) -> PlanSummary {
    let expires_at = (plan.stored_at + plan_storage_ttl())
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".into());
    PlanSummary {
        plan_id: *plan_id,
        diff_hash: diff_hash.clone(),
        summary: summary_text.to_string(),
        expires_at,
        requested_by: requested_by.clone(),
    }
}

#[async_trait]
impl DaemonBackend for MockDaemon {
    async fn status(&self, caller: &CallerIdentity) -> Result<DaemonStatus, ApiError> {
        Self::require_scope(caller, Scope::Read)?;
        let inner = self.inner.read().await;
        Ok(DaemonStatus {
            profile: inner.profile.0.clone(),
            simulator: true,
            mode: inner.mode,
            locked: false,
            live_writes_approved: inner.live_writes_approved,
            queue_depth: 0,
        })
    }

    async fn list_backups(&self, caller: &CallerIdentity) -> Result<BackupList, ApiError> {
        Self::require_scope(caller, Scope::Read)?;
        let inner = self.inner.read().await;
        Ok(BackupList {
            backups: inner.backups.clone(),
        })
    }

    async fn backup_now(&self, caller: &CallerIdentity) -> Result<BackupInfo, ApiError> {
        Self::require_scope(caller, Scope::Plan)?;
        let mut inner = self.inner.write().await;
        inner.next_job += 1;
        let info = BackupInfo {
            id: format!("sim-{}", inner.next_job),
            created_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "unknown".into()),
        };
        inner.backups.push(info.clone());
        Ok(info)
    }

    async fn read_fields(
        &self,
        caller: &CallerIdentity,
        req: ReadFieldsRequest,
    ) -> Result<ReadFieldsResponse, ApiError> {
        Self::require_scope(caller, Scope::Read)?;
        Ok(ReadFieldsResponse {
            fields: vec![FieldValue {
                name: format!("table_{:02x}_rec_{}", req.table, req.record),
                value: "simulated".into(),
            }],
        })
    }

    async fn plan_change(
        &self,
        caller: &CallerIdentity,
        req: PlanChangeRequest,
    ) -> Result<PlanSummary, ApiError> {
        Self::require_scope(caller, Scope::Plan)?;
        let inner = self.inner.read().await;
        let profile = inner.profile.clone();
        drop(inner);
        let creator = caller.token_id().cloned();
        let plan = ImmutablePlan::from_request(profile, req, creator)?;
        let summary_text = format!("{} → {}", plan.request.field, plan.request.new_value);
        let requested_by = caller.token_id().map(|id| RequestedBy {
            agent: match caller {
                CallerIdentity::Mcp(t) => t.agent_name.clone(),
                _ => "admin".into(),
            },
            token_id: id.clone(),
        });
        let plan_id = plan.id;
        let diff_hash = plan.diff_hash.clone();
        let summary = plan_summary_from(&plan_id, &diff_hash, &summary_text, &requested_by, &plan);
        let mut inner = self.inner.write().await;
        inner.plans.insert(Self::plan_key(&plan_id), plan);
        Ok(summary)
    }

    async fn submit_approval(
        &self,
        caller: &CallerIdentity,
        plan_id_or_prefix: &str,
    ) -> Result<Approval, ApiError> {
        Self::require_scope(caller, Scope::Approve)?;
        let approver = caller.token_id().cloned().ok_or(ApiError::ForbiddenScope)?;
        let mut inner = self.inner.write().await;
        let plan_id = Self::resolve_plan_id(&inner.plans, plan_id_or_prefix)?;
        let plan = inner
            .plans
            .get(&Self::plan_key(&plan_id))
            .ok_or(ApiError::PlanNotFound)?;
        if plan.is_expired(plan_storage_ttl()) {
            return Err(ApiError::PlanExpired);
        }
        let requester = plan
            .creator_token
            .clone()
            .ok_or(ApiError::BadRequest("plan has no requester token"))?;
        if requester == approver {
            return Err(ApiError::ApproverMustDiffer);
        }
        let diff_hash = plan.diff_hash.clone();
        let rate = inner
            .submit_rates
            .entry(approver.0.clone())
            .or_insert_with(|| SubmitRateState {
                hour_window: Instant::now(),
                hour_count: 0,
                day_window: Instant::now(),
                day_count: 0,
            });
        Self::check_submit_rate(rate)?;
        let approval = Approval::new(plan_id, diff_hash, inner.profile.clone(), approver.clone());
        inner.plan_approvals.insert(
            approval.id.0.clone(),
            StoredApproval {
                approval: approval.clone(),
                consumed: false,
            },
        );
        Ok(approval)
    }

    async fn apply_plan(
        &self,
        caller: &CallerIdentity,
        plan_id: PlanId,
        diff_hash: DiffHash,
    ) -> Result<ApplyJob, ApiError> {
        Self::require_scope(caller, Scope::Write)?;
        let mut inner = self.inner.write().await;
        if inner.profile == Profile::prod() && !inner.live_writes_approved {
            return Err(ApiError::LiveWritesBlocked);
        }
        {
            let plan = inner
                .plans
                .get(&Self::plan_key(&plan_id))
                .ok_or(ApiError::PlanNotFound)?;
            if plan.diff_hash != diff_hash {
                return Err(ApiError::InvalidApproval);
            }
        }
        let profile = inner.profile.clone();
        let mode = inner.mode;

        if mode == Mode::Production {
            let key = inner.plan_approvals.iter().find_map(|(id, stored)| {
                Self::validate_plan_approval(stored, plan_id, &diff_hash, &profile).ok()?;
                Some(id.clone())
            });
            let Some(approval_key) = key else {
                return Err(ApiError::ApprovalRequired {
                    plan_id,
                    diff_hash,
                    status: "approval_required",
                });
            };
            let stored = inner
                .plan_approvals
                .get_mut(&approval_key)
                .ok_or(ApiError::InvalidApproval)?;
            stored.consumed = true;
        }

        inner.next_job += 1;
        Ok(ApplyJob {
            job_id: JobId(format!("job-{}", inner.next_job)),
            state: JobState::Succeeded,
            message: "simulated apply".into(),
        })
    }

    async fn rollback(&self, caller: &CallerIdentity, job_id: JobId) -> Result<ApplyJob, ApiError> {
        Self::require_scope(caller, Scope::Write)?;
        if job_id.0.is_empty() {
            return Err(ApiError::JobNotFound);
        }
        Ok(ApplyJob {
            job_id,
            state: JobState::Succeeded,
            message: "simulated rollback".into(),
        })
    }

    fn verify_admin_password(&self, password: &str) -> bool {
        Self::verify_password(&self.admin_hash, password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_id::TokenId;

    #[test]
    fn ambiguous_plan_prefix_is_rejected() {
        let mut plans = HashMap::new();
        plans.insert(
            "aabbccdd1111111111111111111111".into(),
            ImmutablePlan::from_request(
                Profile::test(),
                PlanChangeRequest {
                    table: 0x24,
                    record: 1,
                    field: "f".into(),
                    new_value: "v".into(),
                    base_bytes: vec![],
                    new_bytes: vec![1],
                },
                Some(TokenId("r".into())),
            )
            .expect("plan"),
        );
        plans.insert(
            "aabbccdd2222222222222222222222".into(),
            ImmutablePlan::from_request(
                Profile::test(),
                PlanChangeRequest {
                    table: 0x24,
                    record: 2,
                    field: "f".into(),
                    new_value: "v".into(),
                    base_bytes: vec![],
                    new_bytes: vec![2],
                },
                Some(TokenId("r".into())),
            )
            .expect("plan"),
        );
        assert!(matches!(
            MockDaemon::resolve_plan_id(&plans, "aabbccdd"),
            Err(ApiError::AmbiguousPlanPrefix)
        ));
    }
}
