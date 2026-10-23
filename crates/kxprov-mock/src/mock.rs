use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use async_trait::async_trait;
use kxprov_api::{
    ApplyApprovalRequiredResult, ApplyPlanAwaitingStatus, Approval, DiffHash, OperationalMode,
    PlanId, Profile, Scope,
};
use time::OffsetDateTime;
use tokio::sync::RwLock;

use crate::backend::DaemonBackend;
use crate::error::BackendError;
use crate::identity::CallerIdentity;
use crate::plan::{approval_ttl, plan_id_from_hex, plan_storage_ttl, ImmutablePlan};
use crate::types::{
    ApplyJob, BackupInfo, BackupList, DaemonStatus, FieldValue, JobId, JobState,
    PlanChangeRequest, PlanSummary, ReadFieldsRequest, ReadFieldsResponse,
};
use crate::write_gates::prod_profile_write_gates_active;

pub const APPROVAL_SUBMIT_LIMIT_PER_HOUR: u32 = 5;
pub const APPROVAL_SUBMIT_LIMIT_PER_DAY: u32 = 20;

struct StoredApproval {
    approval: Approval,
}

struct SubmitRateState {
    hour_window: Instant,
    hour_count: u32,
    day_window: Instant,
    day_count: u32,
}

struct Inner {
    profile: Profile,
    operational_mode: OperationalMode,
    plans: HashMap<String, ImmutablePlan>,
    plan_approvals: HashMap<String, StoredApproval>,
    submit_rates: HashMap<String, SubmitRateState>,
    backups: Vec<BackupInfo>,
    next_job: u64,
    live_writes_approved: bool,
}

pub struct MockDaemon {
    inner: Arc<RwLock<Inner>>,
}

impl MockDaemon {
    pub fn new() -> Self {
        Self::with_operational_mode(OperationalMode::Testing)
    }

    pub fn with_operational_mode(mode: OperationalMode) -> Self {
        Self::with_mode_profile(mode, Profile::Test)
    }

    /// Compatibility helper for tests that previously passed an admin password.
    pub fn with_mode_and_password(mode: OperationalMode, _password: &str) -> Self {
        Self::with_operational_mode(mode)
    }

    pub fn with_profile(profile: Profile) -> Self {
        Self::with_mode_profile(OperationalMode::Production, profile)
    }

    pub async fn test_set_live_writes_approved(&self, approved: bool) {
        self.inner.write().await.live_writes_approved = approved;
    }

    pub fn with_mode_profile(operational_mode: OperationalMode, profile: Profile) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner {
                profile,
                operational_mode,
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

    fn require_scope(caller: &CallerIdentity, scope: Scope) -> Result<(), BackendError> {
        if caller.scopes().contains(scope) {
            Ok(())
        } else {
            Err(BackendError::ForbiddenScope)
        }
    }

    fn plan_key(id: &PlanId) -> String {
        id.0.clone()
    }

    fn resolve_plan_id(
        plans: &HashMap<String, ImmutablePlan>,
        plan_id_or_prefix: &str,
    ) -> Result<PlanId, BackendError> {
        let id = plan_id_or_prefix.trim();
        if id.len() == 32 {
            return plan_id_from_hex(id);
        }
        if id.len() == 8 {
            let matches: Vec<&String> = plans.keys().filter(|k| k.starts_with(id)).collect();
            return match matches.len() {
                0 => Err(BackendError::PlanNotFound),
                1 => plan_id_from_hex(matches[0]),
                _ => Err(BackendError::AmbiguousPlanPrefix),
            };
        }
        Err(BackendError::BadRequest("plan_id"))
    }

    fn validate_plan_approval(
        stored: &StoredApproval,
        plan_id: &PlanId,
        diff_hash: &DiffHash,
        profile: Profile,
        now_ms: u64,
    ) -> Result<(), BackendError> {
        if stored.approval.consumed {
            return Err(BackendError::InvalidApproval);
        }
        if !stored.approval.active(now_ms, profile) {
            return Err(BackendError::InvalidApproval);
        }
        if !stored.approval.matches(plan_id, diff_hash, profile) {
            return Err(BackendError::InvalidApproval);
        }
        Ok(())
    }

    fn check_submit_rate(state: &mut SubmitRateState) -> Result<(), BackendError> {
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
            return Err(BackendError::ApprovalRateLimited);
        }
        state.hour_count += 1;
        state.day_count += 1;
        Ok(())
    }

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

fn now_ms() -> u64 {
    OffsetDateTime::now_utc().unix_timestamp() as u64 * 1000
}

fn expires_at_ms_from_ttl(ttl: time::Duration) -> u64 {
    (OffsetDateTime::now_utc() + ttl).unix_timestamp() as u64 * 1000
}

#[async_trait]
impl DaemonBackend for MockDaemon {
    async fn status(&self, caller: &CallerIdentity) -> Result<DaemonStatus, BackendError> {
        Self::require_scope(caller, Scope::Read)?;
        let inner = self.inner.read().await;
        Ok(DaemonStatus {
            profile: inner.profile,
            operational_mode: inner.operational_mode,
            locked: false,
            live_writes_approved: inner.live_writes_approved,
            queue_depth: 0,
        })
    }

    async fn list_backups(&self, caller: &CallerIdentity) -> Result<BackupList, BackendError> {
        Self::require_scope(caller, Scope::Read)?;
        let inner = self.inner.read().await;
        Ok(BackupList {
            backups: inner.backups.clone(),
        })
    }

    async fn backup_now(&self, caller: &CallerIdentity) -> Result<BackupInfo, BackendError> {
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
    ) -> Result<ReadFieldsResponse, BackendError> {
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
    ) -> Result<PlanSummary, BackendError> {
        Self::require_scope(caller, Scope::Plan)?;
        let inner = self.inner.read().await;
        let profile = inner.profile;
        drop(inner);
        let creator = caller.token_id().cloned();
        let plan = ImmutablePlan::from_request(profile, req, creator)?;
        let summary_text = format!("{} → {}", plan.request.field, plan.request.new_value);
        let plan_id = plan.id.clone();
        let diff_hash = plan.diff_hash.clone();
        let expires_at = (plan.stored_at + plan_storage_ttl())
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".into());
        let summary = PlanSummary {
            plan_id: plan_id.clone(),
            diff_hash,
            summary: summary_text,
            expires_at,
        };
        let mut inner = self.inner.write().await;
        inner.plans.insert(Self::plan_key(&plan_id), plan);
        Ok(summary)
    }

    async fn submit_approval(
        &self,
        caller: &CallerIdentity,
        plan_id_or_prefix: &str,
        diff_hash: DiffHash,
        profile: Profile,
    ) -> Result<Approval, BackendError> {
        Self::require_scope(caller, Scope::Approve)?;
        let approver = caller.token_id().cloned().ok_or(BackendError::ForbiddenScope)?;
        let mut inner = self.inner.write().await;
        let plan_id = Self::resolve_plan_id(&inner.plans, plan_id_or_prefix)?;
        let plan = inner
            .plans
            .get(&Self::plan_key(&plan_id))
            .ok_or(BackendError::PlanNotFound)?;
        if plan.diff_hash != diff_hash {
            return Err(BackendError::InvalidApproval);
        }
        if plan.profile != profile {
            return Err(BackendError::BadRequest("profile mismatch"));
        }
        if plan.is_expired(plan_storage_ttl()) {
            return Err(BackendError::PlanExpired);
        }
        let requester = plan
            .creator_token
            .clone()
            .ok_or(BackendError::BadRequest("plan has no requester token"))?;
        if requester == approver {
            return Err(BackendError::ApproverMustDiffer);
        }
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
        let approval = Approval {
            plan_id,
            diff_hash,
            profile: inner.profile,
            approver_token: approver,
            expires_at_ms: expires_at_ms_from_ttl(approval_ttl()),
            consumed: false,
        };
        inner
            .plan_approvals
            .insert(approval.plan_id.0.clone(), StoredApproval { approval: approval.clone() });
        Ok(approval)
    }

    async fn apply_plan(
        &self,
        caller: &CallerIdentity,
        plan_id: PlanId,
        diff_hash: DiffHash,
    ) -> Result<ApplyJob, BackendError> {
        Self::require_scope(caller, Scope::Write)?;
        let mut inner = self.inner.write().await;
        let active_profile = inner.profile;
        if prod_profile_write_gates_active(active_profile) && !inner.live_writes_approved {
            return Err(BackendError::LiveWritesBlocked);
        }
        {
            let plan = inner
                .plans
                .get(&Self::plan_key(&plan_id))
                .ok_or(BackendError::PlanNotFound)?;
            if plan.diff_hash != diff_hash {
                return Err(BackendError::InvalidApproval);
            }
        }
        if prod_profile_write_gates_active(active_profile) {
            let now = now_ms();
            let key = inner.plan_approvals.iter().find_map(|(id, stored)| {
                Self::validate_plan_approval(stored, &plan_id, &diff_hash, active_profile, now).ok()?;
                Some(id.clone())
            });
            let Some(approval_key) = key else {
                return Err(BackendError::ApprovalRequired(
                    ApplyApprovalRequiredResult {
                        plan_id,
                        diff_hash,
                        status: ApplyPlanAwaitingStatus::ApprovalRequired,
                    },
                ));
            };
            let stored = inner
                .plan_approvals
                .get_mut(&approval_key)
                .ok_or(BackendError::InvalidApproval)?;
            stored.approval.consumed = true;
        }

        inner.next_job += 1;
        Ok(ApplyJob {
            job_id: JobId(format!("job-{}", inner.next_job)),
            state: JobState::Succeeded,
            message: "simulated apply".into(),
        })
    }

    async fn rollback(&self, caller: &CallerIdentity, job_id: JobId) -> Result<ApplyJob, BackendError> {
        Self::require_scope(caller, Scope::Write)?;
        if job_id.0.is_empty() {
            return Err(BackendError::JobNotFound);
        }
        Ok(ApplyJob {
            job_id,
            state: JobState::Succeeded,
            message: "simulated rollback".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kxprov_api::TokenId;

    #[test]
    fn ambiguous_plan_prefix_is_rejected() {
        let mut plans = HashMap::new();
        plans.insert(
            "aabbccdd1111111111111111111111".into(),
            ImmutablePlan::from_request(
                Profile::Test,
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
                Profile::Test,
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
            Err(BackendError::AmbiguousPlanPrefix)
        ));
    }
}
