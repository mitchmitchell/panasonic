use async_trait::async_trait;

use crate::approval::Approval;
use crate::error::ApiError;
use crate::identity::CallerIdentity;
use crate::plan::{DiffHash, PlanId};
use crate::types::{
    ApplyJob, BackupInfo, BackupList, DaemonStatus, JobId, PlanChangeRequest, PlanSummary,
    ReadFieldsRequest, ReadFieldsResponse,
};

/// Unix-socket API surface. The daemon is the trust boundary (F2); the gateway forwards calls verbatim.
#[async_trait]
pub trait DaemonBackend: Send + Sync {
    async fn status(&self, caller: &CallerIdentity) -> Result<DaemonStatus, ApiError>;

    async fn list_backups(&self, caller: &CallerIdentity) -> Result<BackupList, ApiError>;

    /// `plan` scope — schedules backup work but does not apply field writes (§13 Q5).
    async fn backup_now(&self, caller: &CallerIdentity) -> Result<BackupInfo, ApiError>;

    async fn read_fields(
        &self,
        caller: &CallerIdentity,
        req: ReadFieldsRequest,
    ) -> Result<ReadFieldsResponse, ApiError>;

    async fn plan_change(
        &self,
        caller: &CallerIdentity,
        req: PlanChangeRequest,
    ) -> Result<PlanSummary, ApiError>;

    /// Admin re-auth proof forwarded by the gateway; only the daemon mints approvals (F2).
    async fn mint_plan_approval(
        &self,
        caller: &CallerIdentity,
        plan_id: PlanId,
        diff_hash: DiffHash,
        admin_password: &str,
    ) -> Result<Approval, ApiError>;

    async fn mint_rollback_approval(
        &self,
        caller: &CallerIdentity,
        job_id: JobId,
        admin_password: &str,
    ) -> Result<Approval, ApiError>;

    /// Consumes a live approval for `(plan_id, diff_hash, profile)` or returns `approval_required`.
    async fn apply_plan(
        &self,
        caller: &CallerIdentity,
        plan_id: PlanId,
        diff_hash: DiffHash,
    ) -> Result<ApplyJob, ApiError>;

    async fn rollback(&self, caller: &CallerIdentity, job_id: JobId) -> Result<ApplyJob, ApiError>;

    /// Daemon-owned admin password verification for setup/tests (production: hash only on daemon).
    fn verify_admin_password(&self, password: &str) -> bool;
}
