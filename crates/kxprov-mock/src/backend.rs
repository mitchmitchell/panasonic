use async_trait::async_trait;
use kxprov_api::{Approval, DiffHash, PlanId, Profile};

use crate::error::BackendError;
use crate::identity::CallerIdentity;
use crate::types::{
    ApplyJob, BackupInfo, BackupList, DaemonStatus, JobId, PlanChangeRequest, PlanSummary,
    ReadFieldsRequest, ReadFieldsResponse,
};

#[async_trait]
pub trait DaemonBackend: Send + Sync {
    async fn status(&self, caller: &CallerIdentity) -> Result<DaemonStatus, BackendError>;

    async fn list_backups(&self, caller: &CallerIdentity) -> Result<BackupList, BackendError>;

    async fn backup_now(&self, caller: &CallerIdentity) -> Result<BackupInfo, BackendError>;

    async fn read_fields(
        &self,
        caller: &CallerIdentity,
        req: ReadFieldsRequest,
    ) -> Result<ReadFieldsResponse, BackendError>;

    async fn plan_change(
        &self,
        caller: &CallerIdentity,
        req: PlanChangeRequest,
    ) -> Result<PlanSummary, BackendError>;

    async fn submit_approval(
        &self,
        caller: &CallerIdentity,
        plan_id_or_prefix: &str,
        diff_hash: DiffHash,
        profile: Profile,
    ) -> Result<Approval, BackendError>;

    async fn apply_plan(
        &self,
        caller: &CallerIdentity,
        plan_id: PlanId,
        diff_hash: DiffHash,
    ) -> Result<ApplyJob, BackendError>;

    async fn rollback(&self, caller: &CallerIdentity, job_id: JobId) -> Result<ApplyJob, BackendError>;
}
