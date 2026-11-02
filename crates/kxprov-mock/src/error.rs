use kxprov_api::ApplyApprovalRequiredResult;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackendError {
    #[error("forbidden: insufficient scope")]
    ForbiddenScope,
    #[error("forbidden: admin web session required")]
    ForbiddenAdmin,
    #[error("unauthorized")]
    Unauthorized,
    #[error("approval required")]
    ApprovalRequired(ApplyApprovalRequiredResult),
    #[error("approval invalid or expired")]
    InvalidApproval,
    #[error("approver must differ from plan requester")]
    ApproverMustDiffer,
    #[error("approval submit rate limit exceeded")]
    ApprovalRateLimited,
    #[error("invalid scope combination")]
    InvalidScopeSet,
    #[error("ambiguous plan id prefix")]
    AmbiguousPlanPrefix,
    #[error("plan not found")]
    PlanNotFound,
    #[error("plan or approval window expired")]
    PlanExpired,
    #[error("live writes not approved")]
    LiveWritesBlocked,
    #[error("table {table} record {record} not returned by the phone system")]
    RecordNotFound { table: u8, record: u16 },
    #[error("job not found")]
    JobNotFound,
    #[error("invalid request: {0}")]
    BadRequest(&'static str),
    #[error("phone system port unavailable")]
    PbxTransport,
    #[error("phone system did not complete the exchange")]
    PbxProtocol,
    #[error("call log: {0}")]
    CallLog(kxprov_api::SmdrApiError),
}
