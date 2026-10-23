use kxprov_api::{
    ApplyPlanParams, ArmPlanParams, FieldKindWire, PlanChangeParams, ReadFieldsParams, Scope,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{mpsc, oneshot, Mutex};

static JOB_COUNTER: AtomicU64 = AtomicU64::new(1);

pub fn next_job_id() -> String {
    format!("j{}", JOB_COUNTER.fetch_add(1, Ordering::Relaxed))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Queued,
    Running,
    Done,
    Failed,
}

#[derive(Debug)]
pub enum JobKind {
    ReadFields { params: ReadFieldsParams },
    PlanChange { params: PlanChangeParams },
    ArmPlan { params: ArmPlanParams },
    BackupNow,
    ApplyPlan { params: ApplyPlanParams },
}

pub struct JobRequest {
    pub id: String,
    pub kind: JobKind,
    pub need: Scope,
    pub reply: oneshot::Sender<JobOutcome>,
}

#[derive(Debug)]
pub enum JobOutcome {
    ReadFields(kxprov_api::ReadFieldsResult),
    PlanChange(kxprov_api::PlanChangeResult),
    ArmPlan(kxprov_api::ArmPlanResult),
    BackupNow(kxprov_api::BackupNowResult),
    ApplyDeferred(kxprov_api::ApplyDeferredResult),
    Err { code: String, message: String },
}

pub struct JobQueue {
    tx: mpsc::Sender<JobRequest>,
    pub jobs: Mutex<HashMap<String, JobState>>,
}

impl JobQueue {
    pub fn new(tx: mpsc::Sender<JobRequest>) -> Self {
        Self {
            tx,
            jobs: Mutex::new(HashMap::new()),
        }
    }

    pub async fn enqueue(
        &self,
        need: Scope,
        kind: JobKind,
    ) -> Result<(String, oneshot::Receiver<JobOutcome>), ()> {
        let id = next_job_id();
        let (reply_tx, reply_rx) = oneshot::channel();
        self.jobs.lock().await.insert(id.clone(), JobState::Queued);
        self.tx
            .send(JobRequest {
                id: id.clone(),
                kind,
                need,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ())?;
        Ok((id, reply_rx))
    }

    pub async fn set_state(&self, id: &str, state: JobState) {
        self.jobs.lock().await.insert(id.to_string(), state);
    }

    pub async fn depth(&self) -> u32 {
        self.jobs
            .lock()
            .await
            .values()
            .filter(|s| **s == JobState::Queued)
            .count() as u32
    }

    pub async fn active(&self) -> Option<String> {
        self.jobs
            .lock()
            .await
            .iter()
            .find(|(_, s)| **s == JobState::Running)
            .map(|(id, _)| id.clone())
    }
}

pub fn field_kind_wire(w: FieldKindWire) -> kxtd1232::FieldKind {
    match w {
        FieldKindWire::CidName => kxtd1232::FieldKind::CidName,
        FieldKindWire::CidNumber => kxtd1232::FieldKind::CidNumber,
        FieldKindWire::ExtName => kxtd1232::FieldKind::ExtName,
    }
}
