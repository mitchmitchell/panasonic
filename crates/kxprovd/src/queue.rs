use kxprov_api::{
    DiffHash, FieldKindWire, PlanChangeParams, PlanId, ReadFieldsParams, TokenId,
    TOKEN_JOBS_PER_MINUTE, TOKEN_QUEUE_DEPTH_MAX,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex as StdMutex;
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
    ReadFields {
        params: ReadFieldsParams,
    },
    PlanChange {
        params: PlanChangeParams,
        token_id: TokenId,
    },
    BackupNow {
        operational_mode: kxprov_api::OperationalMode,
    },
    ApplyPlan {
        plan_id: PlanId,
        diff_hash: DiffHash,
        token_id: TokenId,
    },
}

pub struct JobRequest {
    pub id: String,
    pub kind: JobKind,
    pub token_id: Option<TokenId>,
    pub reply: oneshot::Sender<JobOutcome>,
}

#[derive(Debug)]
pub enum JobOutcome {
    ReadFields(kxprov_api::ReadFieldsResult),
    PlanChange(kxprov_api::PlanChangeResult),
    BackupNow(kxprov_api::BackupNowResult),
    ApplyPlan {
        plan_id: PlanId,
        diff_hash: DiffHash,
    },
    Err {
        code: String,
        message: String,
    },
}

#[derive(Default)]
struct TokenRateState {
    active: u32,
    start_times_ms: VecDeque<u64>,
}

pub struct JobQueue {
    tx: mpsc::Sender<JobRequest>,
    pub jobs: Mutex<HashMap<String, JobState>>,
    token_rates: Mutex<HashMap<String, TokenRateState>>,
    /// Tokens revoked on disk; queued jobs for these ids fail without running.
    revoked_tokens: StdMutex<HashSet<String>>,
}

impl JobQueue {
    pub fn new(tx: mpsc::Sender<JobRequest>) -> Self {
        Self {
            tx,
            jobs: Mutex::new(HashMap::new()),
            token_rates: Mutex::new(HashMap::new()),
            revoked_tokens: StdMutex::new(HashSet::new()),
        }
    }

    pub fn mark_token_revoked(&self, token_id: &TokenId) {
        self.revoked_tokens
            .lock()
            .expect("revoked tokens lock")
            .insert(token_id.as_str().to_string());
    }

    pub fn is_token_revoked(&self, token_id: &TokenId) -> bool {
        self.revoked_tokens
            .lock()
            .expect("revoked tokens lock")
            .contains(token_id.as_str())
    }

    pub fn clear_token_revoked(&self, token_id: &TokenId) {
        self.revoked_tokens
            .lock()
            .expect("revoked tokens lock")
            .remove(token_id.as_str());
    }

    pub async fn enqueue(
        &self,
        kind: JobKind,
        token_id: Option<TokenId>,
        now_ms: u64,
    ) -> Result<(String, oneshot::Receiver<JobOutcome>), QueueError> {
        let id = next_job_id();
        let (reply_tx, reply_rx) = oneshot::channel();
        if let Some(ref tid) = token_id {
            let mut rates = self.token_rates.lock().await;
            let st = rates.entry(tid.as_str().to_string()).or_default();
            if st.active >= TOKEN_QUEUE_DEPTH_MAX {
                return Err(QueueError::RateLimit);
            }
            let minute_ago = now_ms.saturating_sub(60_000);
            while st.start_times_ms.front().is_some_and(|t| *t < minute_ago) {
                st.start_times_ms.pop_front();
            }
            if st.start_times_ms.len() as u32 >= TOKEN_JOBS_PER_MINUTE {
                return Err(QueueError::RateLimit);
            }
            st.active += 1;
            st.start_times_ms.push_back(now_ms);
        }
        self.jobs.lock().await.insert(id.clone(), JobState::Queued);
        if self
            .tx
            .send(JobRequest {
                id: id.clone(),
                kind,
                token_id: token_id.clone(),
                reply: reply_tx,
            })
            .await
            .is_err()
        {
            if let Some(ref tid) = token_id {
                let mut rates = self.token_rates.lock().await;
                if let Some(st) = rates.get_mut(tid.as_str()) {
                    st.active = st.active.saturating_sub(1);
                    let _ = st.start_times_ms.pop_back();
                }
            }
            self.jobs.lock().await.remove(&id);
            return Err(QueueError::Shutdown);
        }
        Ok((id, reply_rx))
    }

    pub async fn release_token(&self, token_id: Option<&TokenId>) {
        if let Some(tid) = token_id {
            let mut rates = self.token_rates.lock().await;
            if let Some(st) = rates.get_mut(tid.as_str()) {
                st.active = st.active.saturating_sub(1);
            }
        }
    }

    pub async fn set_state(&self, id: &str, state: JobState) {
        let mut jobs = self.jobs.lock().await;
        if matches!(state, JobState::Done | JobState::Failed) {
            jobs.remove(id);
        } else {
            jobs.insert(id.to_string(), state);
        }
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

    pub async fn is_idle(&self) -> bool {
        self.jobs
            .lock()
            .await
            .values()
            .all(|s| !matches!(s, JobState::Queued | JobState::Running))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    Shutdown,
    RateLimit,
}

pub fn field_kind_wire(w: FieldKindWire) -> kxtd1232::FieldKind {
    match w {
        FieldKindWire::CidName => kxtd1232::FieldKind::CidName,
        FieldKindWire::CidNumber => kxtd1232::FieldKind::CidNumber,
        FieldKindWire::ExtName => kxtd1232::FieldKind::ExtName,
    }
}
