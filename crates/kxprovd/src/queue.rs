use crate::job_principal::JobPrincipal;
use crate::rate_limit::{RateLimitError, TokenRateState};
use kxprov_api::{DiffHash, FieldKindWire, PlanChangeParams, PlanId, ReadFieldsParams, TokenId};
use std::collections::HashMap;
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
    pub principal: Option<JobPrincipal>,
    /// Snapshot of per-token job epoch at enqueue; stale jobs fail after revoke/rotate.
    pub token_epoch: u64,
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

pub struct JobQueue {
    tx: mpsc::Sender<JobRequest>,
    pub jobs: Mutex<HashMap<String, JobState>>,
    token_rates: Mutex<HashMap<String, TokenRateState>>,
    /// Bumped when a token is revoked or reactivated (rotate); jobs with older epochs fail.
    token_epochs: StdMutex<HashMap<String, u64>>,
}

impl JobQueue {
    pub fn new(tx: mpsc::Sender<JobRequest>) -> Self {
        Self {
            tx,
            jobs: Mutex::new(HashMap::new()),
            token_rates: Mutex::new(HashMap::new()),
            token_epochs: StdMutex::new(HashMap::new()),
        }
    }

    pub fn bump_token_epoch(&self, token_id: &TokenId) {
        let mut epochs = self.token_epochs.lock().expect("token epochs lock");
        *epochs.entry(token_id.as_str().to_string()).or_insert(0) += 1;
    }

    pub fn token_epoch(&self, token_id: &TokenId) -> u64 {
        self.token_epochs
            .lock()
            .expect("token epochs lock")
            .get(token_id.as_str())
            .copied()
            .unwrap_or(0)
    }

    pub async fn enqueue(
        &self,
        kind: JobKind,
        principal: Option<JobPrincipal>,
        now_ms: u64,
    ) -> Result<(String, oneshot::Receiver<JobOutcome>), QueueError> {
        let id = next_job_id();
        let (reply_tx, reply_rx) = oneshot::channel();
        let token_epoch = principal
            .as_ref()
            .and_then(|p| p.token_id())
            .map(|t| self.token_epoch(t))
            .unwrap_or(0);
        if let Some(ref p) = principal {
            if let Some(key) = p.rate_limit_key() {
                let mut rates = self.token_rates.lock().await;
                let st = rates.entry(key).or_default();
                st.try_reserve(now_ms).map_err(|e| match e {
                    RateLimitError::QueueDepth | RateLimitError::JobsPerMinute => {
                        QueueError::RateLimit
                    }
                })?;
            }
        }
        self.jobs.lock().await.insert(id.clone(), JobState::Queued);
        if self
            .tx
            .send(JobRequest {
                id: id.clone(),
                kind,
                principal: principal.clone(),
                token_epoch,
                reply: reply_tx,
            })
            .await
            .is_err()
        {
            if let Some(ref p) = principal {
                if let Some(key) = p.rate_limit_key() {
                    let mut rates = self.token_rates.lock().await;
                    if let Some(st) = rates.get_mut(&key) {
                        st.rollback_reserve();
                    }
                }
            }
            self.jobs.lock().await.remove(&id);
            return Err(QueueError::Shutdown);
        }
        Ok((id, reply_rx))
    }

    pub async fn release_token(&self, principal: Option<&JobPrincipal>) {
        if let Some(p) = principal {
            if let Some(key) = p.rate_limit_key() {
                let mut rates = self.token_rates.lock().await;
                if let Some(st) = rates.get_mut(&key) {
                    st.complete();
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job_principal::JobPrincipal;
    use crate::rate_limit::QUEUE_DEPTH_MAX;
    use kxprov_api::ReadFieldsParams;

    #[tokio::test]
    async fn local_uids_use_separate_rate_buckets() {
        let (tx, _rx) = mpsc::channel(64);
        let q = JobQueue::new(tx);
        let now = 3_000_000u64;
        let p100 = JobPrincipal::SyntheticLocal { uid: 100 };
        let p200 = JobPrincipal::SyntheticLocal { uid: 200 };
        let kind = || JobKind::ReadFields {
            params: ReadFieldsParams {
                kind: FieldKindWire::CidName,
                first: 0,
                count: 1,
            },
        };
        for _ in 0..QUEUE_DEPTH_MAX {
            q.enqueue(kind(), Some(p100.clone()), now)
                .await
                .expect("uid 100 under cap");
        }
        assert!(matches!(
            q.enqueue(kind(), Some(p100.clone()), now).await,
            Err(QueueError::RateLimit)
        ));
        q.enqueue(kind(), Some(p200.clone()), now)
            .await
            .expect("uid 200 has its own bucket");
    }
}
