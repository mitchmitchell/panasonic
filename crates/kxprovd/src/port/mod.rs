#[cfg(target_os = "linux")]
pub mod device;
pub mod journal;

use crate::smdr_reader::SmdrSource;
use journal::{LeaseEvent, LeaseJournal};
use kxtd1232::{Transport, TransportError};
use kxtd1232_sim::SimTransport;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const POISON_RECOVERY_REASON: &str = "each port critical section only swaps the transport Option, the holder and the waiter count, so a panic cannot leave a half-applied update; refusing every later lease and read would take the port down for nothing";

fn recover_from_poison<G>(poisoned: std::sync::PoisonError<G>) -> G {
    tracing::warn!(
        reason = POISON_RECOVERY_REASON,
        "port lock was poisoned; continuing"
    );
    poisoned.into_inner()
}

pub const DEFAULT_MAX_LEASE_WAITERS: usize = 4;
pub const DEFAULT_LEASE_TIMEOUT: Duration = Duration::from_secs(30);

pub trait SimRelease: Transport {
    fn bye_and_dtr_cycle(&mut self) -> Result<(), TransportError>;
}

impl SimRelease for SimTransport {
    fn bye_and_dtr_cycle(&mut self) -> Result<(), TransportError> {
        let sent = self.send(b"BYE\r\n");
        self.reconnect();
        sent
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LeaseError {
    #[error("programming lease queue full ({max} waiters)")]
    QueueFull { max: usize },
    #[error("programming lease not granted within {waited_ms} ms")]
    Timeout { waited_ms: u64 },
    #[error("lease journal: {0}")]
    Journal(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMode {
    Smdr,
    Programming,
}

struct State<T> {
    transport: Option<T>,
    waiters: usize,
    holder: Option<String>,
}

struct Shared<T> {
    state: Mutex<State<T>>,
    returned: Condvar,
    journal: Mutex<LeaseJournal>,
    max_waiters: usize,
}

impl<T> Shared<T> {
    fn lock(&self) -> MutexGuard<'_, State<T>> {
        self.state.lock().unwrap_or_else(recover_from_poison)
    }

    fn record(&self, event: LeaseEvent, job_id: &str) -> std::io::Result<()> {
        self.journal
            .lock()
            .unwrap_or_else(recover_from_poison)
            .append(event, job_id)
    }
}

pub struct PortManager<T: SimRelease> {
    shared: Arc<Shared<T>>,
}

impl<T: SimRelease> PortManager<T> {
    pub fn new(transport: T, journal: LeaseJournal, max_waiters: usize) -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    transport: Some(transport),
                    waiters: 0,
                    holder: None,
                }),
                returned: Condvar::new(),
                journal: Mutex::new(journal),
                max_waiters,
            }),
        }
    }

    pub fn mode(&self) -> PortMode {
        if self.shared.lock().transport.is_some() {
            PortMode::Smdr
        } else {
            PortMode::Programming
        }
    }

    pub fn smdr_handle(&self) -> SmdrHandle<T> {
        SmdrHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    pub fn request_lease(
        &self,
        job_id: &str,
        timeout: Duration,
    ) -> Result<ProgrammingLease<T>, LeaseError> {
        self.shared.record(LeaseEvent::Requested, job_id)?;
        let mut state = self.shared.lock();
        if state.transport.is_none() && state.waiters >= self.shared.max_waiters {
            drop(state);
            self.shared.record(LeaseEvent::Refused, job_id)?;
            return Err(LeaseError::QueueFull {
                max: self.shared.max_waiters,
            });
        }
        state.waiters += 1;
        let start = Instant::now();
        let (mut state, wait) = self
            .shared
            .returned
            .wait_timeout_while(state, timeout, |s| s.transport.is_none())
            .unwrap_or_else(recover_from_poison);
        state.waiters -= 1;
        let Some(transport) = state.transport.take().filter(|_| !wait.timed_out()) else {
            drop(state);
            self.shared.record(LeaseEvent::TimedOut, job_id)?;
            return Err(LeaseError::Timeout {
                waited_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
            });
        };
        state.holder = Some(job_id.to_string());
        drop(state);
        self.shared.record(LeaseEvent::Granted, job_id)?;
        self.shared.record(LeaseEvent::ReaderPaused, job_id)?;
        Ok(ProgrammingLease {
            shared: Arc::clone(&self.shared),
            transport: Some(transport),
            job_id: job_id.to_string(),
        })
    }

    pub fn inspect_transport<R>(&self, f: impl FnOnce(&T) -> R) -> Option<R> {
        self.shared.lock().transport.as_ref().map(f)
    }

    pub fn holder(&self) -> Option<String> {
        self.shared.lock().holder.clone()
    }
}

pub struct ProgrammingLease<T: SimRelease> {
    shared: Arc<Shared<T>>,
    transport: Option<T>,
    job_id: String,
}

impl<T: SimRelease> ProgrammingLease<T> {
    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    pub fn release(mut self) -> Result<(), PortReleaseError> {
        self.release_inner()
    }

    fn release_inner(&mut self) -> Result<(), PortReleaseError> {
        let Some(mut transport) = self.transport.take() else {
            return Ok(());
        };
        let cycled = transport.bye_and_dtr_cycle();
        {
            let mut state = self.shared.lock();
            state.transport = Some(transport);
            state.holder = None;
        }
        self.shared.returned.notify_all();
        let journaled = self
            .shared
            .record(LeaseEvent::Released, &self.job_id)
            .and_then(|()| self.shared.record(LeaseEvent::ReaderResumed, &self.job_id));
        match (cycled, journaled) {
            (Err(e), _) => Err(PortReleaseError::Bye(e)),
            (Ok(()), Err(e)) => Err(PortReleaseError::Journal(e)),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

impl<T: SimRelease> Transport for ProgrammingLease<T> {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        match self.transport.as_mut() {
            Some(t) => t.send(data),
            None => Err(TransportError::NothingWritten("lease released".into())),
        }
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        match self.transport.as_mut() {
            Some(t) => t.recv(timeout_ms),
            None => Err(TransportError::Timeout),
        }
    }

    fn now_ms(&mut self) -> u64 {
        self.transport.as_mut().map_or(0, Transport::now_ms)
    }
}

impl<T: SimRelease> Drop for ProgrammingLease<T> {
    fn drop(&mut self) {
        if let Err(e) = self.release_inner() {
            tracing::error!(job_id = %self.job_id, error = %e, "programming lease release failed");
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PortReleaseError {
    #[error("BYE/DTR release failed: {0:?}")]
    Bye(TransportError),
    #[error("lease journal: {0}")]
    Journal(std::io::Error),
}

pub struct SmdrHandle<T: SimRelease> {
    shared: Arc<Shared<T>>,
}

impl<T: SimRelease> SmdrSource for SmdrHandle<T> {
    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        let state = self.shared.lock();
        let (mut state, _) = self
            .shared
            .returned
            .wait_timeout_while(state, Duration::from_millis(timeout_ms), |s| {
                s.transport.is_none()
            })
            .unwrap_or_else(recover_from_poison);
        match state.transport.as_mut() {
            Some(t) => t.recv(timeout_ms),
            None => Err(TransportError::Timeout),
        }
    }
}
