#[cfg(target_os = "linux")]
pub mod device;
pub mod journal;

use crate::smdr_reader::SmdrSource;
use journal::{LeaseEvent, LeaseLog};
use kxtd1232::{Transport, TransportError};
use kxtd1232_sim::SimTransport;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
pub const SMDR_RECV_SLICE: Duration = Duration::from_millis(50);
pub const DEFAULT_RELEASE_STEP_TIMEOUT: Duration = Duration::from_secs(3);

pub const END_BINARY: [u8; 3] = [0x02, 0x0B, 0x0D];
pub const END_BINARY_ACK: [u8; 4] = [0x03, 0x0B, 0x00, 0x0E];
pub const BYE: &[u8] = b"BYE\r\n";
pub const PRG: &[u8] = b"PRG\r\n";
pub const ECS_OF: &[u8] = b"ECS OF\r\n";

pub const DTR_LOW_PERIOD: Duration = Duration::from_millis(300);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DtrError {
    #[error("DTR drop (B0): {0}")]
    Hangup(String),
    #[error("restoring line speed after the DTR drop: {0}")]
    Restore(String),
    #[error("line speed after the DTR drop reads back as {got}, expected {expected}")]
    SpeedMismatch { expected: String, got: String },
}

pub trait PortRelease: Transport {
    fn drop_dtr(&mut self) -> Result<(), DtrError>;
}

impl PortRelease for SimTransport {
    fn drop_dtr(&mut self) -> Result<(), DtrError> {
        self.reconnect();
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMode {
    SignedOut,
    Text,
    Binary,
}

impl SessionMode {
    pub(crate) fn after_send(self, data: &[u8]) -> Self {
        if data == ECS_OF {
            Self::Text
        } else if data == PRG {
            Self::Binary
        } else if data == END_BINARY {
            Self::Text
        } else if data == BYE {
            Self::SignedOut
        } else {
            self
        }
    }
}

const RECV_OTHER_ERROR_AS_NO_ACK_REASON: &str = "TransportError is non_exhaustive and NothingWritten is send-side only; any such recv error means no acknowledging reply arrived, so the step counts as unacknowledged and release still ends with the DTR drop, which is the spec's recovery for an unresponsive unit";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitFailure {
    NoAck,
    LinkDropped,
}

fn wait_for(
    t: &mut impl Transport,
    timeout: Duration,
    done: impl Fn(&[u8]) -> bool,
) -> Result<(), (WaitFailure, Vec<u8>)> {
    let deadline = Instant::now() + timeout;
    let mut got = Vec::new();
    loop {
        if done(&got) {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err((WaitFailure::NoAck, got));
        }
        let ms = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
        match t.recv(ms) {
            Ok(bytes) => got.extend(bytes),
            Err(TransportError::Timeout) => return Err((WaitFailure::NoAck, got)),
            Err(TransportError::LinkDown(_)) => return Err((WaitFailure::LinkDropped, got)),
            Err(_) => {
                tracing::warn!(
                    reason = RECV_OTHER_ERROR_AS_NO_ACK_REASON,
                    "recv returned a non-timeout, non-link-down error during a release ack wait"
                );
                return Err((WaitFailure::NoAck, got));
            }
        }
    }
}

fn has_ok_line(text: &[u8]) -> bool {
    String::from_utf8_lossy(text)
        .split('\n')
        .any(|l| l.trim() == "OK")
}

pub(crate) fn end_session(
    t: &mut impl PortRelease,
    mode: SessionMode,
    step_timeout: Duration,
) -> Result<(), PortReleaseError> {
    let logged_out = match mode {
        SessionMode::SignedOut => Ok(()),
        SessionMode::Binary => end_binary(t, step_timeout).and_then(|()| bye(t, step_timeout)),
        SessionMode::Text => bye(t, step_timeout),
    };
    let dtr = t.drop_dtr().map_err(PortReleaseError::DropDtr);
    logged_out.and(dtr)
}

fn end_binary(t: &mut impl Transport, step_timeout: Duration) -> Result<(), PortReleaseError> {
    t.send(&END_BINARY)
        .map_err(PortReleaseError::EndBinarySend)?;
    wait_for(t, step_timeout, |got| {
        got.windows(END_BINARY_ACK.len())
            .any(|w| w == END_BINARY_ACK)
    })
    .map_err(|(why, got)| match why {
        WaitFailure::NoAck => PortReleaseError::EndBinaryNotAcked {
            got: ReplyBytes(got),
        },
        WaitFailure::LinkDropped => PortReleaseError::EndBinaryLinkDropped {
            got: ReplyBytes(got),
        },
    })
}

fn bye(t: &mut impl Transport, step_timeout: Duration) -> Result<(), PortReleaseError> {
    t.send(BYE).map_err(PortReleaseError::ByeSend)?;
    wait_for(t, step_timeout, has_ok_line).map_err(|(why, got)| match why {
        WaitFailure::NoAck => PortReleaseError::ByeNotAcked {
            got: ReplyBytes(got),
        },
        WaitFailure::LinkDropped => PortReleaseError::ByeLinkDropped {
            got: ReplyBytes(got),
        },
    })
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
    journal: Mutex<Box<dyn LeaseLog>>,
    max_waiters: usize,
    release_step_timeout: Duration,
    leased: Arc<AtomicBool>,
    lease_epoch: Arc<AtomicU64>,
    resume_guard: Arc<Mutex<()>>,
    #[cfg(target_os = "linux")]
    device: Mutex<Option<Arc<Mutex<device::SmdrDevice>>>>,
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

    fn record_refusal(&self, event: LeaseEvent, job_id: &str) {
        if let Err(e) = self.record(event, job_id) {
            tracing::error!(job_id, ?event, error = %e, "lease journal write failed; returning the typed refusal");
        }
    }

    fn restore(&self, transport: T) {
        {
            let mut state = self.lock();
            state.transport = Some(transport);
            state.holder = None;
        }
        self.leased.store(false, Ordering::SeqCst);
        self.returned.notify_all();
    }
}

pub struct PortManager<T: PortRelease> {
    shared: Arc<Shared<T>>,
}

impl<T: PortRelease> PortManager<T> {
    pub fn new(transport: T, journal: impl LeaseLog + 'static, max_waiters: usize) -> Self {
        Self::with_release_step_timeout(
            transport,
            journal,
            max_waiters,
            DEFAULT_RELEASE_STEP_TIMEOUT,
        )
    }

    pub fn with_release_step_timeout(
        transport: T,
        journal: impl LeaseLog + 'static,
        max_waiters: usize,
        release_step_timeout: Duration,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    transport: Some(transport),
                    waiters: 0,
                    holder: None,
                }),
                returned: Condvar::new(),
                journal: Mutex::new(Box::new(journal)),
                max_waiters,
                release_step_timeout,
                leased: Arc::new(AtomicBool::new(false)),
                lease_epoch: Arc::new(AtomicU64::new(0)),
                resume_guard: Arc::new(Mutex::new(())),
                #[cfg(target_os = "linux")]
                device: Mutex::new(None),
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
            self.shared.record_refusal(LeaseEvent::Refused, job_id);
            return Err(LeaseError::QueueFull {
                max: self.shared.max_waiters,
            });
        }
        state.waiters += 1;
        let start = Instant::now();
        let (mut state, _) = self
            .shared
            .returned
            .wait_timeout_while(state, timeout, |s| s.transport.is_none())
            .unwrap_or_else(recover_from_poison);
        state.waiters -= 1;
        let resume = self
            .shared
            .resume_guard
            .lock()
            .unwrap_or_else(recover_from_poison);
        let taken = state.transport.take();
        self.shared.returned.notify_all();
        let Some(transport) = taken else {
            drop(state);
            self.shared.record_refusal(LeaseEvent::TimedOut, job_id);
            return Err(LeaseError::Timeout {
                waited_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
            });
        };
        state.holder = Some(job_id.to_string());
        self.shared.lease_epoch.fetch_add(1, Ordering::SeqCst);
        self.shared.leased.store(true, Ordering::SeqCst);
        drop(resume);
        drop(state);
        if let Err(e) = self
            .shared
            .record(LeaseEvent::Granted, job_id)
            .and_then(|()| self.shared.record(LeaseEvent::ReaderPaused, job_id))
        {
            self.shared.restore(transport);
            return Err(LeaseError::Journal(e));
        }
        Ok(ProgrammingLease {
            shared: Arc::clone(&self.shared),
            transport: Some(transport),
            job_id: job_id.to_string(),
            session: SessionMode::SignedOut,
        })
    }

    pub fn inspect_transport<R>(&self, f: impl FnOnce(&T) -> R) -> Option<R> {
        self.shared.lock().transport.as_ref().map(f)
    }

    pub fn holder(&self) -> Option<String> {
        self.shared.lock().holder.clone()
    }

    #[cfg(target_os = "linux")]
    pub fn open_smdr_device(
        &self,
        path: &std::path::Path,
        options: device::SmdrLineOptions,
    ) -> Result<device::SmdrDeviceHandle, device::DeviceError> {
        let mut slot = self
            .shared
            .device
            .lock()
            .unwrap_or_else(recover_from_poison);
        if slot.is_some() {
            return Err(device::DeviceError::AlreadyOpen);
        }
        let opened = Arc::new(Mutex::new(device::SmdrDevice::open(path, options)?));
        *slot = Some(Arc::clone(&opened));
        Ok(device::SmdrDeviceHandle::new(
            opened,
            Arc::clone(&self.shared.leased),
            Arc::clone(&self.shared.lease_epoch),
            Arc::clone(&self.shared.resume_guard),
        ))
    }

    #[cfg(target_os = "linux")]
    pub fn open_programming_device<'lease>(
        &self,
        lease: &'lease ProgrammingLease<T>,
        path: &std::path::Path,
        options: device::SmdrLineOptions,
    ) -> Result<device::ProgrammingDevice<'lease>, device::DeviceError> {
        if !Arc::ptr_eq(&self.shared, &lease.shared) || lease.transport.is_none() {
            return Err(device::DeviceError::NoLease);
        }
        let slot = self
            .shared
            .device
            .lock()
            .unwrap_or_else(recover_from_poison);
        let lock = match slot.as_ref() {
            Some(smdr) => device::FlockCover::HeldBySmdr(Arc::clone(smdr)),
            None => device::FlockCover::Own,
        };
        device::ProgrammingDevice::open(path, options, lock)
    }
}

pub struct ProgrammingLease<T: PortRelease> {
    shared: Arc<Shared<T>>,
    transport: Option<T>,
    job_id: String,
    session: SessionMode,
}

impl<T: PortRelease> ProgrammingLease<T> {
    pub fn session_mode(&self) -> SessionMode {
        self.session
    }

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
        let cycled = end_session(
            &mut transport,
            self.session,
            self.shared.release_step_timeout,
        );
        self.session = SessionMode::SignedOut;
        self.shared.restore(transport);
        let journaled = self
            .shared
            .record(LeaseEvent::Released, &self.job_id)
            .and_then(|()| self.shared.record(LeaseEvent::ReaderResumed, &self.job_id));
        match (cycled, journaled) {
            (Err(e), _) => Err(e),
            (Ok(()), Err(e)) => Err(PortReleaseError::Journal(e)),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

impl<T: PortRelease> Transport for ProgrammingLease<T> {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        match self.transport.as_mut() {
            Some(t) => {
                let sent = t.send(data);
                if sent.is_ok() {
                    self.session = self.session.after_send(data);
                }
                sent
            }
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

impl<T: PortRelease> Drop for ProgrammingLease<T> {
    fn drop(&mut self) {
        if let Err(e) = self.release_inner() {
            tracing::error!(job_id = %self.job_id, error = %e, "programming lease release failed");
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ReplyBytes(Vec<u8>);

impl ReplyBytes {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for ReplyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReplyBytes({} bytes withheld)", self.0.len())
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PortReleaseError {
    #[error("end-binary 02 0B 0D not sent: {0:?}")]
    EndBinarySend(TransportError),
    #[error("end-binary not acknowledged with 03 0B 00 0E ({} reply bytes withheld)", got.len())]
    EndBinaryNotAcked { got: ReplyBytes },
    #[error("link dropped while waiting for the end-binary ack ({} reply bytes withheld)", got.len())]
    EndBinaryLinkDropped { got: ReplyBytes },
    #[error("BYE not sent: {0:?}")]
    ByeSend(TransportError),
    #[error("BYE not acknowledged with OK ({} reply bytes withheld)", got.len())]
    ByeNotAcked { got: ReplyBytes },
    #[error("link dropped while waiting for the BYE OK ({} reply bytes withheld)", got.len())]
    ByeLinkDropped { got: ReplyBytes },
    #[error("DTR drop failed: {0}")]
    DropDtr(DtrError),
    #[error("lease journal: {0}")]
    Journal(std::io::Error),
}

pub struct SmdrHandle<T: PortRelease> {
    shared: Arc<Shared<T>>,
}

impl<T: PortRelease> SmdrSource for SmdrHandle<T> {
    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let state = self.shared.lock();
            let (mut state, _) = self
                .shared
                .returned
                .wait_timeout_while(state, remaining, |s| s.transport.is_none() || s.waiters > 0)
                .unwrap_or_else(recover_from_poison);
            if state.waiters > 0 {
                return Err(TransportError::Timeout);
            }
            let Some(t) = state.transport.as_mut() else {
                return Err(TransportError::Timeout);
            };
            let slice = remaining.min(SMDR_RECV_SLICE);
            let slice_ms = u64::try_from(slice.as_millis()).unwrap_or(u64::MAX);
            match t.recv(slice_ms) {
                Err(TransportError::Timeout) if Instant::now() < deadline => {}
                other => return other,
            }
            drop(state);
            self.shared.returned.notify_all();
        }
    }
}
