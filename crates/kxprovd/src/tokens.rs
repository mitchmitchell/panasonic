//! Daemon token store: verify bearer secrets (hashed on disk only).

use kxprov_api::{
    hash_bearer_secret, validate_tokens_file, Scope, TokenEntry, TokenId, TokenValidationError,
    TokensFile,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
#[cfg(feature = "test-util")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};
use thiserror::Error;

use crate::queue::JobQueue;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("tokens file must be mode 0600 and root-owned")]
    InsecurePermissions,
    #[error("invalid tokens file: {0}")]
    Invalid(String),
    #[error("unknown or invalid bearer")]
    Unauthorized,
    #[error("token revoked")]
    Revoked,
    #[error("token expired")]
    Expired,
    #[error("scope denied")]
    ScopeDenied,
    #[error("token store unavailable")]
    StoreUnavailable,
}

#[derive(Debug, Clone)]
pub struct VerifiedToken {
    pub id: TokenId,
    pub scopes: Vec<Scope>,
}

struct TokenState {
    path: PathBuf,
    approver_token_id: TokenId,
    entries: Vec<TokenEntry>,
    /// SHA-256 of raw tokens.json bytes; reload when disk content differs.
    loaded_digest: Option<[u8; 32]>,
    /// When true, a reload from disk re-checks root ownership and mode 0600.
    enforce_secure_reload: bool,
    /// When transient reload began; stale snapshot allowed until this ages out (~2s total).
    reload_failure_since: Option<Instant>,
    /// After grace expires, reject bearer auth until a good reload succeeds.
    store_unavailable: bool,
    store_unavailable_logged: bool,
    /// Initial 3-try window already consumed for this outage episode.
    reload_transient_done: bool,
    /// Fingerprint of the last failed on-disk payload (avoid re-reading unchanged bad bytes).
    reload_failed_disk_fingerprint: Option<DiskFingerprint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiskFingerprint {
    Missing,
    InvalidDigest([u8; 32]),
    Unreadable,
}

#[derive(Clone)]
struct ReloadPlan {
    path: PathBuf,
    outage_start: Option<Instant>,
    transient_done: bool,
    failed_fp: Option<DiskFingerprint>,
    probe_cancel: Arc<AtomicBool>,
    #[cfg(feature = "test-util")]
    probe_hang: Arc<AtomicBool>,
}

#[derive(Clone)]
enum DiskProbe {
    Ok(Vec<u8>),
    UnchangedBad,
    StillBad {
        fp: DiskFingerprint,
        outage_start: Instant,
    },
}

enum TransientFlightState {
    Idle,
    Running,
    Done(DiskProbe),
}

struct TransientReloadFlight {
    inner: Mutex<TransientFlightState>,
    cv: Condvar,
}

pub struct TokenStore {
    inner: Arc<Mutex<TokenState>>,
    job_queue: Arc<Mutex<Option<Weak<JobQueue>>>>,
    transient_flight: Arc<TransientReloadFlight>,
    /// At most one in-flight recv coordinating a probe spawn.
    disk_probe_live: Arc<AtomicUsize>,
    /// OS `token-reload-probe` threads currently running (including abandoned).
    probe_threads_alive: Arc<AtomicUsize>,
    /// Path identity the in-flight recv opened (dev/ino).
    probe_path_identity: Arc<Mutex<Option<PathIdentity>>>,
    /// Inodes abandoned probes still hold open; block respawn until thread exits.
    abandoned_probe_refcounts: Arc<Mutex<HashMap<PathIdentity, usize>>>,
    /// When set, the live probe's guard must not decrement `disk_probe_live`.
    active_probe_abandon: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    /// After a bounded probe times out, deny reload briefly without spawning.
    probe_fast_fail_until: Arc<Mutex<Option<Instant>>>,
    #[cfg(feature = "test-util")]
    reload_probe_hang: Arc<AtomicBool>,
}

#[cfg(feature = "test-util")]
static RELOAD_GRACE_OVERRIDE_MS: AtomicU64 = AtomicU64::new(0);

struct TokenRefreshDelta {
    newly_revoked: Vec<TokenId>,
    reactivated: Vec<TokenId>,
    rotated: Vec<TokenId>,
}

impl Clone for TokenStore {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            job_queue: Arc::clone(&self.job_queue),
            transient_flight: Arc::clone(&self.transient_flight),
            disk_probe_live: Arc::clone(&self.disk_probe_live),
            probe_threads_alive: Arc::clone(&self.probe_threads_alive),
            probe_path_identity: Arc::clone(&self.probe_path_identity),
            abandoned_probe_refcounts: Arc::clone(&self.abandoned_probe_refcounts),
            active_probe_abandon: Arc::clone(&self.active_probe_abandon),
            probe_fast_fail_until: Arc::clone(&self.probe_fast_fail_until),
            #[cfg(feature = "test-util")]
            reload_probe_hang: Arc::clone(&self.reload_probe_hang),
        }
    }
}

impl TransientReloadFlight {
    fn new() -> Self {
        Self {
            inner: Mutex::new(TransientFlightState::Idle),
            cv: Condvar::new(),
        }
    }

    fn reset(&self) {
        let mut guard = self.inner.lock().expect("transient flight lock");
        *guard = TransientFlightState::Idle;
        self.cv.notify_all();
    }
}

/// If the leader panics before publishing `Done`, unblock waiters instead of wedging auth.
struct TransientProbeLeaderGuard<'a> {
    flight: &'a TransientReloadFlight,
    on_drop: DiskProbe,
}

impl<'a> TransientProbeLeaderGuard<'a> {
    fn new(flight: &'a TransientReloadFlight, on_drop: DiskProbe) -> Self {
        Self { flight, on_drop }
    }
}

impl Drop for TransientProbeLeaderGuard<'_> {
    fn drop(&mut self) {
        let mut guard = self.flight.inner.lock().expect("transient flight lock");
        if matches!(*guard, TransientFlightState::Running) {
            *guard = TransientFlightState::Done(self.on_drop.clone());
            self.flight.cv.notify_all();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PathIdentity {
    dev: u64,
    ino: u64,
}

struct ProbeThreadSlotGuard {
    alive: Arc<AtomicUsize>,
}

impl Drop for ProbeThreadSlotGuard {
    fn drop(&mut self) {
        self.alive.fetch_sub(1, Ordering::AcqRel);
    }
}

struct ProbeThreadAliveGuard {
    identity: Option<PathIdentity>,
    abandoned_refcounts: Arc<Mutex<HashMap<PathIdentity, usize>>>,
    was_abandoned: Arc<AtomicBool>,
}

impl Drop for ProbeThreadAliveGuard {
    fn drop(&mut self) {
        if !self.was_abandoned.load(Ordering::Acquire) {
            return;
        }
        if let Some(id) = self.identity {
            let mut map = self
                .abandoned_refcounts
                .lock()
                .expect("abandoned probe lock");
            if let Some(n) = map.get_mut(&id) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    map.remove(&id);
                }
            }
        }
    }
}

#[cfg(unix)]
fn path_identity(path: &Path) -> Option<PathIdentity> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path).ok()?;
    Some(PathIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

#[cfg(not(unix))]
fn path_identity(_path: &Path) -> Option<PathIdentity> {
    None
}

struct DiskProbeLiveGuard {
    live: Arc<AtomicUsize>,
    fast_fail_until: Arc<Mutex<Option<Instant>>>,
    abandoned: Arc<AtomicBool>,
}

impl Drop for DiskProbeLiveGuard {
    fn drop(&mut self) {
        if self.abandoned.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self
            .live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
        if self.live.load(Ordering::Acquire) == 0 {
            *self.fast_fail_until.lock().expect("probe fast-fail lock") = None;
        }
    }
}

fn ct_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl TokenStore {
    pub fn load(path: PathBuf) -> Result<Self, TokenError> {
        Self::check_secure(&path)?;
        Self::load_unchecked(path)
    }

    #[cfg(feature = "test-util")]
    pub fn load_insecure(path: PathBuf) -> Result<Self, TokenError> {
        Self::load_unchecked_insecure(path)
    }

    #[cfg(all(test, feature = "test-util"))]
    pub fn set_enforce_secure_reload_for_test(&self, enforce: bool) {
        self.inner
            .lock()
            .expect("token store lock")
            .enforce_secure_reload = enforce;
    }

    #[cfg(feature = "test-util")]
    pub fn set_reload_probe_hang_for_test(&self, hang: bool) {
        self.reload_probe_hang.store(hang, Ordering::Relaxed);
    }

    #[cfg(feature = "test-util")]
    pub fn set_reload_grace_for_test(grace: Duration) {
        RELOAD_GRACE_OVERRIDE_MS.store(grace.as_millis() as u64, Ordering::Relaxed);
    }

    #[cfg(feature = "test-util")]
    pub fn clear_reload_grace_override_for_test() {
        RELOAD_GRACE_OVERRIDE_MS.store(0, Ordering::Relaxed);
    }

    #[cfg(feature = "test-util")]
    pub fn live_disk_probe_threads_for_test(&self) -> usize {
        self.probe_threads_alive.load(Ordering::Acquire)
    }

    #[cfg(feature = "test-util")]
    pub fn leaked_disk_probe_threads_for_test(&self) -> usize {
        self.abandoned_probe_refcounts
            .lock()
            .expect("abandoned probe lock")
            .values()
            .sum()
    }

    pub(crate) const MAX_PROBE_THREADS_ALIVE: usize = 2;

    #[cfg(feature = "test-util")]
    pub const MAX_LIVE_DISK_PROBE_THREADS: usize = Self::MAX_PROBE_THREADS_ALIVE;

    fn wrap_state(state: TokenState) -> Self {
        Self {
            inner: Arc::new(Mutex::new(state)),
            job_queue: Arc::new(Mutex::new(None)),
            transient_flight: Arc::new(TransientReloadFlight::new()),
            disk_probe_live: Arc::new(AtomicUsize::new(0)),
            probe_threads_alive: Arc::new(AtomicUsize::new(0)),
            probe_path_identity: Arc::new(Mutex::new(None)),
            abandoned_probe_refcounts: Arc::new(Mutex::new(HashMap::new())),
            active_probe_abandon: Arc::new(Mutex::new(None)),
            probe_fast_fail_until: Arc::new(Mutex::new(None)),
            #[cfg(feature = "test-util")]
            reload_probe_hang: Arc::new(AtomicBool::new(false)),
        }
    }

    const PROBE_FAST_FAIL_SLACK: Duration = Duration::from_millis(100);

    fn probe_path_differs_from_live(&self, path: &Path) -> bool {
        let current = path_identity(path);
        let stuck = *self
            .probe_path_identity
            .lock()
            .expect("probe path identity lock");
        match (current, stuck) {
            (Some(c), Some(s)) => c != s,
            (None, Some(_)) => true,
            _ => false,
        }
    }

    fn disk_reload_blocked_now(&self, during_outage: bool, path: &Path) -> bool {
        if during_outage {
            if self.probe_threads_alive.load(Ordering::Acquire) >= Self::MAX_PROBE_THREADS_ALIVE {
                return true;
            }
            if self.disk_probe_live.load(Ordering::Acquire) > 0 {
                if self.probe_path_differs_from_live(path) {
                    return false;
                }
                return true;
            }
        }
        self.probe_fast_fail_until
            .lock()
            .expect("probe fast-fail lock")
            .is_some_and(|until| Instant::now() < until)
    }

    fn abandon_stuck_probe(&self) {
        if self.disk_probe_live.load(Ordering::Acquire) == 0 {
            return;
        }
        let mut owned_abandon = false;
        if let Some(flag) = self
            .active_probe_abandon
            .lock()
            .expect("active probe abandon lock")
            .take()
        {
            owned_abandon = !flag.swap(true, Ordering::AcqRel);
        }
        if owned_abandon {
            let _ = self
                .disk_probe_live
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
        }
        let stuck_id = *self
            .probe_path_identity
            .lock()
            .expect("probe path identity lock");
        if owned_abandon {
            if let Some(id) = stuck_id {
                self.abandoned_probe_refcounts
                    .lock()
                    .expect("abandoned probe lock")
                    .entry(id)
                    .and_modify(|n| *n += 1)
                    .or_insert(1);
            }
        }
        *self
            .probe_path_identity
            .lock()
            .expect("probe path identity lock") = None;
    }

    fn disk_probe_spawn_denied(&self, path: &Path) -> bool {
        if self.probe_threads_alive.load(Ordering::Acquire) >= Self::MAX_PROBE_THREADS_ALIVE {
            return true;
        }
        if let Some(id) = path_identity(path) {
            if self
                .abandoned_probe_refcounts
                .lock()
                .expect("abandoned probe lock")
                .get(&id)
                .is_some_and(|n| *n > 0)
            {
                return true;
            }
        }
        false
    }

    fn reconcile_stuck_probe_for_path(&self, path: &Path) {
        if self.disk_probe_live.load(Ordering::Acquire) == 0 {
            return;
        }
        if self.probe_path_differs_from_live(path) {
            self.abandon_stuck_probe();
        }
    }

    fn reload_plan_in_outage(plan: &ReloadPlan) -> bool {
        plan.transient_done || plan.outage_start.is_some()
    }

    fn latch_probe_fast_fail(&self) {
        let until = Instant::now() + Self::PROBE_FAST_FAIL_SLACK;
        let mut guard = self
            .probe_fast_fail_until
            .lock()
            .expect("probe fast-fail lock");
        match *guard {
            Some(prev) if prev > until => {}
            _ => *guard = Some(until),
        }
    }

    fn try_begin_disk_probe(
        &self,
        path: &Path,
        abandoned: Arc<AtomicBool>,
    ) -> Option<DiskProbeLiveGuard> {
        if self.probe_threads_alive.load(Ordering::Acquire) >= Self::MAX_PROBE_THREADS_ALIVE {
            return None;
        }
        if self.disk_probe_spawn_denied(path) {
            return None;
        }
        if self
            .disk_probe_live
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            *self
                .active_probe_abandon
                .lock()
                .expect("active probe abandon lock") = Some(Arc::clone(&abandoned));
            *self
                .probe_path_identity
                .lock()
                .expect("probe path identity lock") = path_identity(path);
            Some(DiskProbeLiveGuard {
                live: Arc::clone(&self.disk_probe_live),
                fast_fail_until: Arc::clone(&self.probe_fast_fail_until),
                abandoned,
            })
        } else {
            None
        }
    }

    fn load_unchecked(path: PathBuf) -> Result<Self, TokenError> {
        let mut state = Self::read_state(&path)?;
        state.enforce_secure_reload = true;
        Self::validate_file(&state.entries, &state.approver_token_id)?;
        Ok(Self::wrap_state(state))
    }

    #[cfg(feature = "test-util")]
    fn load_unchecked_insecure(path: PathBuf) -> Result<Self, TokenError> {
        let mut state = Self::read_state(&path)?;
        state.enforce_secure_reload = false;
        Self::validate_file(&state.entries, &state.approver_token_id)?;
        Ok(Self::wrap_state(state))
    }

    pub fn attach_job_queue(&self, queue: Weak<JobQueue>) {
        *self.job_queue.lock().expect("token store lock") = Some(queue);
    }

    fn notify_token_revocation_changes(&self, delta: &TokenRefreshDelta) {
        let q = self
            .job_queue
            .lock()
            .expect("token store lock")
            .as_ref()
            .and_then(Weak::upgrade);
        let Some(q) = q else {
            return;
        };
        for id in &delta.newly_revoked {
            q.bump_token_epoch(id);
        }
        for id in &delta.reactivated {
            q.bump_token_epoch(id);
        }
        for id in &delta.rotated {
            q.bump_token_epoch(id);
        }
    }

    fn digest_bytes(raw: &[u8]) -> [u8; 32] {
        Sha256::digest(raw).into()
    }

    fn tokens_file_parse_ok(raw: &[u8]) -> bool {
        serde_json::from_slice::<TokensFile>(raw).is_ok()
    }

    const RELOAD_GRACE: Duration = Duration::from_secs(2);
    const RELOAD_MAX_ATTEMPTS: usize = 3;

    #[cfg(feature = "test-util")]
    fn reload_grace_duration() -> Duration {
        let ms = RELOAD_GRACE_OVERRIDE_MS.load(Ordering::Relaxed);
        if ms > 0 {
            Duration::from_millis(ms)
        } else {
            Self::RELOAD_GRACE
        }
    }

    #[cfg(not(feature = "test-util"))]
    fn reload_grace_duration() -> Duration {
        Self::RELOAD_GRACE
    }

    #[cfg(unix)]
    fn fifo_fingerprint(path: &Path) -> Option<DiskFingerprint> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let meta = std::fs::symlink_metadata(path).ok()?;
        if !meta.file_type().is_fifo() {
            return None;
        }
        let mut hasher = Sha256::new();
        hasher.update(b"fifo:");
        hasher.update(meta.dev().to_le_bytes());
        hasher.update(meta.ino().to_le_bytes());
        hasher.update(meta.size().to_le_bytes());
        hasher.update(meta.mtime().to_le_bytes());
        Some(DiskFingerprint::InvalidDigest(hasher.finalize().into()))
    }

    fn disk_fingerprint(path: &Path) -> DiskFingerprint {
        #[cfg(unix)]
        if let Some(fp) = Self::fifo_fingerprint(path) {
            return fp;
        }
        use std::io::ErrorKind;
        match std::fs::read(path) {
            Ok(raw) => DiskFingerprint::InvalidDigest(Self::digest_bytes(&raw)),
            Err(e) if e.kind() == ErrorKind::NotFound => DiskFingerprint::Missing,
            Err(_) => DiskFingerprint::Unreadable,
        }
    }

    fn try_read_valid_tokens_bytes(
        path: &Path,
        cancel: Option<&AtomicBool>,
    ) -> Result<Vec<u8>, DiskFingerprint> {
        use std::io::ErrorKind;
        if cancel.is_some_and(|c| c.load(Ordering::Acquire)) {
            return Err(DiskFingerprint::Unreadable);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if let Ok(meta) = std::fs::symlink_metadata(path) {
                if meta.file_type().is_fifo() {
                    return Self::try_read_fifo_tokens_bytes(path, cancel);
                }
            }
        }
        match std::fs::read(path) {
            Ok(raw) if Self::tokens_file_parse_ok(&raw) => Ok(raw),
            Ok(raw) => Err(DiskFingerprint::InvalidDigest(Self::digest_bytes(&raw))),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(DiskFingerprint::Missing),
            Err(_) => Err(DiskFingerprint::Unreadable),
        }
    }

    #[cfg(unix)]
    fn try_read_fifo_tokens_bytes(
        path: &Path,
        cancel: Option<&AtomicBool>,
    ) -> Result<Vec<u8>, DiskFingerprint> {
        use nix::fcntl::{open, OFlag};
        use nix::sys::stat::Mode;
        use nix::unistd::read;

        struct FifoReadFd(nix::libc::c_int);

        impl Drop for FifoReadFd {
            fn drop(&mut self) {
                let _ = nix::unistd::close(self.0);
            }
        }

        let fd = match open(path, OFlag::O_RDONLY | OFlag::O_NONBLOCK, Mode::empty()) {
            Ok(fd) => FifoReadFd(fd),
            Err(_) => return Err(DiskFingerprint::Unreadable),
        };
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            if cancel.is_some_and(|c| c.load(Ordering::Acquire)) {
                return Err(DiskFingerprint::Unreadable);
            }
            match read(fd.0, &mut buf) {
                Ok(0) => std::thread::sleep(Duration::from_millis(5)),
                Ok(n) => {
                    raw.extend_from_slice(&buf[..n]);
                    if Self::tokens_file_parse_ok(&raw) {
                        return Ok(raw);
                    }
                    if raw.len() > 512 * 1024 {
                        return Err(DiskFingerprint::InvalidDigest(Self::digest_bytes(&raw)));
                    }
                }
                Err(nix::errno::Errno::EAGAIN) => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => return Err(DiskFingerprint::Unreadable),
            }
        }
    }

    /// Up to [`Self::RELOAD_MAX_ATTEMPTS`] within `deadline` (about 2s from outage start).
    fn read_tokens_until_deadline(
        path: &Path,
        deadline: Instant,
        cancel: Option<&AtomicBool>,
    ) -> Result<Vec<u8>, DiskFingerprint> {
        let mut last_fp = DiskFingerprint::Missing;
        for attempt in 0..Self::RELOAD_MAX_ATTEMPTS {
            match Self::try_read_valid_tokens_bytes(path, cancel) {
                Ok(raw) => return Ok(raw),
                Err(fp) => last_fp = fp,
            }
            if attempt + 1 >= Self::RELOAD_MAX_ATTEMPTS || Instant::now() >= deadline {
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            std::thread::sleep(remaining.min(Duration::from_millis(700)));
        }
        Err(last_fp)
    }

    fn clear_reload_outage(state: &mut TokenState, flight: &TransientReloadFlight) {
        state.reload_failure_since = None;
        state.store_unavailable = false;
        state.store_unavailable_logged = false;
        state.reload_transient_done = false;
        state.reload_failed_disk_fingerprint = None;
        flight.reset();
    }

    fn timed_out_disk_probe() -> DiskProbe {
        let outage_start = Instant::now()
            .checked_sub(Self::reload_grace_duration())
            .unwrap_or_else(Instant::now);
        DiskProbe::StillBad {
            fp: DiskFingerprint::Unreadable,
            outage_start,
        }
    }

    fn run_disk_probe_off_thread(&self, plan: ReloadPlan) -> Result<DiskProbe, TokenError> {
        self.reconcile_stuck_probe_for_path(&plan.path);
        let instant_deny = Self::reload_plan_in_outage(&plan);
        let wait_until = if instant_deny {
            Instant::now()
        } else {
            Instant::now() + Duration::from_millis(50)
        };
        let abandoned = Arc::new(AtomicBool::new(false));
        let live_guard = loop {
            self.reconcile_stuck_probe_for_path(&plan.path);
            if self.disk_probe_spawn_denied(&plan.path) {
                self.latch_probe_fast_fail();
                return Err(TokenError::StoreUnavailable);
            }
            if let Some(guard) = self.try_begin_disk_probe(&plan.path, Arc::clone(&abandoned)) {
                break guard;
            }
            if instant_deny || Instant::now() >= wait_until {
                return Err(TokenError::StoreUnavailable);
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        let deadline = Instant::now() + Self::reload_grace_duration();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let probe_alive = Arc::clone(&self.probe_threads_alive);
        let probe_alive_err = Arc::clone(&probe_alive);
        let abandoned_refcounts = Arc::clone(&self.abandoned_probe_refcounts);
        let thread_identity = path_identity(&plan.path);
        let prev = probe_alive.fetch_add(1, Ordering::AcqRel);
        if prev >= Self::MAX_PROBE_THREADS_ALIVE {
            probe_alive.fetch_sub(1, Ordering::AcqRel);
            self.latch_probe_fast_fail();
            return Err(TokenError::StoreUnavailable);
        }
        let mut probe_plan = plan;
        probe_plan.probe_cancel = Arc::clone(&abandoned);
        let spawn_ok = std::thread::Builder::new()
            .name("token-reload-probe".into())
            .spawn(move || {
                let _slot = ProbeThreadSlotGuard { alive: probe_alive };
                let _thread_guard = ProbeThreadAliveGuard {
                    identity: thread_identity,
                    abandoned_refcounts,
                    was_abandoned: Arc::clone(&abandoned),
                };
                let _live = live_guard;
                let _ = tx.send(Self::execute_disk_probe(&probe_plan));
            });
        if let Err(e) = spawn_ok {
            probe_alive_err.fetch_sub(1, Ordering::AcqRel);
            tracing::error!("token-reload-probe spawn failed: {e}");
            self.latch_probe_fast_fail();
            return Err(TokenError::StoreUnavailable);
        }
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .saturating_add(Duration::from_millis(300));
        if timeout.is_zero() {
            self.latch_probe_fast_fail();
            self.abandon_stuck_probe();
            return Ok(Self::timed_out_disk_probe());
        }
        match rx.recv_timeout(timeout) {
            Ok(probe) => {
                *self
                    .probe_path_identity
                    .lock()
                    .expect("probe path identity lock") = None;
                *self
                    .active_probe_abandon
                    .lock()
                    .expect("active probe abandon lock") = None;
                Ok(probe)
            }
            Err(_) => {
                self.latch_probe_fast_fail();
                self.abandon_stuck_probe();
                Ok(Self::timed_out_disk_probe())
            }
        }
    }

    fn coordinated_transient_probe(
        &self,
        flight: &TransientReloadFlight,
        plan: ReloadPlan,
    ) -> Result<DiskProbe, TokenError> {
        let wait_until =
            plan.outage_start.unwrap_or_else(Instant::now) + Self::reload_grace_duration();
        let mut guard = flight.inner.lock().expect("transient flight lock");
        loop {
            match &*guard {
                TransientFlightState::Done(probe) => return Ok(probe.clone()),
                TransientFlightState::Running => {
                    if self.disk_probe_live.load(Ordering::Acquire) > 0
                        && !self.probe_path_differs_from_live(&plan.path)
                    {
                        self.latch_probe_fast_fail();
                        return Err(TokenError::StoreUnavailable);
                    }
                    if Self::reload_plan_in_outage(&plan)
                        && self.probe_threads_alive.load(Ordering::Acquire)
                            >= Self::MAX_PROBE_THREADS_ALIVE
                    {
                        return Err(TokenError::StoreUnavailable);
                    }
                    let remaining = wait_until.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        let probe = Self::timed_out_disk_probe();
                        *guard = TransientFlightState::Done(probe.clone());
                        flight.cv.notify_all();
                        return Ok(probe);
                    }
                    let (g, wait) = flight
                        .cv
                        .wait_timeout(guard, remaining)
                        .expect("transient flight wait");
                    guard = g;
                    if wait.timed_out() && matches!(*guard, TransientFlightState::Running) {
                        let probe = Self::timed_out_disk_probe();
                        *guard = TransientFlightState::Done(probe.clone());
                        flight.cv.notify_all();
                        return Ok(probe);
                    }
                }
                TransientFlightState::Idle => {
                    *guard = TransientFlightState::Running;
                    drop(guard);
                    let _leader =
                        TransientProbeLeaderGuard::new(flight, Self::timed_out_disk_probe());
                    let probe = match self.run_disk_probe_off_thread(plan.clone()) {
                        Ok(p) => p,
                        Err(TokenError::StoreUnavailable) => {
                            let mut guard = flight.inner.lock().expect("transient flight lock");
                            let probe = Self::timed_out_disk_probe();
                            *guard = TransientFlightState::Done(probe);
                            flight.cv.notify_all();
                            return Err(TokenError::StoreUnavailable);
                        }
                        Err(e) => return Err(e),
                    };
                    let mut guard = flight.inner.lock().expect("transient flight lock");
                    *guard = TransientFlightState::Done(probe.clone());
                    flight.cv.notify_all();
                    return Ok(probe);
                }
            }
        }
    }

    fn fingerprint_unchanged(expected: DiskFingerprint, path: &Path) -> bool {
        Self::disk_fingerprint(path) == expected
    }

    fn execute_disk_probe(plan: &ReloadPlan) -> DiskProbe {
        #[cfg(feature = "test-util")]
        while plan.probe_hang.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(50));
        }
        if plan.transient_done {
            if let Some(fp) = plan.failed_fp {
                if Self::fingerprint_unchanged(fp, &plan.path) {
                    return DiskProbe::UnchangedBad;
                }
            }
            if let Ok(raw) = Self::try_read_valid_tokens_bytes(&plan.path, Some(&plan.probe_cancel))
            {
                return DiskProbe::Ok(raw);
            }
            if let Some(start) = plan.outage_start {
                if start.elapsed() >= Self::reload_grace_duration() {
                    let fp = Self::disk_fingerprint(&plan.path);
                    return DiskProbe::StillBad {
                        fp,
                        outage_start: start,
                    };
                }
            }
            return DiskProbe::UnchangedBad;
        }

        let outage_start = plan.outage_start.unwrap_or_else(Instant::now);
        let deadline = outage_start + Self::reload_grace_duration();
        match Self::read_tokens_until_deadline(&plan.path, deadline, Some(&plan.probe_cancel)) {
            Ok(raw) => DiskProbe::Ok(raw),
            Err(fp) => DiskProbe::StillBad { fp, outage_start },
        }
    }

    fn empty_refresh_delta() -> TokenRefreshDelta {
        TokenRefreshDelta {
            newly_revoked: Vec::new(),
            reactivated: Vec::new(),
            rotated: Vec::new(),
        }
    }

    fn read_state(path: &Path) -> Result<TokenState, TokenError> {
        let raw = std::fs::read(path)?;
        if !Self::tokens_file_parse_ok(&raw) {
            return Err(TokenError::Invalid("tokens.json invalid".into()));
        }
        let loaded_digest = Self::digest_bytes(&raw);
        let file: TokensFile = serde_json::from_slice(&raw)?;
        Ok(TokenState {
            path: path.to_path_buf(),
            approver_token_id: file.approver_token_id,
            entries: file.tokens,
            loaded_digest: Some(loaded_digest),
            enforce_secure_reload: true,
            reload_failure_since: None,
            store_unavailable: false,
            store_unavailable_logged: false,
            reload_transient_done: false,
            reload_failed_disk_fingerprint: None,
        })
    }

    fn read_state_from_raw(path: &Path, raw: &[u8]) -> Result<TokenState, TokenError> {
        let file: TokensFile = serde_json::from_slice(raw)?;
        Ok(TokenState {
            path: path.to_path_buf(),
            approver_token_id: file.approver_token_id,
            entries: file.tokens,
            loaded_digest: Some(Self::digest_bytes(raw)),
            enforce_secure_reload: true,
            reload_failure_since: None,
            store_unavailable: false,
            store_unavailable_logged: false,
            reload_transient_done: false,
            reload_failed_disk_fingerprint: None,
        })
    }

    fn validate_file(
        entries: &[TokenEntry],
        approver_token_id: &TokenId,
    ) -> Result<(), TokenError> {
        if entries.is_empty() {
            return Err(TokenError::Invalid("no tokens".into()));
        }
        let approve_ids: Vec<_> = entries
            .iter()
            .filter(|t| !t.revoked && t.scopes.iter().any(|s| *s == Scope::Approve))
            .map(|t| t.id.clone())
            .collect();
        if approve_ids.len() != 1 || approve_ids[0] != *approver_token_id {
            return Err(TokenError::Invalid(
                "exactly one approver token must match approver_token_id".into(),
            ));
        }
        validate_tokens_file(&TokensFile {
            approver_token_id: approver_token_id.clone(),
            tokens: entries.to_vec(),
        })
        .map_err(|e| match e {
            TokenValidationError::ApproverMustNotHoldPlanOrWrite => {
                TokenError::Invalid("approver token must not include Plan or Write scope".into())
            }
            TokenValidationError::ReservedTokenId => {
                TokenError::Invalid("token id is reserved for synthetic Unix principals".into())
            }
        })?;
        let mut ids = std::collections::HashSet::new();
        let mut hashes = std::collections::HashSet::new();
        for t in entries {
            if !ids.insert(t.id.as_str().to_string()) {
                return Err(TokenError::Invalid("duplicate token id".into()));
            }
            if !hashes.insert(t.secret_hash.clone()) {
                return Err(TokenError::Invalid("duplicate token secret_hash".into()));
            }
        }
        Ok(())
    }

    fn latch_store_unavailable(state: &mut TokenState) -> TokenError {
        state.store_unavailable = true;
        if !state.store_unavailable_logged {
            tracing::error!(
                path = %state.path.display(),
                "tokens.json reload failed past grace; bearer-authenticated access rejected until file recovers"
            );
            state.store_unavailable_logged = true;
        }
        TokenError::StoreUnavailable
    }

    fn merge_disk_probe(
        state: &mut TokenState,
        flight: &TransientReloadFlight,
        probe: DiskProbe,
    ) -> Result<TokenRefreshDelta, TokenError> {
        match probe {
            DiskProbe::Ok(raw) => {
                Self::clear_reload_outage(state, flight);
                Self::apply_reloaded_bytes(state, raw)
            }
            DiskProbe::UnchangedBad => {
                if state.store_unavailable {
                    return Err(TokenError::StoreUnavailable);
                }
                if let Some(since) = state.reload_failure_since {
                    if since.elapsed() >= Self::reload_grace_duration() {
                        return Err(Self::latch_store_unavailable(state));
                    }
                }
                Ok(Self::empty_refresh_delta())
            }
            DiskProbe::StillBad { fp, outage_start } => {
                state.reload_failure_since = Some(outage_start);
                state.reload_transient_done = true;
                state.reload_failed_disk_fingerprint = Some(fp);
                if outage_start.elapsed() >= Self::reload_grace_duration()
                    || state.store_unavailable
                {
                    Err(Self::latch_store_unavailable(state))
                } else {
                    Ok(Self::empty_refresh_delta())
                }
            }
        }
    }

    fn refresh_if_modified(&self) -> Result<TokenRefreshDelta, TokenError> {
        let plan = {
            let state = self.inner.lock().expect("token store lock");
            if state.loaded_digest.is_none() {
                return Ok(Self::empty_refresh_delta());
            }
            if state.enforce_secure_reload {
                Self::check_secure(&state.path)?;
            }
            ReloadPlan {
                path: state.path.clone(),
                outage_start: state.reload_failure_since,
                transient_done: state.reload_transient_done,
                failed_fp: state.reload_failed_disk_fingerprint,
                probe_cancel: Arc::new(AtomicBool::new(false)),
                #[cfg(feature = "test-util")]
                probe_hang: Arc::clone(&self.reload_probe_hang),
            }
        };

        let during_outage = Self::reload_plan_in_outage(&plan);
        if self.disk_reload_blocked_now(during_outage, &plan.path) {
            return Err(TokenError::StoreUnavailable);
        }
        if during_outage {
            self.reconcile_stuck_probe_for_path(&plan.path);
        }

        let probe = if plan.transient_done {
            self.run_disk_probe_off_thread(plan)?
        } else {
            self.coordinated_transient_probe(&self.transient_flight, plan)?
        };

        let mut state = self.inner.lock().expect("token store lock");
        Self::merge_disk_probe(&mut state, &self.transient_flight, probe)
    }

    fn apply_reloaded_bytes(
        state: &mut TokenState,
        raw: Vec<u8>,
    ) -> Result<TokenRefreshDelta, TokenError> {
        let digest = Self::digest_bytes(&raw);
        if Some(digest) == state.loaded_digest {
            return Ok(Self::empty_refresh_delta());
        }
        let enforce_secure = state.enforce_secure_reload;
        let prev_ids: HashSet<String> = state
            .entries
            .iter()
            .map(|t| t.id.as_str().to_string())
            .collect();
        let prev_revoked: HashSet<String> = state
            .entries
            .iter()
            .filter(|t| t.revoked)
            .map(|t| t.id.as_str().to_string())
            .collect();
        let prev_hashes: std::collections::HashMap<String, String> = state
            .entries
            .iter()
            .map(|t| (t.id.as_str().to_string(), t.secret_hash.clone()))
            .collect();
        let fresh = Self::read_state_from_raw(&state.path, &raw)?;
        Self::validate_file(&fresh.entries, &fresh.approver_token_id)?;
        let fresh_ids: HashSet<String> = fresh
            .entries
            .iter()
            .map(|t| t.id.as_str().to_string())
            .collect();
        let mut newly_revoked: Vec<TokenId> = fresh
            .entries
            .iter()
            .filter(|t| t.revoked && !prev_revoked.contains(t.id.as_str()))
            .map(|t| t.id.clone())
            .collect();
        for id in prev_ids.difference(&fresh_ids) {
            newly_revoked.push(TokenId(id.clone()));
        }
        let reactivated = fresh
            .entries
            .iter()
            .filter(|t| !t.revoked && prev_revoked.contains(t.id.as_str()))
            .map(|t| t.id.clone())
            .collect();
        let rotated = fresh
            .entries
            .iter()
            .filter(|t| {
                prev_hashes
                    .get(t.id.as_str())
                    .is_some_and(|h| h != &t.secret_hash)
            })
            .map(|t| t.id.clone())
            .collect();
        *state = fresh;
        state.enforce_secure_reload = enforce_secure;
        Ok(TokenRefreshDelta {
            newly_revoked,
            reactivated,
            rotated,
        })
    }

    fn find_entry<'a>(entries: &'a [TokenEntry], hash: &str) -> Option<&'a TokenEntry> {
        let mut found: Option<&TokenEntry> = None;
        for entry in entries {
            if ct_eq_str(&entry.secret_hash, hash) {
                found = Some(entry);
            }
        }
        found
    }

    #[cfg(feature = "test-util")]
    pub fn write_test_file(path: &Path, file: &TokensFile) -> Result<(), TokenError> {
        crate::atomic_write::write(path, &serde_json::to_vec_pretty(file)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn path(&self) -> PathBuf {
        self.inner.lock().expect("token store lock").path.clone()
    }

    pub fn approver_token_id(&self) -> TokenId {
        self.inner
            .lock()
            .expect("token store lock")
            .approver_token_id
            .clone()
    }

    pub fn verify_bearer(
        &self,
        bearer: &str,
        now_ms: u64,
        need: Scope,
    ) -> Result<VerifiedToken, TokenError> {
        let delta = self.refresh_if_modified()?;
        {
            let state = self.inner.lock().expect("token store lock");
            if state.store_unavailable {
                return Err(TokenError::StoreUnavailable);
            }
        }
        self.notify_token_revocation_changes(&delta);
        let state = self.inner.lock().expect("token store lock");
        let hash = hash_bearer_secret(bearer);
        let entry = Self::find_entry(&state.entries, &hash).ok_or(TokenError::Unauthorized)?;
        if entry.revoked {
            return Err(TokenError::Revoked);
        }
        if now_ms >= entry.expires_at_ms {
            return Err(TokenError::Expired);
        }
        if need == Scope::Approve && entry.id != state.approver_token_id {
            return Err(TokenError::ScopeDenied);
        }
        if !entry.scopes.iter().any(|s| *s == need) {
            return Err(TokenError::ScopeDenied);
        }
        Ok(VerifiedToken {
            id: entry.id.clone(),
            scopes: entry.scopes.clone(),
        })
    }

    #[cfg(all(test, feature = "test-util"))]
    pub fn from_entries_insecure(path: PathBuf, file: TokensFile) -> Self {
        let state = TokenState {
            path,
            approver_token_id: file.approver_token_id,
            entries: file.tokens,
            loaded_digest: None,
            enforce_secure_reload: false,
            reload_failure_since: None,
            store_unavailable: false,
            store_unavailable_logged: false,
            reload_transient_done: false,
            reload_failed_disk_fingerprint: None,
        };
        Self::wrap_state(state)
    }

    pub fn is_revoked(&self, token_id: &TokenId) -> Result<bool, TokenError> {
        let delta = self.refresh_if_modified()?;
        self.notify_token_revocation_changes(&delta);
        let state = self.inner.lock().expect("token store lock");
        Ok(state
            .entries
            .iter()
            .find(|t| t.id == *token_id)
            .map(|t| t.revoked)
            .unwrap_or(true))
    }

    #[cfg(unix)]
    fn check_secure(path: &Path) -> Result<(), TokenError> {
        use std::os::unix::fs::MetadataExt;
        if !path.exists() {
            tracing::error!(
                path = %path.display(),
                "tokens file missing on secure reload"
            );
            return Err(TokenError::Invalid("tokens file missing".into()));
        }
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            tracing::error!(
                path = %path.display(),
                "tokens file is not a regular root-owned file"
            );
            return Err(TokenError::InsecurePermissions);
        }
        if meta.uid() != 0 {
            tracing::error!(path = %path.display(), "tokens file is not root-owned");
            return Err(TokenError::InsecurePermissions);
        }
        if meta.mode() & 0o777 != 0o600 {
            tracing::error!(path = %path.display(), "tokens file is not mode 0600");
            return Err(TokenError::InsecurePermissions);
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn check_secure(_path: &Path) -> Result<(), TokenError> {
        Ok(())
    }
}

#[cfg(all(test, feature = "test-util"))]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use kxprov_api::hash_bearer_secret;

    #[test]
    fn approve_scope_requires_configured_cos_token_id() {
        let file = TokensFile {
            approver_token_id: TokenId("approver".into()),
            tokens: vec![
                TokenEntry {
                    id: TokenId("approver".into()),
                    secret_hash: hash_bearer_secret("good"),
                    scopes: vec![Scope::Approve],
                    expires_at_ms: u64::MAX / 2,
                    revoked: false,
                },
                TokenEntry {
                    id: TokenId("evil".into()),
                    secret_hash: hash_bearer_secret("evil"),
                    scopes: vec![Scope::Approve],
                    expires_at_ms: u64::MAX / 2,
                    revoked: false,
                },
            ],
        };
        let store = TokenStore::from_entries_insecure(PathBuf::from("/dev/null"), file);
        assert!(matches!(
            store.verify_bearer("evil", 0, Scope::Approve),
            Err(TokenError::ScopeDenied)
        ));
        assert!(store.verify_bearer("good", 0, Scope::Approve).is_ok());
    }

    fn write_tokens_revoking_writer(path: &Path, revoke: bool) {
        let mut file = crate::test_util::default_tokens_file();
        for t in &mut file.tokens {
            if t.id.as_str() == "writer" {
                t.revoked = revoke;
            }
        }
        TokenStore::write_test_file(path, &file).expect("write tokens");
    }

    #[test]
    fn reload_revoke_on_disk_not_applied_when_json_invalid_after_grace() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        write_tokens_revoking_writer(&path, true);
        std::fs::write(&path, b"{bad").unwrap();
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("grace may serve last good snapshot");
        std::thread::sleep(Duration::from_millis(2100));
        assert!(matches!(
            store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
            Err(TokenError::StoreUnavailable)
        ));
    }

    #[test]
    fn reload_corrupt_fails_closed_after_grace_window() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("warm");
        std::fs::write(&path, b"{not-json").unwrap();
        let grace_start = Instant::now();
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("grace snapshot");
        assert!(
            grace_start.elapsed() <= Duration::from_secs(2) + Duration::from_millis(200),
            "transient reload must finish within ~2s"
        );
        std::thread::sleep(Duration::from_millis(2100));
        assert!(matches!(
            store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
            Err(TokenError::StoreUnavailable)
        ));
    }

    struct ReloadProbeHangGuard {
        flag: Arc<AtomicBool>,
    }

    impl ReloadProbeHangGuard {
        fn enable(store: &TokenStore) -> Self {
            store.reload_probe_hang.store(true, Ordering::Relaxed);
            Self {
                flag: Arc::clone(&store.reload_probe_hang),
            }
        }
    }

    impl Drop for ReloadProbeHangGuard {
        fn drop(&mut self) {
            self.flag.store(false, Ordering::Relaxed);
        }
    }

    #[test]
    fn hung_disk_probe_never_spawns_more_than_one_live_thread() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("warm");
        std::fs::write(&path, b"{bad").unwrap();
        let bound = Duration::from_secs(2) + Duration::from_millis(400);
        {
            let _hang = ReloadProbeHangGuard::enable(&store);
            for i in 0..6 {
                let wall = Instant::now();
                assert!(
                    matches!(
                        store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
                        Err(TokenError::StoreUnavailable)
                    ),
                    "call {i} must fail closed"
                );
                assert!(
                    wall.elapsed() <= bound,
                    "call {i} must fail closed within the reload window without spawning another probe"
                );
                assert!(
                    store.live_disk_probe_threads_for_test() <= TokenStore::MAX_PROBE_THREADS_ALIVE,
                    "at most {} live probe thread(s) (got {})",
                    TokenStore::MAX_PROBE_THREADS_ALIVE,
                    store.live_disk_probe_threads_for_test()
                );
            }
        }
        let drain_deadline = Instant::now() + Duration::from_secs(5);
        while store.live_disk_probe_threads_for_test() > 0 {
            assert!(
                Instant::now() < drain_deadline,
                "probe thread did not finish after hang cleared"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(store.leaked_disk_probe_threads_for_test(), 0);
        write_tokens_revoking_writer(&path, false);
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("reload recovers after hung probe");
        assert_eq!(store.live_disk_probe_threads_for_test(), 0);
    }

    #[test]
    fn abandoned_probe_refcount_not_leaked_after_serial_timeouts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("warm");
        std::fs::write(&path, b"{bad").unwrap();
        let bound = Duration::from_secs(2) + Duration::from_millis(400);
        for round in 0..2 {
            {
                let _hang = ReloadProbeHangGuard::enable(&store);
                let wall = Instant::now();
                assert!(
                    matches!(
                        store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
                        Err(TokenError::StoreUnavailable)
                    ),
                    "round {round} must fail closed"
                );
                assert!(
                    wall.elapsed() <= bound,
                    "round {round} must finish within reload window"
                );
            }
            let drain_deadline = Instant::now() + Duration::from_secs(5);
            while store.live_disk_probe_threads_for_test() > 0 {
                assert!(
                    Instant::now() < drain_deadline,
                    "round {round}: probe thread did not finish"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(
                store.leaked_disk_probe_threads_for_test(),
                0,
                "round {round}: abandoned probe refcount leaked"
            );
        }
    }

    #[test]
    fn reload_hung_probe_fails_closed_and_recovers() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("warm");
        std::fs::write(&path, b"{bad").unwrap();
        let bound = Duration::from_secs(2) + Duration::from_millis(400);
        {
            let _hang = ReloadProbeHangGuard::enable(&store);
            let wall = Instant::now();
            assert!(matches!(
                store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
                Err(TokenError::StoreUnavailable)
            ));
            assert!(
                wall.elapsed() <= bound,
                "first hung probe must fail closed within the reload window"
            );
            let wall2 = Instant::now();
            assert!(matches!(
                store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
                Err(TokenError::StoreUnavailable)
            ));
            assert!(
                wall2.elapsed() <= bound,
                "follow-up reload must stay bounded while probe hangs"
            );
        }
        let drain_deadline = Instant::now() + Duration::from_secs(5);
        while store.live_disk_probe_threads_for_test() > 0 {
            assert!(
                Instant::now() < drain_deadline,
                "probe thread did not finish after hang cleared"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        write_tokens_revoking_writer(&path, false);
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("reload recovers after hung probe");
    }

    #[test]
    fn reload_concurrent_transient_single_flight() {
        use std::sync::Barrier;
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = Arc::new(TokenStore::load_insecure(path.clone()).expect("load"));
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("warm");
        std::fs::write(&path, b"{bad").unwrap();
        let barrier = Arc::new(Barrier::new(4));
        let wall = Instant::now();
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let _ = store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan);
                })
            })
            .collect();
        for h in handles {
            h.join().expect("join");
        }
        assert!(
            wall.elapsed() <= Duration::from_secs(2) + Duration::from_millis(300),
            "four concurrent first-outage verifies must share one transient retry window"
        );
    }

    #[cfg(unix)]
    #[test]
    fn reload_insecure_symlink_fails_closed_immediately() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = tmp.path().join("tokens.real.json");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&real, false);
        std::os::unix::fs::symlink(&real, &path).expect("symlink");
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("warm");
        store.set_enforce_secure_reload_for_test(true);
        assert!(matches!(
            store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
            Err(TokenError::InsecurePermissions)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn reload_insecure_mode_fails_closed_immediately() {
        use std::os::unix::fs::PermissionsExt;
        if !nix::unistd::getuid().is_root() {
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("warm");
        store.set_enforce_secure_reload_for_test(true);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
            Err(TokenError::InsecurePermissions)
        ));
    }

    #[test]
    fn reload_revoke_honored_after_outage_recovers() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("warm");
        std::fs::write(&path, b"{bad").unwrap();
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("grace snapshot");
        std::thread::sleep(Duration::from_millis(2100));
        assert!(matches!(
            store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
            Err(TokenError::StoreUnavailable)
        ));
        write_tokens_revoking_writer(&path, true);
        assert!(matches!(
            store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
            Err(TokenError::Revoked)
        ));
    }

    #[test]
    fn reload_revoke_never_missed_after_load_stress() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        const ROUNDS: usize = 200;
        for i in 0..ROUNDS {
            store
                .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
                .expect("warm load");
            write_tokens_revoking_writer(&path, true);
            let err = store
                .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
                .expect_err("revoke must be visible immediately");
            assert!(
                matches!(err, TokenError::Revoked),
                "missed revoke on iteration {i}: {err:?}"
            );
            write_tokens_revoking_writer(&path, false);
        }
    }

    #[cfg(unix)]
    fn open_fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .map(|d| d.count())
            .unwrap_or(0)
    }

    #[cfg(unix)]
    #[test]
    fn fifo_read_closes_fd_on_every_exit_path() {
        use nix::sys::stat::Mode;
        use std::sync::atomic::AtomicBool;

        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        nix::unistd::mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR).expect("mkfifo");
        let baseline = open_fd_count();
        let cancel = AtomicBool::new(true);
        for _ in 0..40 {
            assert!(matches!(
                TokenStore::try_read_fifo_tokens_bytes(&path, Some(&cancel)),
                Err(DiskFingerprint::Unreadable)
            ));
        }
        let after_cancel = open_fd_count();
        assert!(
            after_cancel <= baseline + 2,
            "cancel exits must not leak FIFO fds (baseline={baseline}, after={after_cancel})"
        );

        let cancel_live = AtomicBool::new(false);
        let path_feed = path.clone();
        let feeder = std::thread::spawn(move || {
            use std::io::Write;
            let file = crate::test_util::default_tokens_file();
            let bytes = serde_json::to_vec_pretty(&file).expect("json");
            let mut w = std::fs::OpenOptions::new()
                .write(true)
                .open(&path_feed)
                .expect("open fifo for write");
            w.write_all(&bytes).expect("write tokens");
        });
        let ok = TokenStore::try_read_fifo_tokens_bytes(&path, Some(&cancel_live));
        feeder.join().expect("join feeder");
        assert!(ok.is_ok(), "expected valid fifo read, got {ok:?}");
        let after_ok = open_fd_count();
        assert!(
            after_ok <= baseline + 2,
            "successful fifo read must close fd (baseline={baseline}, after={after_ok})"
        );
    }
}
