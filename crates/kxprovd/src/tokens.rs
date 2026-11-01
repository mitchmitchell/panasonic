//! Daemon token store: verify bearer secrets (hashed on disk only).

use kxprov_api::{
    hash_bearer_secret, validate_tokens_file, Scope, TokenEntry, TokenId, TokenValidationError,
    TokensFile,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
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
    /// Earliest moment in this outage episode the cached entries stopped being
    /// confirmed by disk: the start of the first stalled probe, or the outage
    /// start if that is earlier. [`TokenStore::max_stale_serve`] is measured
    /// from here when an answer is returned.
    stale_since: Option<Instant>,
    /// After grace expires, reject bearer auth until a good reload succeeds.
    store_unavailable: bool,
    store_unavailable_logged: bool,
    /// Initial 3-try window already consumed for this outage episode.
    reload_transient_done: bool,
    /// Fingerprint of the last failed on-disk payload (avoid re-reading unchanged bad bytes).
    reload_failed_disk_fingerprint: Option<DiskFingerprint>,
    /// Bumped by every good merge. A bad probe whose plan saw an older value
    /// predates that recovery and must not re-open or latch the outage.
    merge_generation: u64,
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
    merge_generation: u64,
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
        /// When the file was last seen bad. The grace is judged from this,
        /// not from when the result is merged, so a probe thread that was
        /// scheduled late does not use up the grace by itself.
        last_bad_read: Instant,
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
    /// How many callers have led a transient retry window.
    #[cfg(test)]
    leaders: AtomicUsize,
}

#[cfg(feature = "test-util")]
static PROBE_JOIN_HANDLES: Mutex<Vec<std::thread::JoinHandle<()>>> = Mutex::new(Vec::new());

#[cfg(feature = "test-util")]
thread_local! {
    static RELOAD_WAITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
type AbandonHook = Box<dyn FnOnce() + Send>;

#[cfg(test)]
thread_local! {
    /// Test-only override of [`TokenStore::reload_grace_duration`].
    ///
    /// Thread-local, so it affects only the thread that set it: the caller
    /// that computes the grace and the delivery deadline. A
    /// `token-reload-probe` thread never sees it, so a helper using this stops
    /// working if any grace or deadline is ever computed on the probe thread.
    static RELOAD_GRACE_OVERRIDE: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

pub struct TokenStore {
    inner: Arc<Mutex<TokenState>>,
    job_queue: Arc<Mutex<Option<Weak<JobQueue>>>>,
    transient_flight: Arc<TransientReloadFlight>,
    /// At most one in-flight recv coordinating a probe spawn.
    disk_probe_live: Arc<AtomicUsize>,
    /// OS `token-reload-probe` threads currently running (including abandoned).
    probe_threads_alive: Arc<AtomicUsize>,
    probe_exit_signal: Arc<ProbeExitSignal>,
    /// Path identity the in-flight recv opened (dev/ino).
    probe_path_identity: Arc<Mutex<Option<PathIdentity>>>,
    /// Inodes abandoned probes still hold open; block respawn until thread exits.
    abandoned_probe_refcounts: Arc<Mutex<HashMap<PathIdentity, usize>>>,
    /// When set, the live probe's guard must not decrement `disk_probe_live`.
    active_probe_abandon: Arc<Mutex<Option<ActiveProbe>>>,
    /// After a bounded probe times out, deny reload briefly without spawning.
    probe_fast_fail_until: Arc<Mutex<Option<Instant>>>,
    #[cfg(feature = "test-util")]
    reload_probe_hang: Arc<AtomicBool>,
    /// Runs inside `abandon_stuck_probe` between reading `exited` and counting
    /// the probe, with the refcount lock held.
    #[cfg(test)]
    abandon_hook: Arc<Mutex<Option<AbandonHook>>>,
    /// Runs on the probe thread right after it sends its result.
    #[cfg(test)]
    after_send_hook: Arc<Mutex<Option<AbandonHook>>>,
    /// Runs on the probe thread right before it sends its result.
    #[cfg(test)]
    before_send_hook: Arc<Mutex<Option<AbandonHook>>>,
    /// Runs on the caller right after it merges a probe result, before it
    /// releases the probe slot.
    #[cfg(test)]
    after_merge_hook: Arc<Mutex<Option<AbandonHook>>>,
    /// Runs on the caller after its probe timed out and was abandoned, before
    /// the timeout is merged.
    #[cfg(test)]
    after_timeout_hook: Arc<Mutex<Option<AbandonHook>>>,
}

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
            probe_exit_signal: Arc::clone(&self.probe_exit_signal),
            probe_path_identity: Arc::clone(&self.probe_path_identity),
            abandoned_probe_refcounts: Arc::clone(&self.abandoned_probe_refcounts),
            active_probe_abandon: Arc::clone(&self.active_probe_abandon),
            probe_fast_fail_until: Arc::clone(&self.probe_fast_fail_until),
            #[cfg(feature = "test-util")]
            reload_probe_hang: Arc::clone(&self.reload_probe_hang),
            #[cfg(test)]
            abandon_hook: Arc::clone(&self.abandon_hook),
            #[cfg(test)]
            after_send_hook: Arc::clone(&self.after_send_hook),
            #[cfg(test)]
            before_send_hook: Arc::clone(&self.before_send_hook),
            #[cfg(test)]
            after_merge_hook: Arc::clone(&self.after_merge_hook),
            #[cfg(test)]
            after_timeout_hook: Arc::clone(&self.after_timeout_hook),
        }
    }
}

impl TransientReloadFlight {
    fn new() -> Self {
        Self {
            inner: Mutex::new(TransientFlightState::Idle),
            cv: Condvar::new(),
            #[cfg(test)]
            leaders: AtomicUsize::new(0),
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
        let mut guard = lock_ignoring_poison(&self.flight.inner);
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

/// Signalled each time a `token-reload-probe` thread starts or exits.
///
/// The count is changed while `lock` is held so a waiter that checked the
/// count under the lock cannot miss the wakeup.
struct ProbeExitSignal {
    lock: Mutex<()>,
    cv: Condvar,
}

struct ProbeThreadSlotGuard {
    alive: Arc<AtomicUsize>,
    exit_signal: Arc<ProbeExitSignal>,
}

impl Drop for ProbeThreadSlotGuard {
    fn drop(&mut self) {
        let _held = lock_ignoring_poison(&self.exit_signal.lock);
        self.alive.fetch_sub(1, Ordering::AcqRel);
        self.exit_signal.cv.notify_all();
    }
}

/// Locks `mutex`, recovering the guard if it is poisoned.
///
/// Every value behind these locks is a counter, map or flag that each writer
/// leaves consistent before it can panic, so the data stays valid after
/// poisoning. Panicking here instead would abort the process when a caller
/// runs during unwinding, such as a `Drop` impl.
fn lock_ignoring_poison<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One probe thread's share of `abandoned_probe_refcounts`.
///
/// `exited` and `counted` change only while the refcount lock is held, so the
/// thread's exit and the caller's abandon step agree on whether the thread
/// still owes a decrement, whichever runs first.
struct ProbeTicket {
    identity: Option<PathIdentity>,
    exited: AtomicBool,
    counted: AtomicBool,
    /// Runs on the exiting probe thread right before it takes the refcount lock.
    #[cfg(test)]
    exit_lock_hook: Mutex<Option<AbandonHook>>,
}

impl ProbeTicket {
    fn new(identity: Option<PathIdentity>) -> Arc<Self> {
        Arc::new(Self {
            identity,
            exited: AtomicBool::new(false),
            counted: AtomicBool::new(false),
            #[cfg(test)]
            exit_lock_hook: Mutex::new(None),
        })
    }
}

struct ActiveProbe {
    abandoned: Arc<AtomicBool>,
    ticket: Arc<ProbeTicket>,
}

struct ProbeThreadAliveGuard {
    ticket: Arc<ProbeTicket>,
    abandoned_refcounts: Arc<Mutex<HashMap<PathIdentity, usize>>>,
}

impl Drop for ProbeThreadAliveGuard {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(hook) = lock_ignoring_poison(&self.ticket.exit_lock_hook).take() {
            hook();
        }
        let mut map = lock_ignoring_poison(&self.abandoned_refcounts);
        self.ticket.exited.store(true, Ordering::Release);
        if !self.ticket.counted.load(Ordering::Acquire) {
            return;
        }
        if let Some(id) = self.ticket.identity {
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

/// The store's one live disk-probe slot, held by the caller that started
/// the probe.
///
/// The caller drops it only after it has merged the probe's result, so no
/// second probe can start while a result is still undelivered, and a finished
/// probe thread never keeps the slot busy for the next caller.
struct DiskProbeLiveGuard {
    live: Arc<AtomicUsize>,
    fast_fail_until: Arc<Mutex<Option<Instant>>>,
    abandoned: Arc<AtomicBool>,
    ticket: Arc<ProbeTicket>,
    active_probe_abandon: Arc<Mutex<Option<ActiveProbe>>>,
    probe_path_identity: Arc<Mutex<Option<PathIdentity>>>,
}

/// A probe result, plus the live slot when this caller started the probe.
struct ProbeOutcome {
    probe: DiskProbe,
    slot: Option<DiskProbeLiveGuard>,
}

impl Drop for DiskProbeLiveGuard {
    fn drop(&mut self) {
        if self.abandoned.swap(true, Ordering::AcqRel) {
            return;
        }
        {
            let mut active = lock_ignoring_poison(&self.active_probe_abandon);
            if active
                .as_ref()
                .is_some_and(|a| Arc::ptr_eq(&a.ticket, &self.ticket))
            {
                *active = None;
                *lock_ignoring_poison(&self.probe_path_identity) = None;
            }
        }
        if self
            .live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_err()
        {
            tracing::error!("disk_probe_live was already 0 when a probe released its slot");
        }
        if self.live.load(Ordering::Acquire) == 0 {
            *lock_ignoring_poison(&self.fast_fail_until) = None;
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

    #[cfg(any(test, feature = "test-util"))]
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
    pub fn live_disk_probe_threads_for_test(&self) -> usize {
        self.probe_threads_alive.load(Ordering::Acquire)
    }

    /// How many times the calling thread has blocked on a probe result or on
    /// the transient flight leader.
    #[cfg(feature = "test-util")]
    pub fn reload_waits_on_this_thread_for_test() -> usize {
        RELOAD_WAITS.with(std::cell::Cell::get)
    }

    /// Blocks until at least one probe thread is running, or `timeout` passes.
    /// Returns whether a probe thread started.
    ///
    /// A poisoned lock is recovered for the reason given on
    /// `lock_ignoring_poison`.
    #[cfg(feature = "test-util")]
    pub fn wait_probe_thread_started_for_test(&self, timeout: Duration) -> bool {
        let held = lock_ignoring_poison(&self.probe_exit_signal.lock);
        let (_held, result) = self
            .probe_exit_signal
            .cv
            .wait_timeout_while(held, timeout, |_| {
                self.probe_threads_alive.load(Ordering::Acquire) == 0
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !result.timed_out()
    }

    /// Blocks until no probe thread is running, or `timeout` passes.
    /// Returns whether every probe thread exited.
    ///
    /// A poisoned lock is recovered for the reason given on
    /// `lock_ignoring_poison`.
    #[cfg(feature = "test-util")]
    pub fn wait_probe_threads_exited_for_test(&self, timeout: Duration) -> bool {
        let held = lock_ignoring_poison(&self.probe_exit_signal.lock);
        let (_held, result) = self
            .probe_exit_signal
            .cv
            .wait_timeout_while(held, timeout, |_| {
                self.probe_threads_alive.load(Ordering::Acquire) > 0
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !result.timed_out()
    }

    /// Ends the probe fast-fail window latched by an earlier call, so the next
    /// call is not refused by it. Clears the latch directly instead of
    /// sleeping until it expires, so tests neither pay real time nor depend on
    /// the scheduler waking them in time.
    #[cfg(feature = "test-util")]
    pub fn clear_probe_fast_fail_window_for_test(&self) {
        *lock_ignoring_poison(&self.probe_fast_fail_until) = None;
    }

    /// Joins every `token-reload-probe` thread spawned so far in this process,
    /// so each one has fully left `/proc/self/task` when this returns.
    ///
    /// Blocks while any probe is still hung; call it only after the hang has
    /// been cleared and no other test in the process can be spawning probes.
    #[cfg(feature = "test-util")]
    pub fn join_probe_threads_for_test() {
        let handles = std::mem::take(&mut *lock_ignoring_poison(&PROBE_JOIN_HANDLES));
        for handle in handles {
            handle.join().expect("token-reload-probe thread panicked");
        }
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
            probe_exit_signal: Arc::new(ProbeExitSignal {
                lock: Mutex::new(()),
                cv: Condvar::new(),
            }),
            probe_path_identity: Arc::new(Mutex::new(None)),
            abandoned_probe_refcounts: Arc::new(Mutex::new(HashMap::new())),
            active_probe_abandon: Arc::new(Mutex::new(None)),
            probe_fast_fail_until: Arc::new(Mutex::new(None)),
            #[cfg(feature = "test-util")]
            reload_probe_hang: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            abandon_hook: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            after_send_hook: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            before_send_hook: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            after_merge_hook: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            after_timeout_hook: Arc::new(Mutex::new(None)),
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
        let mut refcounts = lock_ignoring_poison(&self.abandoned_probe_refcounts);
        if let Some(active) = self
            .active_probe_abandon
            .lock()
            .expect("active probe abandon lock")
            .take()
        {
            if !active.abandoned.swap(true, Ordering::AcqRel) {
                if self
                    .disk_probe_live
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
                    .is_err()
                {
                    tracing::error!("disk_probe_live was already 0 when a probe was abandoned");
                }
                let ticket = &active.ticket;
                let exited = ticket.exited.load(Ordering::Acquire);
                #[cfg(test)]
                if let Some(hook) = lock_ignoring_poison(&self.abandon_hook).take() {
                    hook();
                }
                if !exited {
                    if let Some(id) = ticket.identity {
                        refcounts.entry(id).and_modify(|n| *n += 1).or_insert(1);
                        ticket.counted.store(true, Ordering::Release);
                    }
                }
            }
        }
        drop(refcounts);
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
            if lock_ignoring_poison(&self.abandoned_probe_refcounts)
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
        ticket: &Arc<ProbeTicket>,
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
                .expect("active probe abandon lock") = Some(ActiveProbe {
                abandoned: Arc::clone(&abandoned),
                ticket: Arc::clone(ticket),
            });
            *self
                .probe_path_identity
                .lock()
                .expect("probe path identity lock") = path_identity(path);
            Some(DiskProbeLiveGuard {
                live: Arc::clone(&self.disk_probe_live),
                fast_fail_until: Arc::clone(&self.probe_fast_fail_until),
                abandoned,
                ticket: Arc::clone(ticket),
                active_probe_abandon: Arc::clone(&self.active_probe_abandon),
                probe_path_identity: Arc::clone(&self.probe_path_identity),
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

    #[cfg(any(test, feature = "test-util"))]
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

    /// How long cached entries are served after the tokens file was last seen
    /// good, before bearer access fails closed.
    const RELOAD_GRACE: Duration = Duration::from_secs(2);
    /// How long past the grace a caller waits for a probe thread to deliver.
    const PROBE_DELIVERY_SLACK: Duration = Duration::from_millis(300);
    const RELOAD_MAX_ATTEMPTS: usize = 3;

    fn reload_grace_duration() -> Duration {
        #[cfg(test)]
        if let Some(grace) = RELOAD_GRACE_OVERRIDE.with(std::cell::Cell::get) {
            return grace;
        }
        Self::RELOAD_GRACE
    }

    /// How long a caller waits for a probe result: the grace plus
    /// [`Self::PROBE_DELIVERY_SLACK`].
    fn probe_delivery_deadline() -> Duration {
        Self::reload_grace_duration().saturating_add(Self::PROBE_DELIVERY_SLACK)
    }

    /// Worst-case time a stale or revoked cached entry can still be served,
    /// measured from when the first stalled probe began.
    ///
    /// A stalled probe is abandoned after [`Self::probe_delivery_deadline`];
    /// the outage starts when that timeout is observed, and cached entries are
    /// served for a further [`Self::reload_grace_duration`] before bearer access
    /// fails closed. That is `2 * RELOAD_GRACE + PROBE_DELIVERY_SLACK`, 4.3 s in
    /// production. Saturates at [`Duration::MAX`] instead of panicking.
    ///
    /// Enforced when an answer is returned, not when a request is admitted:
    /// a cached answer is given only while `now - stale_since` is at most this
    /// bound, so a request admitted just before it whose probe then stalls
    /// fails closed instead of returning cached entries late.
    fn max_stale_serve() -> Duration {
        Self::probe_delivery_deadline()
            .checked_add(Self::reload_grace_duration())
            .unwrap_or(Duration::MAX)
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
    ///
    /// A retry is only started before `deadline`, and the returned bad-read time
    /// is the instant that attempt started, so a slow scheduler that wakes the
    /// retry loop late cannot make the leader's own transient window look like
    /// it outlived the grace.
    fn read_tokens_until_deadline(
        path: &Path,
        deadline: Instant,
        cancel: Option<&AtomicBool>,
    ) -> Result<Vec<u8>, (DiskFingerprint, Instant)> {
        let mut last_fp = DiskFingerprint::Missing;
        let mut last_bad_read = Instant::now();
        for attempt in 0..Self::RELOAD_MAX_ATTEMPTS {
            let attempt_at = Instant::now();
            if attempt > 0 && attempt_at >= deadline {
                break;
            }
            last_bad_read = attempt_at;
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
        Err((last_fp, last_bad_read))
    }

    fn clear_reload_outage(state: &mut TokenState, flight: &TransientReloadFlight) {
        state.reload_failure_since = None;
        state.stale_since = None;
        state.store_unavailable = false;
        state.store_unavailable_logged = false;
        state.reload_transient_done = false;
        state.reload_failed_disk_fingerprint = None;
        flight.reset();
    }

    /// A probe that delivered nothing is an outage that began at
    /// `outage_start`; `last_bad_read` is the last moment the file is known to
    /// have been unavailable, which decides whether the grace has run out.
    ///
    /// For a caller that gave up waiting, the outage begins when the timeout is
    /// observed unless an earlier outage is already running, and the stall is
    /// judged by when its probe started: a stall that began inside the grace is
    /// served from cache, one that began after it fails closed.
    fn timed_out_disk_probe(outage_start: Instant, last_bad_read: Instant) -> DiskProbe {
        DiskProbe::StillBad {
            fp: DiskFingerprint::Unreadable,
            outage_start,
            last_bad_read,
        }
    }

    /// The result handed to followers when the leader could not run a probe
    /// at all: an outage whose grace has already run out, so they fail closed.
    fn expired_disk_probe() -> DiskProbe {
        let now = Instant::now();
        let outage_start = now
            .checked_sub(Self::reload_grace_duration())
            .unwrap_or(now);
        Self::timed_out_disk_probe(outage_start, now)
    }

    fn run_disk_probe_off_thread(&self, plan: ReloadPlan) -> Result<ProbeOutcome, TokenError> {
        self.reconcile_stuck_probe_for_path(&plan.path);
        let instant_deny = Self::reload_plan_in_outage(&plan);
        let plan_outage_start = plan.outage_start;
        let wait_until = if instant_deny {
            Instant::now()
        } else {
            Instant::now() + Duration::from_millis(50)
        };
        let abandoned = Arc::new(AtomicBool::new(false));
        let ticket = ProbeTicket::new(path_identity(&plan.path));
        let live_guard = loop {
            self.reconcile_stuck_probe_for_path(&plan.path);
            if self.disk_probe_spawn_denied(&plan.path) {
                self.latch_probe_fast_fail();
                return Err(TokenError::StoreUnavailable);
            }
            if let Some(guard) =
                self.try_begin_disk_probe(&plan.path, Arc::clone(&abandoned), &ticket)
            {
                break guard;
            }
            if instant_deny || Instant::now() >= wait_until {
                return Err(TokenError::StoreUnavailable);
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        let probe_started = Instant::now();
        let timed_out = || {
            Self::timed_out_disk_probe(
                plan_outage_start.unwrap_or_else(Instant::now),
                probe_started,
            )
        };
        let deadline = probe_started
            .checked_add(Self::probe_delivery_deadline())
            .unwrap_or_else(|| {
                tracing::warn!(
                    "token-reload-probe delivery deadline overflows Instant; the probe is treated as timed out so the normal grace applies"
                );
                probe_started
            });
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let probe_alive = Arc::clone(&self.probe_threads_alive);
        let exit_signal = Arc::clone(&self.probe_exit_signal);
        let probe_alive_err = Arc::clone(&probe_alive);
        let exit_signal_err = Arc::clone(&exit_signal);
        let abandoned_refcounts = Arc::clone(&self.abandoned_probe_refcounts);
        let prev = {
            let _held = lock_ignoring_poison(&exit_signal.lock);
            let prev = probe_alive.fetch_add(1, Ordering::AcqRel);
            if prev >= Self::MAX_PROBE_THREADS_ALIVE {
                probe_alive.fetch_sub(1, Ordering::AcqRel);
            } else {
                exit_signal.cv.notify_all();
            }
            prev
        };
        if prev >= Self::MAX_PROBE_THREADS_ALIVE {
            self.latch_probe_fast_fail();
            return Err(TokenError::StoreUnavailable);
        }
        let mut probe_plan = plan;
        probe_plan.probe_cancel = Arc::clone(&abandoned);
        #[cfg(test)]
        let after_send_hook = lock_ignoring_poison(&self.after_send_hook).take();
        #[cfg(test)]
        let before_send_hook = lock_ignoring_poison(&self.before_send_hook).take();
        let spawn_ok = std::thread::Builder::new()
            .name("token-reload-probe".into())
            .spawn(move || {
                let slot = ProbeThreadSlotGuard {
                    alive: probe_alive,
                    exit_signal,
                };
                let thread_guard = ProbeThreadAliveGuard {
                    ticket,
                    abandoned_refcounts,
                };
                let probe = Self::execute_disk_probe(&probe_plan);
                drop(thread_guard);
                drop(slot);
                #[cfg(test)]
                if let Some(hook) = before_send_hook {
                    hook();
                }
                if tx.send(probe).is_err() {
                    tracing::debug!(
                        "token-reload-probe result dropped: the caller stopped waiting for it"
                    );
                }
                #[cfg(test)]
                if let Some(hook) = after_send_hook {
                    hook();
                }
            });
        let spawn_ok = spawn_ok.map(|handle| {
            #[cfg(feature = "test-util")]
            lock_ignoring_poison(&PROBE_JOIN_HANDLES).push(handle);
            #[cfg(not(feature = "test-util"))]
            drop(handle);
        });
        if let Err(e) = spawn_ok {
            {
                let _held = lock_ignoring_poison(&exit_signal_err.lock);
                probe_alive_err.fetch_sub(1, Ordering::AcqRel);
                exit_signal_err.cv.notify_all();
            }
            tracing::error!("token-reload-probe spawn failed: {e}");
            self.latch_probe_fast_fail();
            return Err(TokenError::StoreUnavailable);
        }
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            self.latch_probe_fast_fail();
            self.abandon_stuck_probe();
            self.run_after_timeout_hook();
            return Ok(ProbeOutcome {
                probe: timed_out(),
                slot: None,
            });
        }
        #[cfg(feature = "test-util")]
        RELOAD_WAITS.with(|w| w.set(w.get() + 1));
        match rx.recv_timeout(timeout) {
            Ok(probe) => Ok(ProbeOutcome {
                probe,
                slot: Some(live_guard),
            }),
            Err(_) => {
                self.latch_probe_fast_fail();
                self.abandon_stuck_probe();
                self.run_after_timeout_hook();
                Ok(ProbeOutcome {
                    probe: timed_out(),
                    slot: None,
                })
            }
        }
    }

    fn run_after_timeout_hook(&self) {
        #[cfg(test)]
        if let Some(hook) = lock_ignoring_poison(&self.after_timeout_hook).take() {
            hook();
        }
    }

    fn coordinated_transient_probe(
        &self,
        flight: &TransientReloadFlight,
        plan: ReloadPlan,
    ) -> Result<ProbeOutcome, TokenError> {
        let follower = |probe: DiskProbe| ProbeOutcome { probe, slot: None };
        let follower_outage_start = plan.outage_start.unwrap_or_else(Instant::now);
        let wait_until = follower_outage_start + Self::reload_grace_duration();
        let mut guard = flight.inner.lock().expect("transient flight lock");
        loop {
            match &*guard {
                TransientFlightState::Done(probe) => return Ok(follower(probe.clone())),
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
                        let probe =
                            Self::timed_out_disk_probe(follower_outage_start, Instant::now());
                        *guard = TransientFlightState::Done(probe.clone());
                        flight.cv.notify_all();
                        return Ok(follower(probe));
                    }
                    #[cfg(feature = "test-util")]
                    RELOAD_WAITS.with(|w| w.set(w.get() + 1));
                    let (g, wait) = flight
                        .cv
                        .wait_timeout(guard, remaining)
                        .expect("transient flight wait");
                    guard = g;
                    if wait.timed_out() && matches!(*guard, TransientFlightState::Running) {
                        let probe =
                            Self::timed_out_disk_probe(follower_outage_start, Instant::now());
                        *guard = TransientFlightState::Done(probe.clone());
                        flight.cv.notify_all();
                        return Ok(follower(probe));
                    }
                }
                TransientFlightState::Idle => {
                    *guard = TransientFlightState::Running;
                    #[cfg(test)]
                    flight.leaders.fetch_add(1, Ordering::AcqRel);
                    drop(guard);
                    let _leader =
                        TransientProbeLeaderGuard::new(flight, Self::expired_disk_probe());
                    let probe = match self.run_disk_probe_off_thread(plan.clone()) {
                        Ok(p) => p,
                        Err(TokenError::StoreUnavailable) => {
                            let mut guard = flight.inner.lock().expect("transient flight lock");
                            let probe = Self::expired_disk_probe();
                            *guard = TransientFlightState::Done(probe);
                            flight.cv.notify_all();
                            return Err(TokenError::StoreUnavailable);
                        }
                        Err(e) => return Err(e),
                    };
                    let mut guard = flight.inner.lock().expect("transient flight lock");
                    *guard = TransientFlightState::Done(probe.probe.clone());
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
                        last_bad_read: Instant::now(),
                    };
                }
            }
            return DiskProbe::UnchangedBad;
        }

        let outage_start = plan.outage_start.unwrap_or_else(Instant::now);
        let deadline = outage_start + Self::reload_grace_duration();
        match Self::read_tokens_until_deadline(&plan.path, deadline, Some(&plan.probe_cancel)) {
            Ok(raw) => DiskProbe::Ok(raw),
            Err((fp, last_bad_read)) => DiskProbe::StillBad {
                fp,
                outage_start,
                last_bad_read,
            },
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
            stale_since: None,
            store_unavailable: false,
            store_unavailable_logged: false,
            reload_transient_done: false,
            reload_failed_disk_fingerprint: None,
            merge_generation: 0,
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
            stale_since: None,
            store_unavailable: false,
            store_unavailable_logged: false,
            reload_transient_done: false,
            reload_failed_disk_fingerprint: None,
            merge_generation: 0,
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
            .filter(|t| !t.revoked && t.scopes.contains(&Scope::Approve))
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

    /// Whether `probe` is a bad result from a plan taken before a newer good
    /// merge, so it says nothing about the store as it is now.
    fn bad_probe_predates_newer_generation(
        state: &TokenState,
        plan_generation: u64,
        probe: &DiskProbe,
    ) -> bool {
        !matches!(probe, DiskProbe::Ok(_)) && state.merge_generation != plan_generation
    }

    /// Merges `probe`, taken from a plan that saw `plan_generation`.
    ///
    /// A bad result (`StillBad`, `UnchangedBad`, or a timeout's synthetic
    /// `StillBad`) from before a newer good merge is dropped: it cannot
    /// re-open the outage, move `stale_since`, or latch the store.
    fn merge_disk_probe(
        state: &mut TokenState,
        flight: &TransientReloadFlight,
        plan_generation: u64,
        probe: DiskProbe,
    ) -> Result<TokenRefreshDelta, TokenError> {
        if Self::bad_probe_predates_newer_generation(state, plan_generation, &probe) {
            return Ok(Self::empty_refresh_delta());
        }
        match probe {
            DiskProbe::Ok(raw) => {
                let delta = Self::apply_reloaded_bytes(state, raw)?;
                Self::clear_reload_outage(state, flight);
                state.merge_generation = state.merge_generation.wrapping_add(1);
                Ok(delta)
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
            DiskProbe::StillBad {
                fp,
                outage_start,
                last_bad_read,
            } => {
                let outage_start = state
                    .reload_failure_since
                    .map_or(outage_start, |since| since.min(outage_start));
                state.reload_failure_since = Some(outage_start);
                let stale_from = outage_start.min(last_bad_read);
                state.stale_since = Some(
                    state
                        .stale_since
                        .map_or(stale_from, |since| since.min(stale_from)),
                );
                state.reload_transient_done = true;
                state.reload_failed_disk_fingerprint = Some(fp);
                if last_bad_read.saturating_duration_since(outage_start)
                    >= Self::reload_grace_duration()
                    || state.store_unavailable
                {
                    Err(Self::latch_store_unavailable(state))
                } else {
                    Ok(Self::empty_refresh_delta())
                }
            }
        }
    }

    /// Fails closed. Inside an outage the failure is latched so a later
    /// `UnchangedBad` probe cannot serve cached entries; before an outage starts
    /// (the first-blip grace window) it is not, so one concurrent caller does not
    /// end the grace for everyone.
    ///
    /// `during_outage` comes from the caller's pre-probe snapshot, so the
    /// current state is checked again under the lock: if another caller has
    /// recovered the store since, nothing is latched.
    fn fail_closed(&self, during_outage: bool) -> TokenError {
        if !during_outage {
            return TokenError::StoreUnavailable;
        }
        let mut state = self.inner.lock().expect("token store lock");
        if !Self::state_in_outage(&state) {
            return TokenError::StoreUnavailable;
        }
        Self::latch_store_unavailable(&mut state)
    }

    /// Fails closed, latching the outage, when a cached answer at `now` would
    /// be older than [`Self::max_stale_serve`] measured from `stale_since`.
    fn enforce_max_stale_serve(state: &mut TokenState, now: Instant) -> Result<(), TokenError> {
        match state.stale_since {
            Some(since) if now.saturating_duration_since(since) > Self::max_stale_serve() => {
                Err(Self::latch_store_unavailable(state))
            }
            _ => Ok(()),
        }
    }

    fn state_in_outage(state: &TokenState) -> bool {
        state.reload_failure_since.is_some() || state.reload_transient_done
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
                merge_generation: state.merge_generation,
                probe_cancel: Arc::new(AtomicBool::new(false)),
                #[cfg(feature = "test-util")]
                probe_hang: Arc::clone(&self.reload_probe_hang),
            }
        };

        let plan_generation = plan.merge_generation;
        let during_outage = Self::reload_plan_in_outage(&plan);
        if self.disk_reload_blocked_now(during_outage, &plan.path) {
            return Err(self.fail_closed(during_outage));
        }
        if during_outage {
            self.reconcile_stuck_probe_for_path(&plan.path);
        }

        let probe = if plan.transient_done {
            self.run_disk_probe_off_thread(plan)
        } else {
            self.coordinated_transient_probe(&self.transient_flight, plan)
        };
        let ProbeOutcome { probe, slot } = match probe {
            Ok(p) => p,
            Err(TokenError::StoreUnavailable) => return Err(self.fail_closed(during_outage)),
            Err(e) => return Err(e),
        };

        let mut state = self.inner.lock().expect("token store lock");
        let merged =
            Self::merge_disk_probe(&mut state, &self.transient_flight, plan_generation, probe)
                .and_then(|delta| {
                    Self::enforce_max_stale_serve(&mut state, Instant::now())?;
                    Ok(delta)
                });
        #[cfg(test)]
        if slot.is_some() {
            if let Some(hook) = lock_ignoring_poison(&self.after_merge_hook).take() {
                hook();
            }
        }
        drop(slot);
        merged
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
        let merge_generation = state.merge_generation;
        *state = fresh;
        state.enforce_secure_reload = enforce_secure;
        state.merge_generation = merge_generation;
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
        if !entry.scopes.contains(&need) {
            return Err(TokenError::ScopeDenied);
        }
        Ok(VerifiedToken {
            id: entry.id.clone(),
            scopes: entry.scopes.clone(),
        })
    }

    /// Validate bearer credentials and return token identity without requiring a specific scope.
    pub fn verify_bearer_identity(
        &self,
        bearer: &str,
        now_ms: u64,
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
            stale_since: None,
            store_unavailable: false,
            store_unavailable_logged: false,
            reload_transient_done: false,
            reload_failed_disk_fingerprint: None,
            merge_generation: 0,
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

    const TEST_BODY_BOUND: Duration = Duration::from_secs(60);

    /// Runs a test body on its own thread and fails the test if it has not
    /// finished within [`TEST_BODY_BOUND`], so a blocking wait that never
    /// returns becomes a failure instead of hanging the suite. The bound is a
    /// safety net for hangs, not a timing assertion.
    fn run_bounded(body: impl FnOnce() + Send + 'static) {
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::Builder::new()
            .name("bounded-test-body".into())
            .spawn(move || {
                let _signals_done_on_drop = done_tx;
                body();
            })
            .expect("spawn test body thread");
        if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
            done_rx.recv_timeout(TEST_BODY_BOUND)
        {
            panic!(
                "test body did not finish within {TEST_BODY_BOUND:?}: a blocking wait never returned"
            );
        }
        if let Err(payload) = handle.join() {
            std::panic::resume_unwind(payload);
        }
    }

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

    fn arm_active_probe(store: &TokenStore, path: &Path) -> Arc<ProbeTicket> {
        let ticket = ProbeTicket::new(path_identity(path));
        store.disk_probe_live.store(1, Ordering::Release);
        *store.probe_path_identity.lock().unwrap() = path_identity(path);
        *store.active_probe_abandon.lock().unwrap() = Some(ActiveProbe {
            abandoned: Arc::new(AtomicBool::new(false)),
            ticket: Arc::clone(&ticket),
        });
        ticket
    }

    fn probe_thread_exit(store: &TokenStore, ticket: Arc<ProbeTicket>) {
        drop(ProbeThreadAliveGuard {
            ticket,
            abandoned_refcounts: Arc::clone(&store.abandoned_probe_refcounts),
        });
    }

    #[test]
    fn probe_that_exits_before_it_is_abandoned_leaves_no_refcount() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        let ticket = arm_active_probe(&store, &path);
        probe_thread_exit(&store, ticket);
        store.abandon_stuck_probe();
        assert_eq!(store.leaked_disk_probe_threads_for_test(), 0);
        assert!(!store.disk_probe_spawn_denied(&path));
    }

    #[test]
    fn probe_abandoned_while_running_is_counted_until_it_exits() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        let ticket = arm_active_probe(&store, &path);
        store.abandon_stuck_probe();
        assert_eq!(store.leaked_disk_probe_threads_for_test(), 1);
        assert!(store.disk_probe_spawn_denied(&path));
        probe_thread_exit(&store, ticket);
        assert_eq!(store.leaked_disk_probe_threads_for_test(), 0);
    }

    #[test]
    fn probe_exiting_while_abandon_holds_the_lock_leaves_no_refcount() {
        run_bounded(|| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let path = tmp.path().join("tokens.json");
            write_tokens_revoking_writer(&path, false);
            let store = TokenStore::load_insecure(path.clone()).expect("load");
            let ticket = arm_active_probe(&store, &path);
            let (at_lock_tx, at_lock_rx) = std::sync::mpsc::channel();
            *ticket.exit_lock_hook.lock().unwrap() = Some(Box::new(move || {
                at_lock_tx.send(()).unwrap();
            }));
            let watched = Arc::clone(&ticket);
            let exiter_store = store.clone();
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let done_rx = Arc::new(Mutex::new(done_rx));
            let hook_rx = Arc::clone(&done_rx);
            let exiter = Arc::new(Mutex::new(None));
            let exiter_slot = Arc::clone(&exiter);
            *store.abandon_hook.lock().unwrap() = Some(Box::new(move || {
                *exiter_slot.lock().unwrap() = Some(std::thread::spawn(move || {
                    probe_thread_exit(&exiter_store, ticket);
                    done_tx.send(()).unwrap();
                }));
                assert!(
                at_lock_rx.recv_timeout(Duration::from_secs(10)).is_ok(),
                "exiting probe never reached the refcount lock: the 10 s limit only catches a deadlock"
            );
                assert!(
                    !watched.exited.load(Ordering::Acquire),
                    "probe marked itself exited before taking the refcount lock"
                );
                assert!(
                    hook_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(2))
                        .is_err(),
                    "probe exit finished while abandon held the refcount lock"
                );
            }));
            store.abandon_stuck_probe();
            let handle = exiter.lock().unwrap().take().expect("hook ran");
            handle.join().expect("exiter");
            done_rx.lock().unwrap().recv().expect("exiter finished");
            assert_eq!(store.leaked_disk_probe_threads_for_test(), 0);
            assert!(!store.disk_probe_spawn_denied(&path));
        });
    }

    #[test]
    fn probe_slot_is_held_until_the_result_is_merged_then_freed() {
        run_bounded(|| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let path = tmp.path().join("tokens.json");
            write_tokens_revoking_writer(&path, false);
            let store = TokenStore::load_insecure(path.clone()).expect("load");
            let live_before_send = Arc::new(AtomicUsize::new(usize::MAX));
            let second_probe_started = Arc::new(AtomicBool::new(true));
            {
                let live = Arc::clone(&live_before_send);
                let started = Arc::clone(&second_probe_started);
                let probing = store.clone();
                let probe_path = path.clone();
                *store.before_send_hook.lock().unwrap() = Some(Box::new(move || {
                    live.store(
                        probing.disk_probe_live.load(Ordering::Acquire),
                        Ordering::Release,
                    );
                    let ticket = ProbeTicket::new(path_identity(&probe_path));
                    let second = probing.try_begin_disk_probe(
                        &probe_path,
                        Arc::new(AtomicBool::new(false)),
                        &ticket,
                    );
                    started.store(second.is_some(), Ordering::Release);
                }));
            }
            let live_at_merge = Arc::new(AtomicUsize::new(usize::MAX));
            {
                let live = Arc::clone(&live_at_merge);
                let merging = store.clone();
                *store.after_merge_hook.lock().unwrap() = Some(Box::new(move || {
                    live.store(
                        merging.disk_probe_live.load(Ordering::Acquire),
                        Ordering::Release,
                    );
                }));
            }
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            *store.after_send_hook.lock().unwrap() = Some(Box::new(move || {
                assert!(
                    release_rx.recv_timeout(Duration::from_secs(10)).is_ok(),
                    "test never released the probe thread: the 10 s limit only catches a deadlock"
                );
            }));
            write_tokens_revoking_writer(&path, true);
            assert!(matches!(
                store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
                Err(TokenError::Revoked)
            ));
            let live_after_merge = store.disk_probe_live.load(Ordering::Acquire);
            let threads_after_merge = store.live_disk_probe_threads_for_test();
            release_tx.send(()).expect("release probe thread");
            assert!(store.wait_probe_threads_exited_for_test(Duration::from_secs(10)));
            assert_eq!(
                live_before_send.load(Ordering::Acquire),
                1,
                "the probe slot was free before the result was delivered"
            );
            assert_eq!(
                live_at_merge.load(Ordering::Acquire),
                1,
                "the probe slot was free before the result was merged"
            );
            assert!(
                !second_probe_started.load(Ordering::Acquire),
                "a second probe started while the first result was undelivered"
            );
            assert_eq!(
                live_after_merge, 0,
                "the probe slot stayed busy after the result was merged"
            );
            assert_eq!(
                threads_after_merge, 0,
                "a finished probe thread still counted as alive after sending its result"
            );
            assert!(store.active_probe_abandon.lock().unwrap().is_none());
            assert!(store.probe_path_identity.lock().unwrap().is_none());
        });
    }

    impl TokenStore {
        fn merge_at_current_generation(
            state: &mut TokenState,
            flight: &TransientReloadFlight,
            probe: DiskProbe,
        ) -> Result<TokenRefreshDelta, TokenError> {
            let generation = state.merge_generation;
            Self::merge_disk_probe(state, flight, generation, probe)
        }
    }

    fn backdate_outage_for_test(store: &TokenStore, by: Duration) {
        let mut state = store.inner.lock().unwrap();
        let back = |t: Instant| t.checked_sub(by).expect("backdate within Instant range");
        state.reload_failure_since = state.reload_failure_since.map(back);
        state.stale_since = state.stale_since.map(back);
    }

    #[test]
    fn reload_keeps_the_merge_generation_so_a_bad_probe_from_before_two_good_merges_is_dropped() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        let mut state = store.inner.lock().unwrap();
        let start_generation = state.merge_generation;

        write_tokens_revoking_writer(&path, true);
        let revoked = std::fs::read(&path).expect("read revoked tokens");
        TokenStore::merge_at_current_generation(
            &mut state,
            &store.transient_flight,
            DiskProbe::Ok(revoked),
        )
        .expect("first good merge");
        let plan_generation = state.merge_generation;
        assert_eq!(plan_generation, start_generation.wrapping_add(1));

        write_tokens_revoking_writer(&path, false);
        let restored = std::fs::read(&path).expect("read restored tokens");
        TokenStore::merge_at_current_generation(
            &mut state,
            &store.transient_flight,
            DiskProbe::Ok(restored),
        )
        .expect("second good merge");
        assert_eq!(
            state.merge_generation,
            plan_generation.wrapping_add(1),
            "a reload that replaces the state must keep counting merge generations"
        );

        let now = Instant::now();
        let outage_start = now
            .checked_sub(Duration::from_secs(30))
            .expect("backdate within Instant range");
        let stale = TokenStore::merge_disk_probe(
            &mut state,
            &store.transient_flight,
            plan_generation,
            DiskProbe::StillBad {
                fp: DiskFingerprint::Unreadable,
                outage_start,
                last_bad_read: now,
            },
        );
        assert!(
            stale.is_ok(),
            "a bad probe planned before the second good merge must be dropped"
        );
        assert!(
            !state.store_unavailable,
            "the stale bad probe latched the store"
        );
        assert!(
            state.reload_failure_since.is_none() && state.stale_since.is_none(),
            "the stale bad probe re-opened the outage"
        );
    }

    #[test]
    fn ok_probe_failing_validation_keeps_the_latch_for_an_older_still_bad() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        let mut file = crate::test_util::default_tokens_file();
        let mut duplicate = None;
        for t in &mut file.tokens {
            if t.id.as_str() == "writer" {
                t.revoked = true;
                duplicate = Some(t.clone());
            }
        }
        file.tokens
            .push(duplicate.expect("default file has a writer token"));
        TokenStore::write_test_file(&path, &file).expect("write duplicate-id tokens");
        let invalid_raw = std::fs::read(&path).expect("read duplicate-id tokens");
        let start = Instant::now()
            .checked_sub(Duration::from_secs(30))
            .expect("backdate within Instant range");
        let mut state = store.inner.lock().unwrap();
        state.reload_failure_since = Some(start);
        state.stale_since = Some(start);
        state.reload_transient_done = true;
        state.reload_failed_disk_fingerprint = Some(DiskFingerprint::Unreadable);
        TokenStore::latch_store_unavailable(&mut state);
        let plan_generation = state.merge_generation;
        assert!(
            TokenStore::merge_disk_probe(
                &mut state,
                &store.transient_flight,
                plan_generation,
                DiskProbe::Ok(invalid_raw),
            )
            .is_err(),
            "a duplicate-id file must fail validation"
        );
        assert!(state.store_unavailable, "a failed apply cleared the latch");
        assert_eq!(
            state.stale_since,
            Some(start),
            "a failed apply moved stale_since"
        );
        assert_eq!(
            state.merge_generation, plan_generation,
            "a failed apply bumped merge_generation"
        );
        let concurrent = TokenStore::merge_disk_probe(
            &mut state,
            &store.transient_flight,
            plan_generation,
            DiskProbe::StillBad {
                fp: DiskFingerprint::Unreadable,
                outage_start: start,
                last_bad_read: Instant::now(),
            },
        );
        assert!(
            matches!(concurrent, Err(TokenError::StoreUnavailable)),
            "the concurrent StillBad was dropped instead of failing closed"
        );
        assert!(state.store_unavailable);
        assert_eq!(state.stale_since, Some(start));
        drop(state);
        let answer = store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan);
        assert!(
            answer.is_err(),
            "a token revoked on disk was served from cache after a latched outage: {answer:?}"
        );
        assert!(store.inner.lock().unwrap().store_unavailable);
    }

    #[test]
    fn timed_out_merge_after_a_newer_good_merge_does_not_reopen_the_outage() {
        run_bounded(|| {
            let grace = Duration::from_millis(50);
            let _grace = GraceOverride::set(grace);
            let tmp = tempfile::tempdir().expect("tempdir");
            let path = tmp.path().join("tokens.json");
            write_tokens_revoking_writer(&path, false);
            let store = TokenStore::load_insecure(path.clone()).expect("load");
            {
                let mut state = store.inner.lock().unwrap();
                let start = Instant::now()
                    .checked_sub(grace * 4)
                    .expect("backdate within Instant range");
                state.reload_failure_since = Some(start);
                state.stale_since = Some(start);
                state.reload_transient_done = true;
                state.reload_failed_disk_fingerprint = Some(DiskFingerprint::Unreadable);
            }
            let release = block_next_probe_delivery(&store);
            let good_merged = Arc::new(AtomicBool::new(false));
            {
                let merging = store.clone();
                let good_path = path.clone();
                let merged = Arc::clone(&good_merged);
                *store.after_timeout_hook.lock().unwrap() = Some(Box::new(move || {
                    let raw = std::fs::read(&good_path).expect("read good tokens");
                    let mut state = merging.inner.lock().unwrap();
                    TokenStore::merge_at_current_generation(
                        &mut state,
                        &merging.transient_flight,
                        DiskProbe::Ok(raw),
                    )
                    .expect("good merge");
                    merged.store(true, Ordering::Release);
                }));
            }
            let answer = store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan);
            assert!(
            good_merged.load(Ordering::Acquire),
            "the first probe must time out so the good merge lands between its timeout and its merge"
        );
            assert!(
                answer.is_ok(),
                "a timeout older than a good merge must not refuse a valid store: {answer:?}"
            );
            {
                let state = store.inner.lock().unwrap();
                assert!(
                    !state.store_unavailable,
                    "the stale timeout latched the store"
                );
                assert!(
                    state.reload_failure_since.is_none() && state.stale_since.is_none(),
                    "the stale timeout re-opened the outage"
                );
                assert!(!state.reload_transient_done);
            }
            let mut state = store.inner.lock().unwrap();
            let stale_generation = state.merge_generation.wrapping_sub(1);
            assert!(TokenStore::merge_disk_probe(
                &mut state,
                &store.transient_flight,
                stale_generation,
                DiskProbe::UnchangedBad,
            )
            .is_ok());
            assert!(!state.store_unavailable);
            assert!(state.reload_failure_since.is_none());
            drop(state);
            release.send(()).expect("release probe");
            assert!(store.wait_probe_threads_exited_for_test(Duration::from_secs(10)));
            store.clear_probe_fast_fail_window_for_test();
            write_tokens_revoking_writer(&path, true);
            assert!(matches!(
                store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
                Err(TokenError::Revoked)
            ));
        });
    }

    struct GraceOverride;

    impl GraceOverride {
        fn set(grace: Duration) -> Self {
            RELOAD_GRACE_OVERRIDE.with(|g| g.set(Some(grace)));
            Self
        }
    }

    impl Drop for GraceOverride {
        fn drop(&mut self) {
            RELOAD_GRACE_OVERRIDE.with(|g| g.set(None));
        }
    }

    fn block_next_probe_delivery(store: &TokenStore) -> std::sync::mpsc::Sender<()> {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        *store.before_send_hook.lock().unwrap() = Some(Box::new(move || {
            assert!(
                release_rx.recv_timeout(Duration::from_secs(10)).is_ok(),
                "test never released the probe thread: the 10 s limit only catches a deadlock"
            );
        }));
        release_tx
    }

    #[test]
    fn probe_timeout_is_an_outage_from_the_observed_timeout_with_normal_grace() {
        run_bounded(|| {
            let _grace = GraceOverride::set(Duration::from_millis(50));
            let tmp = tempfile::tempdir().expect("tempdir");
            let path = tmp.path().join("tokens.json");
            write_tokens_revoking_writer(&path, false);
            let store = TokenStore::load_insecure(path.clone()).expect("load");

            let first = block_next_probe_delivery(&store);
            let before_first = Instant::now();
            store
                .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
                .expect("an undelivered probe starts the grace; cached entries are served");
            let outage_start = {
                let state = store.inner.lock().unwrap();
                assert!(!state.store_unavailable, "a first timeout must not latch");
                state
                    .reload_failure_since
                    .expect("timeout starts an outage")
            };
            assert!(
                outage_start >= before_first + TokenStore::probe_delivery_deadline(),
                "the outage must start when the timeout was observed, not be backdated"
            );

            store.clear_probe_fast_fail_window_for_test();
            let second = block_next_probe_delivery(&store);
            assert!(matches!(
                store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
                Err(TokenError::StoreUnavailable)
            ));
            {
                let state = store.inner.lock().unwrap();
                assert!(state.store_unavailable, "past the grace it fails closed");
                assert_eq!(
                    state.reload_failure_since,
                    Some(outage_start),
                    "a second timeout must not move the outage start"
                );
            }

            first.send(()).expect("release first probe");
            second.send(()).expect("release second probe");
            assert!(store.wait_probe_threads_exited_for_test(Duration::from_secs(10)));
            store.clear_probe_fast_fail_window_for_test();
            store
                .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
                .expect("a good probe ends the outage");
            {
                let state = store.inner.lock().unwrap();
                assert!(!state.store_unavailable);
                assert!(state.reload_failure_since.is_none());
            }
            assert_eq!(store.leaked_disk_probe_threads_for_test(), 0);

            write_tokens_revoking_writer(&path, true);
            assert!(matches!(
                store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
                Err(TokenError::Revoked)
            ));
        });
    }

    /// Merges a first stall that began one delivery deadline before now and
    /// timed out now, and checks that its answer at the observed timeout was
    /// served from cache. Returns the stall start and the outage start.
    ///
    /// A request admitted right after it blocks for at least one more
    /// deadline, so its answer lands at least one slack past
    /// `stall_start + max_stale_serve` and only scheduling delay adds to that.
    /// The overshoot stays small enough that loosening the bound by more than
    /// the slack lets that answer be served.
    fn seed_first_stall_that_just_timed_out(store: &TokenStore) -> (Instant, Instant) {
        let deadline = TokenStore::probe_delivery_deadline();
        let stall_start = Instant::now()
            .checked_sub(deadline)
            .expect("backdate within Instant range");
        let observed_timeout = stall_start + deadline;
        let mut state = store.inner.lock().unwrap();
        assert!(
            TokenStore::merge_at_current_generation(
                &mut state,
                &store.transient_flight,
                TokenStore::timed_out_disk_probe(observed_timeout, stall_start),
            )
            .is_ok(),
            "a first timeout starts the grace; cached entries are served"
        );
        assert!(
            TokenStore::enforce_max_stale_serve(&mut state, observed_timeout).is_ok(),
            "the first stall is answered from cache before the bound"
        );
        assert!(!state.store_unavailable, "a first timeout must not latch");
        assert_eq!(state.stale_since, Some(stall_start));
        assert_eq!(state.reload_failure_since, Some(observed_timeout));
        assert!(state.reload_transient_done);
        (stall_start, observed_timeout)
    }

    /// Runs one verify whose probe never delivers and returns its answer and
    /// how many times it blocked.
    fn verify_with_hung_probe(
        store: &TokenStore,
    ) -> (Result<(), TokenError>, usize, std::sync::mpsc::Sender<()>) {
        store.clear_probe_fast_fail_window_for_test();
        let release = block_next_probe_delivery(store);
        let waits_before = TokenStore::reload_waits_on_this_thread_for_test();
        let answer = store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .map(|_| ());
        let waits = TokenStore::reload_waits_on_this_thread_for_test() - waits_before;
        (answer, waits, release)
    }

    #[test]
    fn stall_after_a_timeout_is_admitted_inside_grace_but_fails_closed_past_max_stale_serve() {
        run_bounded(|| {
            let grace = Duration::from_millis(1000);
            let _grace = GraceOverride::set(grace);
            let tmp = tempfile::tempdir().expect("tempdir");
            let path = tmp.path().join("tokens.json");
            write_tokens_revoking_writer(&path, false);
            let store = TokenStore::load_insecure(path.clone()).expect("load");
            let (stall_start, outage_start) = seed_first_stall_that_just_timed_out(&store);

            let (answer, waits, second) = verify_with_hung_probe(&store);
            assert_eq!(
            waits, 1,
            "the second stall must be admitted to its own probe and block once on its delivery wait"
        );
            assert!(
            matches!(answer, Err(TokenError::StoreUnavailable)),
            "its answer lands past max_stale_serve from the first stall, so it fails closed: {answer:?}"
        );
            assert!(Instant::now() > stall_start + TokenStore::max_stale_serve());
            {
                let state = store.inner.lock().unwrap();
                assert!(state.store_unavailable);
                assert_eq!(state.reload_failure_since, Some(outage_start));
                assert_eq!(state.stale_since, Some(stall_start));
            }

            backdate_outage_for_test(&store, grace);
            let outage_start = outage_start - grace;
            let (answer, _, third) = verify_with_hung_probe(&store);
            assert!(matches!(answer, Err(TokenError::StoreUnavailable)));
            {
                let state = store.inner.lock().unwrap();
                assert!(state.store_unavailable, "past the grace it fails closed");
                assert_eq!(state.reload_failure_since, Some(outage_start));
            }

            second.send(()).expect("release second probe");
            third.send(()).expect("release third probe");
            assert!(store.wait_probe_threads_exited_for_test(Duration::from_secs(10)));
            store.clear_probe_fast_fail_window_for_test();
            store
                .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
                .expect("a good probe ends the outage");
            {
                let state = store.inner.lock().unwrap();
                assert!(!state.store_unavailable);
                assert!(state.reload_failure_since.is_none());
            }
            assert_eq!(store.leaked_disk_probe_threads_for_test(), 0);
        });
    }

    #[test]
    fn max_stale_serve_is_two_graces_plus_delivery_slack() {
        assert_eq!(TokenStore::max_stale_serve(), Duration::from_millis(4300));
    }

    #[test]
    fn cached_answer_is_given_only_within_max_stale_serve_of_the_first_stall_start() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        let grace = TokenStore::reload_grace_duration();
        let bound = TokenStore::max_stale_serve();
        let stall_start = Instant::now();
        let observed_timeout = stall_start + TokenStore::probe_delivery_deadline();
        let mut state = store.inner.lock().unwrap();
        let timed_out = TokenStore::timed_out_disk_probe(observed_timeout, stall_start);
        assert!(TokenStore::merge_at_current_generation(
            &mut state,
            &store.transient_flight,
            timed_out
        )
        .is_ok());
        assert_eq!(state.stale_since, Some(stall_start));
        let later =
            TokenStore::timed_out_disk_probe(observed_timeout, observed_timeout + grace / 4);
        assert!(TokenStore::merge_at_current_generation(
            &mut state,
            &store.transient_flight,
            later
        )
        .is_ok());
        assert_eq!(
            state.stale_since,
            Some(stall_start),
            "a later stall must not move the start the bound is measured from"
        );

        let measured_from = stall_start;
        assert!(
            TokenStore::enforce_max_stale_serve(&mut state, measured_from + bound).is_ok(),
            "an answer exactly at the bound is still served"
        );
        assert!(!state.store_unavailable);
        assert!(matches!(
            TokenStore::enforce_max_stale_serve(
                &mut state,
                measured_from + bound + Duration::from_millis(1)
            ),
            Err(TokenError::StoreUnavailable)
        ));
        assert!(state.store_unavailable, "past the bound it fails closed");
    }

    #[test]
    fn fast_bad_read_inside_grace_after_a_timeout_is_served_from_cache_and_does_not_latch() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        let grace = TokenStore::reload_grace_duration();
        let now = Instant::now();
        let stall_start = now
            .checked_sub(TokenStore::probe_delivery_deadline() + grace / 2)
            .expect("backdate within Instant range");
        let observed_timeout = stall_start + TokenStore::probe_delivery_deadline();
        let mut state = store.inner.lock().unwrap();
        assert!(TokenStore::merge_at_current_generation(
            &mut state,
            &store.transient_flight,
            TokenStore::timed_out_disk_probe(observed_timeout, stall_start)
        )
        .is_ok());
        assert!(!state.store_unavailable, "a single timeout must not latch");

        let fast_bad = DiskProbe::StillBad {
            fp: DiskFingerprint::Unreadable,
            outage_start: now,
            last_bad_read: now,
        };
        assert!(
            TokenStore::merge_at_current_generation(&mut state, &store.transient_flight, fast_bad)
                .is_ok(),
            "a fast bad read half a grace after the timeout is served from cache"
        );
        assert!(
            TokenStore::merge_at_current_generation(
                &mut state,
                &store.transient_flight,
                DiskProbe::UnchangedBad
            )
            .is_ok(),
            "an unchanged bad file half a grace after the timeout is served from cache"
        );
        assert!(TokenStore::enforce_max_stale_serve(&mut state, now).is_ok());
        assert!(
            !state.store_unavailable,
            "reads inside the grace must not latch"
        );
        assert_eq!(state.reload_failure_since, Some(observed_timeout));
        assert_eq!(state.stale_since, Some(stall_start));
        let writer = TokenStore::find_entry(
            &state.entries,
            &hash_bearer_secret(crate::test_util::WRITER_SECRET),
        )
        .expect("cached entries are kept for serving");
        assert!(!writer.revoked);
    }

    #[test]
    fn request_admitted_before_max_stale_serve_whose_probe_stalls_past_it_fails_closed() {
        run_bounded(|| {
            let grace = Duration::from_millis(2000);
            let _grace = GraceOverride::set(grace);
            let bound = TokenStore::max_stale_serve();
            let tmp = tempfile::tempdir().expect("tempdir");
            let path = tmp.path().join("tokens.json");
            write_tokens_revoking_writer(&path, false);
            let store = TokenStore::load_insecure(path.clone()).expect("load");
            let (stall_start, outage_start) = seed_first_stall_that_just_timed_out(&store);
            assert!(
                outage_start < stall_start + bound,
                "a request right after the timeout is admitted before the bound"
            );

            let (answer, waits, second) = verify_with_hung_probe(&store);
            assert_eq!(
                waits, 1,
                "the request must be admitted to its own probe and block once on its delivery wait"
            );
            assert!(
            matches!(answer, Err(TokenError::StoreUnavailable)),
            "its answer arrived past the bound, so cached entries must not be returned: {answer:?}"
        );
            assert!(Instant::now() > stall_start + bound);
            assert!(store.inner.lock().unwrap().store_unavailable);

            second.send(()).expect("release second probe");
            assert!(store.wait_probe_threads_exited_for_test(Duration::from_secs(10)));
            store.clear_probe_fast_fail_window_for_test();
            store
                .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
                .expect("a good probe ends the outage");
            {
                let state = store.inner.lock().unwrap();
                assert!(!state.store_unavailable);
                assert!(state.reload_failure_since.is_none());
                assert!(state.stale_since.is_none());
            }
            assert_eq!(store.leaked_disk_probe_threads_for_test(), 0);

            write_tokens_revoking_writer(&path, true);
            assert!(matches!(
                store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
                Err(TokenError::Revoked)
            ));
        });
    }

    #[test]
    fn a_retry_woken_after_the_transient_deadline_is_not_a_bad_read_past_it() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("missing.json");
        let deadline = Instant::now() + Duration::from_millis(300);
        let (_, last_bad_read) = TokenStore::read_tokens_until_deadline(&path, deadline, None)
            .expect_err("a missing file never reads");
        assert!(
            last_bad_read < deadline,
            "the last bad read must be an attempt started before the deadline"
        );
    }

    #[test]
    fn later_bad_probe_inside_grace_does_not_extend_the_outage() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        let grace = TokenStore::reload_grace_duration();
        let first_start = Instant::now();
        let mut state = store.inner.lock().unwrap();
        let first = TokenStore::timed_out_disk_probe(first_start, first_start);
        assert!(TokenStore::merge_at_current_generation(
            &mut state,
            &store.transient_flight,
            first
        )
        .is_ok());
        let later_start = first_start + grace / 2;
        let later = TokenStore::timed_out_disk_probe(later_start, first_start + grace);
        assert!(matches!(
            TokenStore::merge_at_current_generation(&mut state, &store.transient_flight, later),
            Err(TokenError::StoreUnavailable)
        ));
        assert_eq!(state.reload_failure_since, Some(first_start));
    }

    #[test]
    fn late_merged_first_blip_probe_does_not_latch() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        let now = Instant::now();
        let outage_start = now - TokenStore::reload_grace_duration() * 2;
        let probe = DiskProbe::StillBad {
            fp: DiskFingerprint::Missing,
            outage_start,
            last_bad_read: outage_start + TokenStore::reload_grace_duration() / 2,
        };
        let mut state = store.inner.lock().unwrap();
        assert!(TokenStore::merge_at_current_generation(
            &mut state,
            &store.transient_flight,
            probe
        )
        .is_ok());
        assert!(
            !state.store_unavailable,
            "the file was last seen bad inside the grace, so merging late must not latch"
        );
    }

    #[test]
    fn follower_refusal_before_an_outage_does_not_end_the_first_blip_grace() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("warm");
        std::fs::write(&path, b"{bad").unwrap();
        let _ticket = arm_active_probe(&store, &path);
        *store.transient_flight.inner.lock().unwrap() = TransientFlightState::Running;
        assert!(matches!(
            store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
            Err(TokenError::StoreUnavailable)
        ));
        *store.transient_flight.inner.lock().unwrap() = TransientFlightState::Idle;
        *store.active_probe_abandon.lock().unwrap() = None;
        *store.probe_path_identity.lock().unwrap() = None;
        store.disk_probe_live.store(0, Ordering::Release);
        *store.probe_fast_fail_until.lock().unwrap() = None;
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("still inside the first-blip grace");
    }

    #[test]
    fn hung_disk_probe_never_spawns_more_than_one_live_thread() {
        run_bounded(|| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let path = tmp.path().join("tokens.json");
            write_tokens_revoking_writer(&path, false);
            let store = TokenStore::load_insecure(path.clone()).expect("load");
            store
                .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
                .expect("warm");
            std::fs::write(&path, b"{bad").unwrap();
            let mut waits_after_first = 0;
            {
                let _hang = ReloadProbeHangGuard::enable(&store);
                for i in 0..6 {
                    let waits_before = TokenStore::reload_waits_on_this_thread_for_test();
                    let result =
                        store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan);
                    if i == 0 {
                        assert!(
                            result.is_ok(),
                            "the first hung probe starts the grace and serves cached entries"
                        );
                    } else {
                        assert!(
                            matches!(result, Err(TokenError::StoreUnavailable)),
                            "call {i} must fail closed once the grace has run out"
                        );
                    }
                    assert!(
                        TokenStore::reload_waits_on_this_thread_for_test() - waits_before <= 1,
                        "call {i} must block at most once, on its bounded delivery wait"
                    );
                    assert!(
                        store.leaked_disk_probe_threads_for_test() <= 1,
                        "call {i} abandoned more than the one hung probe"
                    );
                    if i == 0 {
                        waits_after_first = TokenStore::reload_waits_on_this_thread_for_test();
                    }
                    assert_eq!(
                        TokenStore::reload_waits_on_this_thread_for_test(),
                        waits_after_first,
                        "call {i} waited on the reload window instead of failing fast"
                    );
                    assert_eq!(
                        store.live_disk_probe_threads_for_test(),
                        1,
                        "call {i} must reuse the one hung probe instead of spawning another"
                    );
                }
            }
            assert!(
                store.wait_probe_threads_exited_for_test(Duration::from_secs(10)),
                "probe thread did not finish after hang cleared"
            );
            assert_eq!(store.leaked_disk_probe_threads_for_test(), 0);
            write_tokens_revoking_writer(&path, false);
            store
                .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
                .expect("reload recovers after hung probe");
            assert_eq!(
                store.live_disk_probe_threads_for_test(),
                0,
                "the recovery probe must release its slot before it hands back its result"
            );
            assert_eq!(store.leaked_disk_probe_threads_for_test(), 0);
        });
    }

    #[test]
    fn abandoned_probe_refcount_not_leaked_after_serial_timeouts() {
        run_bounded(|| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let path = tmp.path().join("tokens.json");
            write_tokens_revoking_writer(&path, false);
            let store = TokenStore::load_insecure(path.clone()).expect("load");
            store
                .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
                .expect("warm");
            std::fs::write(&path, b"{bad").unwrap();
            for round in 0..2 {
                {
                    let _hang = ReloadProbeHangGuard::enable(&store);
                    let waits_before = TokenStore::reload_waits_on_this_thread_for_test();
                    let result =
                        store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan);
                    if round == 0 {
                        assert!(
                        result.is_ok(),
                        "round 0: a hung probe that starts inside the grace serves cached entries"
                    );
                    } else {
                        assert!(
                        matches!(result, Err(TokenError::StoreUnavailable)),
                        "round {round}: a second hung probe answers past max_stale_serve, so it fails closed"
                    );
                    }
                    assert_eq!(
                    TokenStore::reload_waits_on_this_thread_for_test() - waits_before,
                    1,
                    "round {round}: the call must block only once, on its own probe's bounded delivery wait"
                );
                }
                assert!(
                    store.wait_probe_threads_exited_for_test(Duration::from_secs(10)),
                    "round {round}: probe thread did not finish"
                );
                assert_eq!(
                    store.leaked_disk_probe_threads_for_test(),
                    0,
                    "round {round}: abandoned probe refcount leaked"
                );
            }
        });
    }

    #[test]
    fn reload_hung_probe_fails_closed_and_recovers() {
        run_bounded(|| {
            let _grace = GraceOverride::set(Duration::from_millis(200));
            let tmp = tempfile::tempdir().expect("tempdir");
            let path = tmp.path().join("tokens.json");
            write_tokens_revoking_writer(&path, false);
            let store = TokenStore::load_insecure(path.clone()).expect("load");
            store
                .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
                .expect("warm");
            std::fs::write(&path, b"{bad").unwrap();
            let first = block_next_probe_delivery(&store);
            let waits = TokenStore::reload_waits_on_this_thread_for_test();
            store
                .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
                .expect("the first hung probe starts the grace and serves cached entries");
            assert_eq!(
                TokenStore::reload_waits_on_this_thread_for_test() - waits,
                1,
                "the first hung probe call must block only once, on its bounded delivery wait"
            );

            store.clear_probe_fast_fail_window_for_test();
            let second = block_next_probe_delivery(&store);
            let waits = TokenStore::reload_waits_on_this_thread_for_test();
            assert!(matches!(
                store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
                Err(TokenError::StoreUnavailable)
            ));
            assert!(
                TokenStore::reload_waits_on_this_thread_for_test() - waits <= 1,
                "the follow-up reload must block at most once, on its bounded delivery wait"
            );

            first.send(()).expect("release first probe");
            second.send(()).expect("release second probe");
            assert!(
                store.wait_probe_threads_exited_for_test(Duration::from_secs(10)),
                "probe thread did not finish after it was released"
            );
            store.clear_probe_fast_fail_window_for_test();
            write_tokens_revoking_writer(&path, false);
            store
                .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
                .expect("reload recovers after hung probe");
        });
    }

    #[test]
    fn reload_concurrent_transient_single_flight() {
        use std::sync::Barrier;
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = Arc::new(TokenStore::load_insecure(path.clone()).expect("load"));
        {
            let state = store.inner.lock().unwrap();
            assert!(
                state.reload_failure_since.is_none() && !state.reload_transient_done,
                "a freshly loaded store has no outage, so the four verifies are the first one"
            );
        }
        std::fs::write(&path, b"{bad").unwrap();
        let leaders_before = store.transient_flight.leaders.load(Ordering::Acquire);
        let barrier = Arc::new(Barrier::new(4));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let waits_before = TokenStore::reload_waits_on_this_thread_for_test();
                    let _ = store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan);
                    TokenStore::reload_waits_on_this_thread_for_test() - waits_before
                })
            })
            .collect();
        for h in handles {
            let waits = h.join().expect("join");
            assert!(
                waits <= 1,
                "each concurrent first-outage verify must block at most once, on its bounded wait; blocked {waits} times"
            );
        }
        assert_eq!(
            store.transient_flight.leaders.load(Ordering::Acquire) - leaders_before,
            1,
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
    fn stale_outage_snapshot_does_not_relatch_after_recovery() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tokens.json");
        write_tokens_revoking_writer(&path, false);
        let store = TokenStore::load_insecure(path.clone()).expect("load");
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("warm");
        {
            let mut state = store.inner.lock().unwrap();
            state.reload_failure_since = Some(Instant::now());
        }
        assert!(matches!(
            store.fail_closed(true),
            TokenError::StoreUnavailable
        ));
        assert!(store.inner.lock().unwrap().store_unavailable);
        {
            let mut state = store.inner.lock().unwrap();
            TokenStore::clear_reload_outage(&mut state, &store.transient_flight);
        }
        assert!(matches!(
            store.fail_closed(true),
            TokenError::StoreUnavailable
        ));
        assert!(
            !store.inner.lock().unwrap().store_unavailable,
            "a caller holding a pre-recovery snapshot must not re-latch the store"
        );
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("recovered store keeps serving");
    }

    #[test]
    fn reload_revoke_honored_after_outage_recovers() {
        run_bounded(|| {
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
            assert!(
                store.wait_probe_threads_exited_for_test(Duration::from_secs(10)),
                "outage probes did not exit"
            );
            assert_eq!(store.leaked_disk_probe_threads_for_test(), 0);
            store.clear_probe_fast_fail_window_for_test();
            assert!(matches!(
                store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
                Err(TokenError::Revoked)
            ));
        });
    }

    #[test]
    fn reload_revoke_never_missed_after_load_stress() {
        run_bounded(|| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let path = tmp.path().join("tokens.json");
            write_tokens_revoking_writer(&path, false);
            let store = TokenStore::load_insecure(path.clone()).expect("load");
            const ROUNDS: usize = 200;
            for i in 0..ROUNDS {
                store
                    .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
                    .expect("warm load");
                assert_eq!(
                    store.live_disk_probe_threads_for_test(),
                    0,
                    "iteration {i}: a finished probe must not hold its slot into the next call"
                );
                write_tokens_revoking_writer(&path, true);
                let mut err = store
                    .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
                    .expect_err("revoke must be visible immediately");
                if matches!(err, TokenError::StoreUnavailable) {
                    assert!(store.wait_probe_threads_exited_for_test(Duration::from_secs(10)));
                    store.clear_probe_fast_fail_window_for_test();
                    err = store
                        .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
                        .expect_err("revoke must be visible once the stalled probe is gone");
                }
                assert!(
                    matches!(err, TokenError::Revoked),
                    "missed revoke on iteration {i}: {err:?}"
                );
                write_tokens_revoking_writer(&path, false);
            }
        });
    }

    #[cfg(unix)]
    /// Open descriptors in this process that resolve to `path`.
    ///
    /// Filtering by target keeps descriptors opened by tests running in
    /// parallel threads of the same binary out of the count.
    /// An entry that fails to list was closed while the directory was read,
    /// so it is not open on `path` and is skipped.
    fn fds_open_on(path: &Path) -> usize {
        let target = std::fs::canonicalize(path).expect("canonical fifo path");
        std::fs::read_dir("/proc/self/fd")
            .expect("/proc/self/fd")
            .filter_map(|e| e.ok())
            .filter(|e| std::fs::read_link(e.path()).is_ok_and(|t| t == target))
            .count()
    }

    #[cfg(unix)]
    #[test]
    fn fifo_read_closes_fd_on_every_exit_path() {
        run_bounded(|| {
            use nix::sys::stat::Mode;
            use std::sync::atomic::AtomicBool;

            let tmp = tempfile::tempdir().expect("tempdir");
            let path = tmp.path().join("tokens.json");
            nix::unistd::mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR).expect("mkfifo");
            assert_eq!(fds_open_on(&path), 0);
            let cancel = AtomicBool::new(true);
            for _ in 0..40 {
                assert!(matches!(
                    TokenStore::try_read_fifo_tokens_bytes(&path, Some(&cancel)),
                    Err(DiskFingerprint::Unreadable)
                ));
            }
            assert_eq!(fds_open_on(&path), 0, "cancel exits must not leak FIFO fds");

            let cancel_live = AtomicBool::new(false);
            let path_feed = path.clone();
            let file = crate::test_util::default_tokens_file();
            let bytes = serde_json::to_vec_pretty(&file).expect("json");
            let bytes_feed = bytes.clone();
            let (done_tx, done_rx) = std::sync::mpsc::sync_channel(0);
            let reader_path = path.clone();
            let reader = std::thread::spawn(move || {
                let ok = TokenStore::try_read_fifo_tokens_bytes(&reader_path, Some(&cancel_live));
                let _ = done_tx.send(ok);
            });
            // Let the reader thread open its O_NONBLOCK read fd before pairing ends (avoid FIFO open deadlock).
            std::thread::sleep(Duration::from_millis(50));
            std::thread::scope(|scope| {
                use nix::fcntl::{open, OFlag};
                use nix::sys::stat::Mode;
                use nix::unistd::close;
                use std::io::Write;

                let path_read = path_feed.clone();
                let path_write = path_feed;
                scope.spawn(move || {
                    let fd = open(
                        path_read.as_path(),
                        OFlag::O_RDONLY | OFlag::O_NONBLOCK,
                        Mode::empty(),
                    )
                    .expect("fifo read end for paired open");
                    std::thread::sleep(Duration::from_secs(2));
                    let _ = close(fd);
                });
                scope.spawn(move || {
                    let mut w = std::fs::OpenOptions::new()
                        .write(true)
                        .open(path_write)
                        .expect("fifo write end");
                    w.write_all(&bytes_feed).expect("write tokens");
                });
            });
            let ok = done_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("fifo read result");
            reader.join().expect("join fifo reader");
            assert!(ok.is_ok(), "expected valid fifo read, got {ok:?}");
            assert_eq!(fds_open_on(&path), 0, "successful fifo read must close fd");
        });
    }
}
