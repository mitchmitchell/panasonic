use kxprov_api::{hash_bearer_secret, Scope, TokenEntry, TokenId, TokensFile};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use tokio::sync::Notify;

pub const WRITER_SECRET: &str = "test-writer-secret";
pub const APPROVER_SECRET: &str = "test-approver-secret";
pub const READER_SECRET: &str = "test-reader-secret";
pub const COMM_SECRET: &str = "test-comm-secret";
pub const GATEWAY_SECRET: &str = "test-gateway-secret";

static PLAN_CHANGE_HOLD: AtomicBool = AtomicBool::new(false);
static SMDR_INGEST_FAIL_REMAINING: AtomicU32 = AtomicU32::new(0);
static SMDR_INGEST_FAIL_CONSUMED: AtomicU32 = AtomicU32::new(0);
#[cfg(all(target_os = "linux", feature = "test-util"))]
static SMDR_DEVICE_CLEAR_COUNT: AtomicU32 = AtomicU32::new(0);
#[cfg(all(target_os = "linux", feature = "test-util"))]
static SERIAL_FORCE_LINK_DOWN: AtomicBool = AtomicBool::new(false);
static PLAN_CHANGE_HOLD_NOTIFY: OnceLock<Notify> = OnceLock::new();

fn plan_change_hold_notify() -> &'static Notify {
    PLAN_CHANGE_HOLD_NOTIFY.get_or_init(Notify::new)
}

/// While held, the worker blocks at the start of each plan-change job (rate-limit integration tests).
pub struct PlanChangeHoldGuard;

impl PlanChangeHoldGuard {
    pub fn arm() -> Self {
        PLAN_CHANGE_HOLD.store(true, Ordering::Release);
        Self
    }
}

impl Drop for PlanChangeHoldGuard {
    fn drop(&mut self) {
        PLAN_CHANGE_HOLD.store(false, Ordering::Release);
        plan_change_hold_notify().notify_waiters();
    }
}

pub async fn plan_change_hold_if_armed() {
    while PLAN_CHANGE_HOLD.load(Ordering::Acquire) {
        plan_change_hold_notify().notified().await;
    }
}

pub fn default_tokens_file() -> TokensFile {
    TokensFile {
        approver_token_id: TokenId("approver".into()),
        tokens: vec![
            TokenEntry {
                id: TokenId("reader".into()),
                secret_hash: hash_bearer_secret(READER_SECRET),
                scopes: vec![Scope::Read],
                expires_at_ms: u64::MAX / 2,
                revoked: false,
            },
            TokenEntry {
                id: TokenId("gateway".into()),
                secret_hash: hash_bearer_secret(GATEWAY_SECRET),
                scopes: vec![Scope::Read, Scope::Plan, Scope::CallLog],
                expires_at_ms: u64::MAX / 2,
                revoked: false,
            },
            TokenEntry {
                id: TokenId("writer".into()),
                secret_hash: hash_bearer_secret(WRITER_SECRET),
                scopes: vec![Scope::Read, Scope::Plan, Scope::Write],
                expires_at_ms: u64::MAX / 2,
                revoked: false,
            },
            TokenEntry {
                id: TokenId("comm".into()),
                secret_hash: hash_bearer_secret(COMM_SECRET),
                scopes: vec![Scope::Read, Scope::Plan, Scope::Write],
                expires_at_ms: u64::MAX / 2,
                revoked: false,
            },
            TokenEntry {
                id: TokenId("approver".into()),
                secret_hash: hash_bearer_secret(APPROVER_SECRET),
                scopes: vec![Scope::Read, Scope::Approve],
                expires_at_ms: u64::MAX / 2,
                revoked: false,
            },
        ],
    }
}

pub fn write_integration_tokens(path: &Path) {
    crate::tokens::TokenStore::write_test_file(path, &default_tokens_file())
        .expect("write integration tokens");
}

/// Drives fifo reload probes; auth success or failure is irrelevant to contention tests.
pub fn verify_bearer_driving_fifo_contention(store: &crate::tokens::TokenStore) {
    let _ = store.verify_bearer(WRITER_SECRET, 0, Scope::Plan);
}

/// Integration fixtures seed placeholder dbh bytes; a failed write leaves meta-only rows.
pub fn write_bytes_best_effort(path: &Path, data: impl AsRef<[u8]>) {
    let _ = std::fs::write(path, data.as_ref());
}

/// Waits for a fifo probe helper thread; panics from the thread propagate via `join`.
pub fn join_probe_helper_thread(handle: std::thread::JoinHandle<()>) {
    handle
        .join()
        .expect("fifo probe helper thread panicked or failed to join");
}

struct ChunkSource(std::collections::VecDeque<Vec<u8>>);

impl crate::smdr_reader::SmdrSource for ChunkSource {
    fn recv(&mut self, _timeout_ms: u64) -> Result<Vec<u8>, kxtd1232::TransportError> {
        self.0.pop_front().ok_or(kxtd1232::TransportError::Timeout)
    }
}

/// Feeds raw SMDR bytes in small chunks through the reader into the store under
/// `data_dir`, publishing stored calls to `live`. Returns how many calls were stored.
pub fn ingest_smdr_bytes(
    data_dir: &Path,
    live: std::sync::Arc<crate::smdr_bus::SmdrLive>,
    bytes: &[u8],
) -> usize {
    use crate::smdr_reader::ReaderEvent;
    use crate::smdr_store::IngestOutcome;
    let backups = data_dir.join("backups");
    let store = crate::smdr_store::SmdrStore::open(
        data_dir,
        &[backups.as_path()],
        kxtd1232::smdr::DateOrder::Mdy,
    )
    .expect("open smdr store");
    let mut sink = crate::smdr_bus::PublishingSink::new(store, std::sync::Arc::clone(&live));
    let chunks = bytes.chunks(11).map(<[u8]>::to_vec).collect();
    let mut reader = crate::smdr_reader::SmdrReader::new(ChunkSource(chunks));
    live.set_running(true);
    let mut stored = 0;
    let mut note = |events: &[ReaderEvent]| {
        live.note_events(events);
        stored += events
            .iter()
            .filter(|e| **e == ReaderEvent::Ingested(IngestOutcome::Stored))
            .count();
    };
    loop {
        let events = reader
            .poll_once(&mut sink, 1, chrono::Utc::now)
            .expect("reader poll");
        if events == [ReaderEvent::Idle] {
            break;
        }
        note(&events);
    }
    note(
        &reader
            .finish(&mut sink, chrono::Utc::now)
            .expect("reader finish"),
    );
    stored
}

/// The SMDR v1 fixture stream (header, outgoing, incoming with caller ID, transfer).
pub fn smdr_fixture(name: &str) -> Vec<u8> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../kxtd1232/tests/fixtures/smdr-v1");
    std::fs::read(dir.join(name)).expect("smdr fixture")
}

/// `n` distinct synthetic outgoing call records as the PBX would print them.
pub fn synthetic_smdr_bytes(first: usize, n: usize) -> Vec<u8> {
    use kxtd1232_sim::smdr::{BufferPolicy, LineEnding, SmdrEmitter, SyntheticCall};
    let mut emitter = SmdrEmitter::new(BufferPolicy::Drop, LineEnding::CrLf);
    for i in first..first + n {
        let call = SyntheticCall {
            date: "10/23/26".into(),
            time: "01:05PM".into(),
            ext: "101".into(),
            co: "01".into(),
            number: format!("555{:07}", i % 10_000_000),
            duration: "00:01'00".into(),
            ..SyntheticCall::default()
        };
        emitter.call_ended(&call).expect("synthetic call");
    }
    emitter.take_output()
}

static SIM_OPEN_HOLDERS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Records the lease holder id the in-process sim transport was opened under (#74).
pub fn record_sim_open_holder(holder: &str) {
    SIM_OPEN_HOLDERS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(holder.to_string());
}

/// Lease holder ids the in-process sim transport has been opened under, oldest first.
pub fn sim_open_holders() -> Vec<String> {
    SIM_OPEN_HOLDERS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Forces the next `n` SMDR store ingests in the daemon reader to fail (#119 STOREBACKOFF).
pub fn arm_smdr_ingest_failures(n: u32) {
    SMDR_INGEST_FAIL_CONSUMED.store(0, Ordering::SeqCst);
    SMDR_INGEST_FAIL_REMAINING.store(n, Ordering::SeqCst);
}

pub fn smdr_ingest_failures_consumed() -> u32 {
    SMDR_INGEST_FAIL_CONSUMED.load(Ordering::SeqCst)
}

#[cfg(feature = "test-util")]
pub(crate) fn take_armed_smdr_ingest_failure() -> bool {
    loop {
        let cur = SMDR_INGEST_FAIL_REMAINING.load(Ordering::SeqCst);
        if cur == 0 {
            return false;
        }
        if SMDR_INGEST_FAIL_REMAINING
            .compare_exchange(cur, cur - 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            SMDR_INGEST_FAIL_CONSUMED.fetch_add(1, Ordering::SeqCst);
            return true;
        }
    }
}

#[cfg(all(target_os = "linux", feature = "test-util"))]
pub fn reset_smdr_device_clear_count() {
    SMDR_DEVICE_CLEAR_COUNT.store(0, Ordering::SeqCst);
}

#[cfg(all(target_os = "linux", feature = "test-util"))]
pub fn smdr_device_clear_count() -> u32 {
    SMDR_DEVICE_CLEAR_COUNT.load(Ordering::SeqCst)
}

#[cfg(all(target_os = "linux", feature = "test-util"))]
pub(crate) fn record_smdr_device_clear() {
    SMDR_DEVICE_CLEAR_COUNT.fetch_add(1, Ordering::SeqCst);
}

#[cfg(all(target_os = "linux", feature = "test-util"))]
pub fn arm_serial_force_link_down() {
    SERIAL_FORCE_LINK_DOWN.store(true, Ordering::SeqCst);
}

#[cfg(all(target_os = "linux", feature = "test-util"))]
pub(crate) fn take_serial_force_link_down() -> bool {
    SERIAL_FORCE_LINK_DOWN
        .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}
