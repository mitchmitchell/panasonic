use kxprov_api::{hash_bearer_secret, Scope, TokenEntry, TokenId, TokensFile};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use tokio::sync::Notify;

pub const WRITER_SECRET: &str = "test-writer-secret";
pub const APPROVER_SECRET: &str = "test-approver-secret";
pub const READER_SECRET: &str = "test-reader-secret";
pub const COMM_SECRET: &str = "test-comm-secret";
pub const GATEWAY_SECRET: &str = "test-gateway-secret";

static PLAN_CHANGE_HOLD: AtomicBool = AtomicBool::new(false);
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
