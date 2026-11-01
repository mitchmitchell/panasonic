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
