//! Canonical on-disk token schema (`tokens.json`). **PR #4 owns this crate**; PR #5 must match.

use crate::{Scope, TokenId};
use serde::{Deserialize, Serialize};

/// Per-token queue depth cap (queued + running jobs).
pub const TOKEN_QUEUE_DEPTH_MAX: u32 = 4;
/// Per-token job starts per rolling minute.
pub const TOKEN_JOBS_PER_MINUTE: u32 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokensFile {
    /// Exactly one token with [`Scope::Approve`] must use this id (Chief of Staff channel).
    pub approver_token_id: TokenId,
    pub tokens: Vec<TokenEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenEntry {
    pub id: TokenId,
    /// SHA-256 hex of the bearer secret (see [`hash_bearer_secret`]).
    pub secret_hash: String,
    pub scopes: Vec<Scope>,
    pub expires_at_ms: u64,
    #[serde(default)]
    pub revoked: bool,
}

/// Hash a presented bearer secret for lookup (daemon never stores plaintext).
pub fn hash_bearer_secret(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(secret.as_bytes()))
}
