use kxprov_api::{hash_bearer_secret, Scope, TokenEntry, TokenId, TokensFile};
use std::path::Path;

pub const WRITER_SECRET: &str = "test-writer-secret";
pub const APPROVER_SECRET: &str = "test-approver-secret";
pub const READER_SECRET: &str = "test-reader-secret";
pub const COMM_SECRET: &str = "test-comm-secret";

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
