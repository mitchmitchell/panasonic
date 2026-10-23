//! Daemon token store: verify bearer secrets (hashed on disk only).

use kxprov_api::{
    hash_bearer_secret, validate_tokens_file, Scope, TokenEntry, TokenId, TokenValidationError,
    TokensFile,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, Weak};
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
}

pub struct TokenStore {
    inner: Mutex<TokenState>,
    job_queue: Mutex<Option<Weak<JobQueue>>>,
}

struct TokenRefreshDelta {
    newly_revoked: Vec<TokenId>,
    reactivated: Vec<TokenId>,
    rotated: Vec<TokenId>,
}

impl Clone for TokenStore {
    fn clone(&self) -> Self {
        let state = self.inner.lock().expect("token store lock");
        Self {
            inner: Mutex::new(TokenState {
                path: state.path.clone(),
                approver_token_id: state.approver_token_id.clone(),
                entries: state.entries.clone(),
                loaded_digest: state.loaded_digest,
                enforce_secure_reload: state.enforce_secure_reload,
            }),
            job_queue: Mutex::new(self.job_queue.lock().expect("token store lock").clone()),
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

    fn load_unchecked(path: PathBuf) -> Result<Self, TokenError> {
        let mut state = Self::read_state(&path)?;
        state.enforce_secure_reload = true;
        Self::validate_file(&state.entries, &state.approver_token_id)?;
        Ok(Self {
            inner: Mutex::new(state),
            job_queue: Mutex::new(None),
        })
    }

    #[cfg(feature = "test-util")]
    fn load_unchecked_insecure(path: PathBuf) -> Result<Self, TokenError> {
        let mut state = Self::read_state(&path)?;
        state.enforce_secure_reload = false;
        Self::validate_file(&state.entries, &state.approver_token_id)?;
        Ok(Self {
            inner: Mutex::new(state),
            job_queue: Mutex::new(None),
        })
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

    fn read_state(path: &Path) -> Result<TokenState, TokenError> {
        let raw = std::fs::read(path)?;
        let loaded_digest = Self::digest_bytes(&raw);
        let file: TokensFile = serde_json::from_slice(&raw)?;
        Ok(TokenState {
            path: path.to_path_buf(),
            approver_token_id: file.approver_token_id,
            entries: file.tokens,
            loaded_digest: Some(loaded_digest),
            enforce_secure_reload: true,
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

    fn refresh_if_modified(state: &mut TokenState) -> Result<TokenRefreshDelta, TokenError> {
        if state.loaded_digest.is_none() {
            return Ok(TokenRefreshDelta {
                newly_revoked: Vec::new(),
                reactivated: Vec::new(),
                rotated: Vec::new(),
            });
        }
        let raw = std::fs::read(&state.path)?;
        let digest = Self::digest_bytes(&raw);
        if Some(digest) == state.loaded_digest {
            return Ok(TokenRefreshDelta {
                newly_revoked: Vec::new(),
                reactivated: Vec::new(),
                rotated: Vec::new(),
            });
        }
        let enforce_secure = state.enforce_secure_reload;
        if enforce_secure {
            Self::check_secure(&state.path)?;
        }
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
        let mut state = self.inner.lock().expect("token store lock");
        let delta = Self::refresh_if_modified(&mut state)?;
        drop(state);
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
        };
        Self {
            inner: Mutex::new(state),
            job_queue: Mutex::new(None),
        }
    }

    pub fn is_revoked(&self, token_id: &TokenId) -> Result<bool, TokenError> {
        let mut state = self.inner.lock().expect("token store lock");
        let delta = Self::refresh_if_modified(&mut state)?;
        drop(state);
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
            return Err(TokenError::Invalid("tokens file missing".into()));
        }
        let meta = std::fs::metadata(path)?;
        if meta.uid() != 0 {
            return Err(TokenError::InsecurePermissions);
        }
        if meta.mode() & 0o777 != 0o600 {
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
}
