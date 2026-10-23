//! Daemon token store: verify bearer secrets (hashed on disk only).

use kxprov_api::{
    hash_bearer_secret, validate_tokens_file, Scope, TokenEntry, TokenId, TokenValidationError,
    TokensFile,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, Weak};
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
    /// First transient reload failure (ENOENT / torn JSON); serve cached file until this ages out.
    reload_failure_since: Option<Instant>,
    /// After grace expires, reject bearer auth until a good reload succeeds.
    store_unavailable: bool,
    store_unavailable_logged: bool,
    /// Skip disk probes until this instant (coalesce retries across concurrent requests).
    reload_probe_backoff_until: Option<Instant>,
    /// Fingerprint of the last failed on-disk payload (avoid re-reading unchanged bad bytes).
    reload_failed_disk_fingerprint: Option<DiskFingerprint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiskFingerprint {
    Missing,
    InvalidDigest([u8; 32]),
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
                reload_failure_since: state.reload_failure_since,
                store_unavailable: state.store_unavailable,
                store_unavailable_logged: state.store_unavailable_logged,
                reload_probe_backoff_until: state.reload_probe_backoff_until,
                reload_failed_disk_fingerprint: state.reload_failed_disk_fingerprint,
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

    #[cfg(all(test, feature = "test-util"))]
    pub fn set_enforce_secure_reload_for_test(&self, enforce: bool) {
        self.inner
            .lock()
            .expect("token store lock")
            .enforce_secure_reload = enforce;
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

    fn tokens_file_parse_ok(raw: &[u8]) -> bool {
        serde_json::from_slice::<TokensFile>(raw).is_ok()
    }

    const RELOAD_GRACE: Duration = Duration::from_secs(2);
    const RELOAD_MAX_ATTEMPTS: usize = 3;

    fn disk_fingerprint(path: &Path) -> Result<DiskFingerprint, std::io::Error> {
        use std::io::ErrorKind;
        match std::fs::read(path) {
            Ok(raw) if Self::tokens_file_parse_ok(&raw) => Err(ErrorKind::InvalidData.into()),
            Ok(raw) => Ok(DiskFingerprint::InvalidDigest(Self::digest_bytes(&raw))),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(DiskFingerprint::Missing),
            Err(e) => Err(e),
        }
    }

    fn try_read_valid_tokens_bytes(path: &Path) -> Result<Vec<u8>, DiskFingerprint> {
        use std::io::ErrorKind;
        match std::fs::read(path) {
            Ok(raw) if Self::tokens_file_parse_ok(&raw) => Ok(raw),
            Ok(raw) => Err(DiskFingerprint::InvalidDigest(Self::digest_bytes(&raw))),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(DiskFingerprint::Missing),
            Err(_) => Err(DiskFingerprint::Missing),
        }
    }

    /// Up to [`Self::RELOAD_MAX_ATTEMPTS`] reads within about [`Self::RELOAD_GRACE`] total.
    fn read_tokens_bytes_transient_window(path: &Path) -> Result<Vec<u8>, DiskFingerprint> {
        let deadline = Instant::now() + Self::RELOAD_GRACE;
        let mut last_fp = DiskFingerprint::Missing;
        for attempt in 0..Self::RELOAD_MAX_ATTEMPTS {
            match Self::try_read_valid_tokens_bytes(path) {
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

    fn clear_reload_outage(state: &mut TokenState) {
        state.reload_failure_since = None;
        state.store_unavailable = false;
        state.store_unavailable_logged = false;
        state.reload_probe_backoff_until = None;
        state.reload_failed_disk_fingerprint = None;
    }

    fn set_reload_probe_backoff(state: &mut TokenState, fp: DiskFingerprint) {
        state.reload_failed_disk_fingerprint = Some(fp);
        state.reload_probe_backoff_until = Some(Instant::now() + Self::RELOAD_GRACE);
    }

    fn reload_probe_backoff_active(state: &TokenState) -> bool {
        state
            .reload_probe_backoff_until
            .is_some_and(|until| Instant::now() < until)
    }

    fn reload_disk_unchanged_since_failure(state: &TokenState, path: &Path) -> bool {
        let Some(expected) = state.reload_failed_disk_fingerprint else {
            return false;
        };
        match Self::disk_fingerprint(path) {
            Ok(fp) => fp == expected,
            Err(_) => false,
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
            reload_probe_backoff_until: None,
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
            reload_probe_backoff_until: None,
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

    fn handle_transient_reload_failure(
        state: &mut TokenState,
        fp: DiskFingerprint,
    ) -> Result<TokenRefreshDelta, TokenError> {
        let now = Instant::now();
        if state.reload_failure_since.is_none() {
            state.reload_failure_since = Some(now);
            Self::set_reload_probe_backoff(state, fp);
            return Ok(Self::empty_refresh_delta());
        }
        if let Some(since) = state.reload_failure_since {
            if now.duration_since(since) < Self::RELOAD_GRACE {
                Self::set_reload_probe_backoff(state, fp);
                return Ok(Self::empty_refresh_delta());
            }
        }
        Self::set_reload_probe_backoff(state, fp);
        Err(Self::latch_store_unavailable(state))
    }

    fn reload_from_disk(state: &mut TokenState) -> Result<TokenRefreshDelta, TokenError> {
        if Self::reload_probe_backoff_active(state)
            && Self::reload_disk_unchanged_since_failure(state, &state.path)
        {
            if state.store_unavailable {
                return Err(TokenError::StoreUnavailable);
            }
            if state.reload_failure_since.is_some() {
                return Ok(Self::empty_refresh_delta());
            }
        }

        match Self::try_read_valid_tokens_bytes(&state.path) {
            Ok(raw) => {
                Self::clear_reload_outage(state);
                Self::apply_reloaded_bytes(state, raw)
            }
            Err(fp) => {
                if state.reload_failure_since.is_none() && !state.store_unavailable {
                    match Self::read_tokens_bytes_transient_window(&state.path) {
                        Ok(raw) => {
                            Self::clear_reload_outage(state);
                            return Self::apply_reloaded_bytes(state, raw);
                        }
                        Err(window_fp) => {
                            return Self::handle_transient_reload_failure(state, window_fp);
                        }
                    }
                }
                if state.store_unavailable {
                    Self::set_reload_probe_backoff(state, fp);
                    return Err(Self::latch_store_unavailable(state));
                }
                if let Some(since) = state.reload_failure_since {
                    if since.elapsed() < Self::RELOAD_GRACE {
                        return Self::handle_transient_reload_failure(state, fp);
                    }
                }
                Self::handle_transient_reload_failure(state, fp)
            }
        }
    }

    fn refresh_if_modified(state: &mut TokenState) -> Result<TokenRefreshDelta, TokenError> {
        if state.loaded_digest.is_none() {
            return Ok(Self::empty_refresh_delta());
        }

        if state.enforce_secure_reload {
            Self::check_secure(&state.path)?;
        }

        Self::reload_from_disk(state)
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

    pub fn verify_bearer_identity(
        &self,
        bearer: &str,
        now_ms: u64,
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
        Ok(VerifiedToken {
            id: entry.id.clone(),
            scopes: entry.scopes.clone(),
        })
    }

    pub fn verify_bearer(
        &self,
        bearer: &str,
        now_ms: u64,
        need: Scope,
    ) -> Result<VerifiedToken, TokenError> {
        let mut state = self.inner.lock().expect("token store lock");
        let delta = Self::refresh_if_modified(&mut state)?;
        if state.store_unavailable {
            return Err(TokenError::StoreUnavailable);
        }
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
        if !entry.scopes.contains(&need) {
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
            reload_probe_backoff_until: None,
            reload_failed_disk_fingerprint: None,
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
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(TokenError::InsecurePermissions);
        }
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
        store
            .verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan)
            .expect("grace snapshot");
        std::thread::sleep(Duration::from_millis(2100));
        assert!(matches!(
            store.verify_bearer(crate::test_util::WRITER_SECRET, 0, Scope::Plan),
            Err(TokenError::StoreUnavailable)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn reload_insecure_path_fails_closed_immediately() {
        use std::os::unix::fs::PermissionsExt;
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
        if nix::unistd::getuid().is_root() {
            std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o644)).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(&real, &path).unwrap();
        }
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
}
