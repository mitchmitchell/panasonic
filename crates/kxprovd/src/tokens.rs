//! Daemon token store: verify bearer secrets (hashed on disk only).

use kxprov_api::{hash_bearer_secret, Scope, TokenEntry, TokenId, TokensFile};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;
use thiserror::Error;

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
    loaded_mtime: Option<SystemTime>,
}

pub struct TokenStore {
    inner: Mutex<TokenState>,
}

impl Clone for TokenStore {
    fn clone(&self) -> Self {
        let state = self.inner.lock().expect("token store lock");
        Self {
            inner: Mutex::new(TokenState {
                path: state.path.clone(),
                approver_token_id: state.approver_token_id.clone(),
                entries: state.entries.clone(),
                loaded_mtime: state.loaded_mtime,
            }),
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
        Self::load_unchecked(path)
    }

    fn load_unchecked(path: PathBuf) -> Result<Self, TokenError> {
        let state = Self::read_state(&path)?;
        Self::validate_file(&state.entries, &state.approver_token_id)?;
        Ok(Self {
            inner: Mutex::new(state),
        })
    }

    fn read_state(path: &Path) -> Result<TokenState, TokenError> {
        let meta = std::fs::metadata(path)?;
        let loaded_mtime = meta.modified().ok();
        let raw = std::fs::read(path)?;
        let file: TokensFile = serde_json::from_slice(&raw)?;
        Ok(TokenState {
            path: path.to_path_buf(),
            approver_token_id: file.approver_token_id,
            entries: file.tokens,
            loaded_mtime,
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
        let mut ids = std::collections::HashSet::new();
        for t in entries {
            if !ids.insert(t.id.as_str().to_string()) {
                return Err(TokenError::Invalid("duplicate token id".into()));
            }
        }
        Ok(())
    }

    fn refresh_if_modified(state: &mut TokenState) -> Result<(), TokenError> {
        if state.loaded_mtime.is_none() {
            return Ok(());
        }
        let meta = std::fs::metadata(&state.path)?;
        let mtime = meta.modified().ok();
        if mtime == state.loaded_mtime {
            return Ok(());
        }
        let fresh = Self::read_state(&state.path)?;
        Self::validate_file(&fresh.entries, &fresh.approver_token_id)?;
        *state = fresh;
        Ok(())
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
        Self::refresh_if_modified(&mut state)?;
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
            loaded_mtime: None,
        };
        Self {
            inner: Mutex::new(state),
        }
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
}
