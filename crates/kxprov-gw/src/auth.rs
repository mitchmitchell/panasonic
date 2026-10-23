use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use argon2::password_hash::{PasswordHash, PasswordVerifier};
use argon2::Argon2;
use kxprov_mock::{scopes_for_role, ScopeSet};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub struct McpTokenRecord {
    pub token_id: String,
    pub agent_name: String,
    pub scopes: ScopeSet,
    expires_at_ms: Option<u64>,
}

pub struct AdminPassword {
    hash: String,
}

impl AdminPassword {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        validate_secret_file(path, "admin password")?;
        let hash = fs::read_to_string(path)?.trim().to_string();
        if hash.is_empty() {
            anyhow::bail!("empty password hash file");
        }
        Ok(Self { hash })
    }

    pub fn verify(&self, password: &str) -> bool {
        let parsed = match PasswordHash::new(&self.hash) {
            Ok(p) => p,
            Err(_) => return false,
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    }
}

#[derive(Debug, Deserialize)]
struct TokenFileWrapper {
    tokens: Vec<TokenFileEntry>,
}

#[derive(Debug, Deserialize)]
struct TokenFileEntry {
    id: String,
    name: String,
    role: String,
    token_sha256_hex: String,
    #[serde(default)]
    expires_at_ms: Option<u64>,
}

struct TokenCache {
    mtime: SystemTime,
    len: u64,
    by_hash: HashMap<[u8; 32], McpTokenRecord>,
}

pub struct McpTokenStore {
    path: PathBuf,
    cache: Mutex<TokenCache>,
}

impl McpTokenStore {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        validate_secret_file(path, "MCP token")?;
        let by_hash = load_by_hash(path)?;
        let meta = fs::metadata(path)?;
        let mtime = meta.modified()?;
        let len = meta.len();
        Ok(Self {
            path: path.to_path_buf(),
            cache: Mutex::new(TokenCache {
                mtime,
                len,
                by_hash,
            }),
        })
    }

    fn reload_if_stale(&self) -> HashMap<[u8; 32], McpTokenRecord> {
        let meta = fs::metadata(&self.path).ok();
        let mtime = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let len = meta.map(|m| m.len()).unwrap_or(0);
        let mut guard = self.cache.lock().expect("token cache");
        if mtime != guard.mtime || len != guard.len {
            if let Ok(fresh) = load_by_hash(&self.path) {
                guard.mtime = mtime;
                guard.len = len;
                guard.by_hash = fresh;
            }
        }
        guard.by_hash.clone()
    }

    pub fn verify_bearer(&self, bearer: &str) -> Option<McpTokenRecord> {
        let by_hash = match load_by_hash(&self.path) {
            Ok(fresh) => {
                if let Ok(meta) = fs::metadata(&self.path) {
                    let mut guard = self.cache.lock().expect("token cache");
                    guard.mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    guard.len = meta.len();
                    guard.by_hash = fresh.clone();
                }
                fresh
            }
            Err(_) => self.reload_if_stale(),
        };
        let digest = Sha256::digest(bearer.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        let now_ms = OffsetDateTime::now_utc().unix_timestamp() as u64 * 1000;
        for (stored_hash, record) in &by_hash {
            if bool::from(key.ct_eq(stored_hash)) {
                if let Some(exp) = record.expires_at_ms {
                    if now_ms >= exp {
                        return None;
                    }
                }
                return Some(record.clone());
            }
        }
        None
    }
}

fn load_by_hash(path: &Path) -> anyhow::Result<HashMap<[u8; 32], McpTokenRecord>> {
    let raw = fs::read_to_string(path)?;
    let entries = load_token_entries(&raw)?;
    let approver_count = entries.iter().filter(|e| e.role == "approver").count();
    if approver_count != 1 {
        anyhow::bail!("token file must contain exactly one approver (found {approver_count})");
    }
    let now_ms = OffsetDateTime::now_utc().unix_timestamp() as u64 * 1000;
    let mut by_hash = HashMap::new();
    for entry in entries {
        if let Some(exp) = entry.expires_at_ms {
            if now_ms >= exp {
                anyhow::bail!("token {} expired", entry.id);
            }
        }
        let hash = decode_sha256_hex(&entry.token_sha256_hex)?;
        let scopes = scopes_for_role(&entry.role);
        scopes.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
        by_hash.insert(
            hash,
            McpTokenRecord {
                token_id: entry.id,
                agent_name: entry.name,
                scopes,
                expires_at_ms: entry.expires_at_ms,
            },
        );
    }
    Ok(by_hash)
}

#[cfg(test)]
mod verify_tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn verify_bearer_rejects_expired_token_after_load() {
        let bearer = "test-bearer-secret";
        let digest = Sha256::digest(bearer.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        let mut by_hash = HashMap::new();
        by_hash.insert(
            key,
            McpTokenRecord {
                token_id: "t1".into(),
                agent_name: "T".into(),
                scopes: scopes_for_role("approver"),
                expires_at_ms: Some(1),
            },
        );
        let store = McpTokenStore {
            path: PathBuf::from("/nonexistent"),
            cache: Mutex::new(TokenCache {
                mtime: SystemTime::UNIX_EPOCH,
                len: 0,
                by_hash,
            }),
        };
        assert!(store.verify_bearer(bearer).is_none());
    }

    #[test]
    fn revoked_token_drops_after_file_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.toml");
        let bearer = "live-token-value";
        let hash_hex = hash_token_for_file(bearer);
        let body = format!(
            r#"
[[tokens]]
id = "approver"
name = "Approver"
role = "approver"
token_sha256_hex = "{hash_hex}"
[[tokens]]
id = "comms"
name = "Comms"
role = "communications"
token_sha256_hex = "0202020202020202020202020202020202020202020202020202020202020202"
"#
        );
        std::fs::write(&path, body).unwrap();
        std::env::set_var("KXPROV_SKIP_SECRET_FILE_CHECKS", "1");
        let store = McpTokenStore::from_file(&path).expect("load");
        assert!(store.verify_bearer(bearer).is_some());

        let body2 = r#"
[[tokens]]
id = "approver"
name = "Approver"
role = "approver"
token_sha256_hex = "0101010101010101010101010101010101010101010101010101010101010101"
[[tokens]]
id = "comms"
name = "Comms"
role = "communications"
token_sha256_hex = "0202020202020202020202020202020202020202020202020202020202020202"
"#
        .to_string();
        std::fs::write(&path, body2).unwrap();
        assert!(store.verify_bearer(bearer).is_none());
    }
}

pub fn validate_secret_file(path: &Path, label: &str) -> anyhow::Result<()> {
    if skip_secret_file_checks() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(path)?;
        if meta.uid() != 0 {
            anyhow::bail!("{label} file must be owned by root (uid 0)");
        }
        if meta.mode() & 0o777 != 0o600 {
            anyhow::bail!("{label} file must be mode 0600");
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "test-secret-skip"))]
fn skip_secret_file_checks() -> bool {
    std::env::var("KXPROV_SKIP_SECRET_FILE_CHECKS")
        .ok()
        .as_deref()
        == Some("1")
}

#[cfg(not(any(test, feature = "test-secret-skip")))]
fn skip_secret_file_checks() -> bool {
    false
}

fn load_token_entries(raw: &str) -> anyhow::Result<Vec<TokenFileEntry>> {
    if let Ok(wrapper) = toml::from_str::<TokenFileWrapper>(raw) {
        return Ok(wrapper.tokens);
    }
    toml::from_str(raw).map_err(Into::into)
}

fn decode_sha256_hex(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim())?;
    if bytes.len() != 32 {
        anyhow::bail!("sha256 hex must be 32 bytes");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn hash_token_for_file(bearer: &str) -> String {
    hex::encode(Sha256::digest(bearer.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn skip_secret_file_checks_only_honors_env_in_test_builds() {
        std::env::remove_var("KXPROV_SKIP_SECRET_FILE_CHECKS");
        assert!(!skip_secret_file_checks());
        std::env::set_var("KXPROV_SKIP_SECRET_FILE_CHECKS", "1");
        assert!(skip_secret_file_checks());
    }

    fn write_tokens(path: &std::path::Path, body: &str) {
        std::fs::write(path, body).unwrap();
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).unwrap();
    }

    #[test]
    fn rejects_multiple_approvers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.toml");
        write_tokens(
            &path,
            r#"
[[tokens]]
id = "a1"
name = "A1"
role = "approver"
token_sha256_hex = "0101010101010101010101010101010101010101010101010101010101010101"
[[tokens]]
id = "a2"
name = "A2"
role = "approver"
token_sha256_hex = "0202020202020202020202020202020202020202020202020202020202020202"
"#,
        );
        std::env::set_var("KXPROV_SKIP_SECRET_FILE_CHECKS", "1");
        let result = McpTokenStore::from_file(&path);
        let err = result.err().expect("load should fail");
        assert!(err.to_string().contains("exactly one approver"));
    }

    #[test]
    fn rejects_expired_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.toml");
        write_tokens(
            &path,
            r#"
[[tokens]]
id = "approver"
name = "Approver"
role = "approver"
token_sha256_hex = "0101010101010101010101010101010101010101010101010101010101010101"
expires_at_ms = 1
[[tokens]]
id = "comms"
name = "Comms"
role = "communications"
token_sha256_hex = "0202020202020202020202020202020202020202020202020202020202020202"
"#,
        );
        std::env::set_var("KXPROV_SKIP_SECRET_FILE_CHECKS", "1");
        let result = McpTokenStore::from_file(&path);
        let err = result.err().expect("load should fail");
        assert!(err.to_string().contains("expired"));
    }
}
