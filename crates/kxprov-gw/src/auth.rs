use std::collections::HashMap;
use std::fs;
use std::path::Path;

use argon2::password_hash::{PasswordHash, PasswordVerifier};
use argon2::Argon2;
use kxprov_api::{scopes_for_role, ScopeSet};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone)]
pub struct McpTokenRecord {
    pub token_id: String,
    pub agent_name: String,
    pub scopes: ScopeSet,
}

pub struct AdminPassword {
    hash: String,
}

impl AdminPassword {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
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
struct TokenFileEntry {
    id: String,
    name: String,
    role: String,
    /// sha256 hex of bearer token (never store plaintext in prod; tests use runtime-generated file).
    token_sha256_hex: String,
}

pub struct McpTokenStore {
    by_hash: HashMap<[u8; 32], McpTokenRecord>,
}

impl McpTokenStore {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path)?;
        let entries: Vec<TokenFileEntry> = toml::from_str(&raw)?;
        let mut by_hash = HashMap::new();
        for entry in entries {
            let hash = decode_sha256_hex(&entry.token_sha256_hex)?;
            by_hash.insert(
                hash,
                McpTokenRecord {
                    token_id: entry.id,
                    agent_name: entry.name,
                    scopes: scopes_for_role(&entry.role),
                },
            );
        }
        Ok(Self { by_hash })
    }

    pub fn verify_bearer(&self, bearer: &str) -> Option<McpTokenRecord> {
        let digest = Sha256::digest(bearer.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        for (stored_hash, record) in &self.by_hash {
            if bool::from(key.ct_eq(stored_hash)) {
                return Some(record.clone());
            }
        }
        None
    }
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
