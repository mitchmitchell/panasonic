use std::fs;
use std::path::{Path, PathBuf};

use kxprov_api::{hash_bearer_secret, Scope, TokenEntry, TokensFile};
use thiserror::Error;

use crate::auth::validate_secret_file;

#[derive(Debug, Error)]
pub enum GatewayTokenError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("gateway bearer: {0}")]
    Invalid(String),
}

/// Gateway daemon bearer (read + plan only), validated against [`TokensFile`].
#[derive(Clone)]
pub struct GatewayDaemonToken {
    bearer: String,
}

impl GatewayDaemonToken {
    pub fn load(tokens_path: &Path, bearer_path: &Path) -> Result<Self, GatewayTokenError> {
        validate_secret_file(tokens_path, "daemon tokens")
            .map_err(|e| GatewayTokenError::Invalid(e.to_string()))?;
        validate_secret_file(bearer_path, "gateway daemon bearer")
            .map_err(|e| GatewayTokenError::Invalid(e.to_string()))?;
        let file: TokensFile = serde_json::from_slice(&fs::read(tokens_path)?)?;
        let bearer = fs::read_to_string(bearer_path)?.trim().to_string();
        if bearer.is_empty() {
            return Err(GatewayTokenError::Invalid("empty gateway bearer".into()));
        }
        let hash = hash_bearer_secret(&bearer);
        let entry = file
            .tokens
            .iter()
            .find(|t| !t.revoked && t.secret_hash == hash)
            .ok_or_else(|| {
                GatewayTokenError::Invalid("bearer does not match any active token entry".into())
            })?;
        validate_gateway_entry(entry)?;
        Ok(Self { bearer })
    }

    pub fn bearer(&self) -> &str {
        &self.bearer
    }
}

fn validate_gateway_entry(entry: &TokenEntry) -> Result<(), GatewayTokenError> {
    if entry
        .scopes
        .iter()
        .any(|s| *s == Scope::Write || *s == Scope::Approve)
    {
        return Err(GatewayTokenError::Invalid(
            "gateway service token must not include write or approve scope".into(),
        ));
    }
    if !entry.scopes.iter().any(|s| *s == Scope::Read)
        || !entry.scopes.iter().any(|s| *s == Scope::Plan)
    {
        return Err(GatewayTokenError::Invalid(
            "gateway service token must include read and plan scopes".into(),
        ));
    }
    Ok(())
}

pub fn default_paths() -> (PathBuf, PathBuf) {
    (
        PathBuf::from("/var/lib/kxprov/tokens.json"),
        PathBuf::from("/etc/kx-provision/secrets/gateway-daemon.bearer"),
    )
}
