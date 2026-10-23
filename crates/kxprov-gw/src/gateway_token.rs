use std::fs;
use std::path::{Path, PathBuf};

use kxprov_api::{ApiClient, RequestAuth, RequestBody, ResponseResult, Scope};
use thiserror::Error;

use crate::auth::validate_secret_file;

#[derive(Debug, Error)]
pub enum GatewayTokenError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("api: {0}")]
    Api(#[from] kxprov_api::ApiError),
    #[error("gateway bearer: {0}")]
    Invalid(String),
}

/// Gateway daemon bearer (read + plan only), validated via daemon [`Whoami`](kxprov_api::RequestBody::Whoami).
#[derive(Clone)]
pub struct GatewayDaemonToken {
    bearer: String,
}

impl GatewayDaemonToken {
    pub async fn load(bearer_path: &Path, daemon_socket: &Path) -> Result<Self, GatewayTokenError> {
        validate_secret_file(bearer_path, "gateway daemon bearer")
            .map_err(|e| GatewayTokenError::Invalid(e.to_string()))?;
        let bearer = fs::read_to_string(bearer_path)?.trim().to_string();
        if bearer.is_empty() {
            return Err(GatewayTokenError::Invalid("empty gateway bearer".into()));
        }
        let whoami = Self::whoami(daemon_socket, &bearer).await?;
        validate_gateway_scopes(&whoami)?;
        Ok(Self { bearer })
    }

    async fn whoami(
        socket: &Path,
        bearer: &str,
    ) -> Result<kxprov_api::WhoamiResult, GatewayTokenError> {
        let mut client = ApiClient::connect(socket).await?;
        let result = client
            .call_auth(
                RequestBody::Whoami,
                Some(RequestAuth {
                    bearer: bearer.to_string(),
                }),
            )
            .await?;
        match result {
            ResponseResult::Whoami(w) => Ok(w),
            _ => Err(GatewayTokenError::Invalid(
                "unexpected whoami response".into(),
            )),
        }
    }

    pub fn bearer(&self) -> &str {
        &self.bearer
    }
}

fn validate_gateway_scopes(whoami: &kxprov_api::WhoamiResult) -> Result<(), GatewayTokenError> {
    if whoami
        .scopes
        .iter()
        .any(|s| *s == Scope::Write || *s == Scope::Approve)
    {
        return Err(GatewayTokenError::Invalid(
            "gateway service token must not include write or approve scope".into(),
        ));
    }
    if !whoami.scopes.contains(&Scope::Read) || !whoami.scopes.contains(&Scope::Plan) {
        return Err(GatewayTokenError::Invalid(
            "gateway service token must include read and plan scopes".into(),
        ));
    }
    Ok(())
}

pub fn default_paths() -> (PathBuf, PathBuf) {
    (
        PathBuf::from(kxprov_api::TOKENS_JSON),
        PathBuf::from("/etc/kx-provision/secrets/gateway-daemon.bearer"),
    )
}
