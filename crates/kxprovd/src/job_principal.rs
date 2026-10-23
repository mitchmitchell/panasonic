//! Job queue identity: real bearer tokens vs Unix-socket synthetic principals.

use kxprov_api::TokenId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobPrincipal {
    Token(TokenId),
    SyntheticRoot,
    SyntheticLocal { uid: u32 },
}

impl JobPrincipal {
    /// Per-token / per-local-uid rate limit bucket key (`local:{uid}` for read-only peers).
    pub fn rate_limit_key(&self) -> Option<String> {
        match self {
            Self::Token(id) => Some(id.as_str().to_string()),
            Self::SyntheticLocal { uid } => Some(format!("local:{uid}")),
            Self::SyntheticRoot => Some("root".into()),
        }
    }

    pub fn token_id(&self) -> Option<&TokenId> {
        match self {
            Self::Token(id) => Some(id),
            _ => None,
        }
    }
}
