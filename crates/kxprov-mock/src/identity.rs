use kxprov_api::{Scope, TokenId};

use crate::scope::ScopeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpTokenIdentity {
    pub token_id: TokenId,
    pub agent_name: String,
    pub scopes: ScopeSet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSessionIdentity {
    pub session_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerIdentity {
    Web(WebSessionIdentity),
    Mcp(McpTokenIdentity),
}

impl CallerIdentity {
    pub fn rate_limit_key(&self) -> String {
        match self {
            Self::Web(w) => format!("web-session:{}", w.session_key),
            Self::Mcp(t) => format!("mcp-token:{}", t.token_id.0),
        }
    }

    pub fn scopes(&self) -> ScopeSet {
        match self {
            Self::Web(_) => ScopeSet::empty().with(Scope::Read).with(Scope::Plan),
            Self::Mcp(t) => t.scopes.clone(),
        }
    }

    pub fn token_id(&self) -> Option<&TokenId> {
        match self {
            Self::Mcp(t) => Some(&t.token_id),
            _ => None,
        }
    }
}
