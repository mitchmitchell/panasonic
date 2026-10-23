use serde::{Deserialize, Serialize};

use crate::scope::ScopeSet;
use crate::token_id::TokenId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpTokenIdentity {
    pub token_id: TokenId,
    pub agent_name: String,
    pub scopes: ScopeSet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAdminIdentity {
    pub session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallerIdentity {
    WebAdmin(WebAdminIdentity),
    Mcp(McpTokenIdentity),
}

impl CallerIdentity {
    pub fn rate_limit_key(&self) -> String {
        match self {
            Self::WebAdmin(a) => format!("web-admin:{}", a.session_id),
            Self::Mcp(t) => format!("mcp-token:{}", t.token_id.0),
        }
    }

    pub fn scopes(&self) -> ScopeSet {
        match self {
            Self::WebAdmin(_) => ScopeSet::empty()
                .with(crate::scope::Scope::Read)
                .with(crate::scope::Scope::Plan)
                .with(crate::scope::Scope::Write),
            Self::Mcp(t) => t.scopes.clone(),
        }
    }

    pub fn is_web_admin(&self) -> bool {
        matches!(self, Self::WebAdmin(_))
    }

    pub fn token_id(&self) -> Option<&TokenId> {
        match self {
            Self::Mcp(t) => Some(&t.token_id),
            _ => None,
        }
    }
}
