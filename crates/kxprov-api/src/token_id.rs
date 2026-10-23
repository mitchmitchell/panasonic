use serde::{Deserialize, Serialize};

/// Stable MCP token identifier for audit (never the bearer secret).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenId(pub String);
