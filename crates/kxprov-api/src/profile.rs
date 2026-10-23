use serde::{Deserialize, Serialize};

/// Profile banner (SIM / TEST / PROD) — wire shape matches A3 `kxprov-api` ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Sim,
    Test,
    Prod,
}

impl Profile {
    pub fn test() -> Self {
        Self::Test
    }

    pub fn prod() -> Self {
        Self::Prod
    }

    pub fn parse_wire(s: &str) -> Result<Self, crate::error::ApiError> {
        let trimmed = s.trim();
        serde_json::from_value(serde_json::Value::String(trimmed.into()))
            .map_err(|_| crate::error::ApiError::BadRequest("profile"))
    }
}
