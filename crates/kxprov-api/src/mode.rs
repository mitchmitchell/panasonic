use serde::{Deserialize, Serialize};

/// Daemon operating mode (F1). Mode is read-only via status; nothing in MCP/web sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    ReadOnly,
    Testing,
    Production,
}

impl Mode {
    /// Uppercase banner text for the web UI (operational mode).
    pub fn banner_label(self) -> &'static str {
        match self {
            Mode::ReadOnly => "READ-ONLY",
            Mode::Testing => "TESTING",
            Mode::Production => "PRODUCTION",
        }
    }

    /// CSS modifier for the mode banner (`testing`, `production`, `readonly`).
    pub fn banner_class(self) -> &'static str {
        match self {
            Mode::ReadOnly => "readonly",
            Mode::Testing => "testing",
            Mode::Production => "production",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_list_includes_testing_and_production() {
        let testing = serde_json::to_value(Mode::Testing).unwrap();
        let production = serde_json::to_value(Mode::Production).unwrap();
        assert_eq!(testing, "testing");
        assert_eq!(production, "production");
    }

    #[test]
    fn banner_labels_are_uppercase_operational() {
        assert_eq!(Mode::Testing.banner_label(), "TESTING");
        assert_eq!(Mode::Production.banner_label(), "PRODUCTION");
    }
}
