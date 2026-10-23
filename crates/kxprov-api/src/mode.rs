use serde::{Deserialize, Serialize};

/// Daemon operating mode (F1). Mode is read-only via status; nothing in MCP/web sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    ReadOnly,
    DryRun,
    Production,
}

impl Mode {
    pub fn banner_label(self) -> &'static str {
        match self {
            Mode::ReadOnly => "Read-only",
            Mode::DryRun => "Dry-run",
            Mode::Production => "Production",
        }
    }
}
