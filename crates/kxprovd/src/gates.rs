use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GateConfig {
    pub live_writes_approved: bool,
}

#[derive(Debug, Clone, Default)]
pub struct GateState {
    pub config: GateConfig,
}
