use crate::arm::ArmGrant;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    pub live_writes_approved: bool,
    pub max_arm_ttl_secs: u32,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            live_writes_approved: false,
            max_arm_ttl_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct GateState {
    pub config: GateConfig,
    pub locked: bool,
    pub arm: Option<ArmGrant>,
}

impl GateState {
    pub fn armed(&self) -> bool {
        self.arm.as_ref().is_some_and(ArmGrant::active)
    }

    pub fn take_arm_for_apply(&mut self, plan_id: &str, diff_hash: &str) -> bool {
        let Some(grant) = self.arm.as_mut() else {
            return false;
        };
        if grant.matches(plan_id, diff_hash) {
            grant.consume();
            true
        } else {
            false
        }
    }
}
