//! Single-use arm bound to one plan id + diff hash (v2.3 threat model).

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmGrant {
    pub plan_id: String,
    pub diff_hash: String,
    pub expires_at_ms: u64,
    pub used: bool,
}

impl ArmGrant {
    pub fn new(plan_id: String, diff_hash: String, ttl_secs: u32, max_ttl_secs: u32) -> Self {
        let ttl = ttl_secs.min(max_ttl_secs);
        let now = now_ms();
        Self {
            plan_id,
            diff_hash,
            expires_at_ms: now + u64::from(ttl) * 1000,
            used: false,
        }
    }

    pub fn active(&self) -> bool {
        !self.used && now_ms() < self.expires_at_ms
    }

    pub fn matches(&self, plan_id: &str, diff_hash: &str) -> bool {
        self.active() && self.plan_id == plan_id && self.diff_hash == diff_hash
    }

    pub fn consume(&mut self) {
        self.used = true;
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
