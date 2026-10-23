use serde::{Deserialize, Serialize};

/// Profile banner (SIM / TEST / PROD).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Sim,
    Test,
    Prod,
}
use std::fmt;
use std::str::FromStr;

/// 128-bit random plan identifier (hex).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PlanId(pub String);

impl PlanId {
    pub fn new_random() -> Result<Self, getrandom::Error> {
        let mut b = [0u8; 16];
        getrandom::fill(&mut b)?;
        Ok(Self(hex::encode(b)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PlanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// SHA-256 over canonical plan bytes (hex).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DiffHash(pub String);

impl DiffHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DiffHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Opaque token identifier (never the secret bearer token).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TokenId(pub String);

impl TokenId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for TokenId {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > 64 {
            return Err("invalid token id");
        }
        Ok(Self(s.to_string()))
    }
}

/// Single-use approval for one exact plan under one profile (daemon-minted only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub plan_id: PlanId,
    pub diff_hash: DiffHash,
    pub profile: Profile,
    pub expires_at_ms: u64,
    #[serde(default)]
    pub consumed: bool,
}

impl Approval {
    pub fn active(&self, now_ms: u64, profile: Profile) -> bool {
        !self.consumed && now_ms < self.expires_at_ms && self.profile == profile
    }

    pub fn matches(&self, plan_id: &PlanId, diff_hash: &DiffHash, profile: Profile) -> bool {
        self.plan_id == *plan_id && self.diff_hash == *diff_hash && self.profile == profile
    }
}
