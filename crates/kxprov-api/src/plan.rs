use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use time::OffsetDateTime;

use crate::error::ApiError;
use crate::profile::Profile;
use crate::types::PlanChangeRequest;

/// 128-bit random plan identifier (hex).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PlanId(pub String);

impl Default for PlanId {
    fn default() -> Self {
        Self::new()
    }
}

impl PlanId {
    pub fn new() -> Self {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        self.0.clone()
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, ApiError> {
        let trimmed = hex_str.trim();
        if trimmed.len() != 32 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ApiError::BadRequest("plan_id"));
        }
        Ok(Self(trimmed.to_ascii_lowercase()))
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
    pub fn from_canonical_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        self.0.clone()
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, ApiError> {
        let trimmed = hex_str.trim();
        if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ApiError::BadRequest("diff_hash"));
        }
        Ok(Self(trimmed.to_ascii_lowercase()))
    }
}

impl fmt::Display for DiffHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Canonical plan serialization for stable `DiffHash` (A3 will match this on the daemon).
pub fn canonical_plan_bytes(
    profile: &Profile,
    request: &PlanChangeRequest,
) -> Result<Vec<u8>, ApiError> {
    #[derive(Serialize)]
    struct Canonical<'a> {
        profile: Profile,
        table: u8,
        record: u16,
        field: &'a str,
        new_value: &'a str,
        base_bytes: &'a [u8],
        new_bytes: &'a [u8],
    }
    let body = Canonical {
        profile: *profile,
        table: request.table,
        record: request.record,
        field: &request.field,
        new_value: &request.new_value,
        base_bytes: request.base_bytes.as_slice(),
        new_bytes: request.new_bytes.as_slice(),
    };
    serde_json::to_vec(&body).map_err(|_| ApiError::BadRequest("canonical plan"))
}

/// Stored plan: immutable once created (F7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmutablePlan {
    pub id: PlanId,
    pub diff_hash: DiffHash,
    pub profile: Profile,
    pub request: PlanChangeRequest,
    pub creator_token: Option<crate::token_id::TokenId>,
    pub stored_at: OffsetDateTime,
}

impl ImmutablePlan {
    pub fn from_request(
        profile: Profile,
        request: PlanChangeRequest,
        creator_token: Option<crate::token_id::TokenId>,
    ) -> Result<Self, ApiError> {
        let bytes = canonical_plan_bytes(&profile, &request)?;
        let diff_hash = DiffHash::from_canonical_bytes(&bytes);
        Ok(Self {
            id: PlanId::new(),
            diff_hash,
            profile,
            request,
            creator_token,
            stored_at: OffsetDateTime::now_utc(),
        })
    }

    pub fn is_expired(&self, ttl: time::Duration) -> bool {
        OffsetDateTime::now_utc() > self.stored_at + ttl
    }
}
