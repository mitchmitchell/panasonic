use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::error::ApiError;
use crate::profile::Profile;
use crate::types::PlanChangeRequest;

/// 128-bit random plan identifier (F1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlanId(pub u128);

impl Default for PlanId {
    fn default() -> Self {
        Self::new()
    }
}

impl PlanId {
    pub fn new() -> Self {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(u128::from_be_bytes(bytes))
    }

    pub fn to_hex(&self) -> String {
        format!("{:032x}", self.0)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, ApiError> {
        let id = u128::from_str_radix(hex_str.trim(), 16)
            .map_err(|_| ApiError::BadRequest("plan_id"))?;
        Ok(Self(id))
    }
}

/// SHA-256 over canonical plan bytes (profile, table, blocks, base/new bytes).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DiffHash(pub [u8; 32]);

impl DiffHash {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Self(out)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, ApiError> {
        let bytes = hex::decode(hex_str.trim()).map_err(|_| ApiError::BadRequest("diff_hash"))?;
        if bytes.len() != 32 {
            return Err(ApiError::BadRequest("diff_hash length"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(DiffHash(out))
    }
}

/// Canonical plan serialization for stable `DiffHash` (A3 will match this on the daemon).
pub fn canonical_plan_bytes(
    profile: &Profile,
    request: &PlanChangeRequest,
) -> Result<Vec<u8>, ApiError> {
    #[derive(Serialize)]
    struct Canonical<'a> {
        profile: &'a str,
        table: u8,
        record: u16,
        field: &'a str,
        new_value: &'a str,
        base_bytes: &'a [u8],
        new_bytes: &'a [u8],
    }
    let body = Canonical {
        profile: &profile.0,
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
