use kxprov_api::{diff_hash, CanonicalPlan, CanonicalWrite};
use kxprov_api::{DiffHash, PlanId, Profile, TokenId};
use time::OffsetDateTime;

use crate::error::BackendError;
use crate::types::PlanChangeRequest;

pub fn plan_id_from_hex(hex_str: &str) -> Result<PlanId, BackendError> {
    let trimmed = hex_str.trim();
    if trimmed.len() != 32 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BackendError::BadRequest("plan_id"));
    }
    Ok(PlanId(trimmed.to_ascii_lowercase()))
}

pub fn diff_hash_from_hex(hex_str: &str) -> Result<DiffHash, BackendError> {
    let trimmed = hex_str.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BackendError::BadRequest("diff_hash"));
    }
    Ok(DiffHash(trimmed.to_ascii_lowercase()))
}

pub fn canonical_diff_hash(profile: Profile, request: &PlanChangeRequest) -> DiffHash {
    let plan = CanonicalPlan {
        profile,
        table: request.table,
        record_size: 16,
        writes: vec![CanonicalWrite {
            table: request.table,
            record: request.record,
            word: 0,
            base: request.base_bytes.as_slice(),
            new: request.new_bytes.as_slice(),
        }],
    };
    diff_hash(&plan)
}

pub fn plan_storage_ttl() -> time::Duration {
    time::Duration::minutes(30)
}

pub fn approval_ttl() -> time::Duration {
    time::Duration::minutes(10)
}

#[derive(Debug, Clone)]
pub struct ImmutablePlan {
    pub id: PlanId,
    pub diff_hash: DiffHash,
    pub profile: Profile,
    #[allow(dead_code)]
    pub request: PlanChangeRequest,
    pub creator_token: Option<TokenId>,
    pub stored_at: OffsetDateTime,
}

impl ImmutablePlan {
    pub fn from_request(
        profile: Profile,
        request: PlanChangeRequest,
        creator_token: Option<TokenId>,
    ) -> Result<Self, BackendError> {
        let diff_hash = canonical_diff_hash(profile, &request);
        let id = PlanId::new_random().map_err(|_| BackendError::BadRequest("plan_id"))?;
        Ok(Self {
            id,
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
