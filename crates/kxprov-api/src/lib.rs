//! Unix-socket API types and client for [`kxprovd`](../../kxprovd/README.md).
//!
//! v2.3: per-plan [`Approval`] (no daemon-wide arm), immutable plans tied to [`TokenId`],
//! [`PlanId`] + [`DiffHash`] + [`Profile`]; daemon enforces scope from SO_PEERCRED.

mod client;
mod ids;
mod plan_hash;
mod protocol;
mod surface;
mod tokens;
mod types;

pub use client::{ApiClient, ApiError};
pub use ids::{Approval, DiffHash, PlanId, Profile, TokenId};
pub use plan_hash::{diff_hash, CanonicalPlan, CanonicalWrite};
pub use protocol::*;
pub use surface::*;
pub use tokens::{
    hash_bearer_secret, validate_tokens_file, TokenEntry, TokenValidationError, TokensFile,
    TOKEN_JOBS_PER_MINUTE, TOKEN_QUEUE_DEPTH_MAX,
};
pub use types::*;
