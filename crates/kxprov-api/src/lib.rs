//! Unix-socket API types and client for [`kxprovd`](../../kxprovd/README.md).
//!
//! v2.3: per-plan [`Approval`] (no daemon-wide arm), immutable plans tied to [`TokenId`],
//! [`PlanId`] + [`DiffHash`] + [`Profile`]; daemon enforces scope from SO_PEERCRED.

mod client;
mod ids;
mod mode_sign;
mod plan_hash;
mod protocol;
mod types;

pub use client::{ApiClient, ApiError};
pub use ids::{Approval, DiffHash, PlanId, Profile, TokenId};
pub use mode_sign::mode_sign_message;
pub use plan_hash::{diff_hash, CanonicalPlan, CanonicalWrite};
pub use protocol::*;
pub use types::*;
