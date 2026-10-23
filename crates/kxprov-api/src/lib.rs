//! Unix-socket API types and client for [`kxprovd`](../../kxprovd/README.md).
//!
//! v2.3: per-plan [`Approval`] (no daemon-wide arm), immutable plans tied to [`TokenId`],
//! [`PlanId`] + [`DiffHash`] + [`Profile`]; daemon enforces scope from SO_PEERCRED.

mod client;
mod ids;
mod paths;
mod plan_hash;
mod protocol;
mod surface;
mod tokens;
mod types;

pub use client::{ApiClient, ApiError};
pub use ids::{Approval, DiffHash, PlanId, Profile, TokenId};
pub use paths::{
    goliath_dir, mode_counter_path, production_layout, profile_data_dir, profile_dir_name,
    resolve_profile_data_dir, sim_passed_path, DAEMON_ETC_CONFIG, DAEMON_SOCKET, DATA_DIR,
    MODE_COUNTER, SIM_PASSED_JSON, TOKENS_JSON,
};
pub use plan_hash::{diff_hash, CanonicalPlan, CanonicalWrite};
pub use protocol::*;
pub use surface::*;
pub use tokens::{
    hash_bearer_secret, TokenEntry, TokensFile, TOKEN_JOBS_PER_MINUTE, TOKEN_QUEUE_DEPTH_MAX,
};
pub use types::*;
