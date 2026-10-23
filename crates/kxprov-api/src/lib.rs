//! Unix-socket API types and client for [`kxprovd`](../../kxprovd/README.md).
//!
//! Newline-delimited JSON: one [`RequestEnvelope`] per line, one [`Response`] per line.
//!
//! v2.3 (threat model): plans are immutable and content-addressed; arming binds one plan id
//! and diff hash (single-use, TTL); the daemon enforces [`Scope`] from SO_PEERCRED and does
//! not trust the gateway to skip checks.

mod client;
mod types;

pub use client::{ApiClient, ApiError};
pub use types::*;
