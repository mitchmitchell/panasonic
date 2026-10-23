//! Protocol and policy constants (design v2.3 §13–§14). Durations are defaults until H5.

/// Login / text line cap (overflow = framing error).
pub const LINE_CAP_BYTES: usize = 256;

/// Mismatched reply frames tolerated before treating a write as unacked.
pub const STALE_FRAME_CAP: u32 = 4;

/// Per-plan approval lifetime (single-use).
pub const APPROVAL_TTL_SECS: u32 = 600;

/// submit_approval rate limits (v2.6 F1).
pub const APPROVAL_SUBMIT_LIMIT_HOUR: u32 = 5;
pub const APPROVAL_SUBMIT_LIMIT_DAY: u32 = 20;

/// Canonical prefix for mode.json ed25519 signatures.
pub const MODE_SIGN_PREFIX: &str = "kxprov-mode-v1";

/// Server-side plan retention.
pub const PLAN_EXPIRY_SECS: u32 = 1800;

/// Simulator busy-frame interval (parameterized; not a capture-derived constant in-repo).
pub const BUSY_CADENCE_DEFAULT_MS: u64 = 128;

/// Default busy-run duration in the simulator (parameterized).
pub const BUSY_DURATION_DEFAULT_MS: u64 = 7_000;

/// Busy bound with margin for the protocol client (§9b default until H5).
pub const BUSY_LIMIT_DEFAULT_MS: u64 = 12_000;

/// Verified `.DBH` backups retained on disk (v2.4 default).
pub const DEFAULT_BACKUP_KEEP: usize = 20;
