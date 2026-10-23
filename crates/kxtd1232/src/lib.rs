//! Sans-I/O, synchronous protocol core for the Panasonic KX-TD1232 programming port.
//!
//! Clean-room: built only from Reverse Engineer's behavior spec and Architect's design
//! (v2.2). No tokio, no serial I/O: the [`client::Client`] drives an abstract
//! [`client::Transport`] and asks it for the time, so the simulator and (later) the
//! daemon's real port behave identically and tests run on virtual time.
//!
//! Safety rules enforced structurally here:
//! - The [`frame::Cmd`] enum has no variant for the full-upload commands `0x0A`/`0x10`
//!   (gate G3), so they cannot be encoded.
//! - Writes are allowed only to tables 0x24/0x25 (caller-ID) until G6/H8 closes.
//! - Tables 0x40 and up refuse any record index >= the first-cabinet record count.
//! - An unacked, garbled, mismatched or NAKed write is never resent: the session holds
//!   `end_binary` until a drain-then-re-read verify (and any rollback) finishes.

pub mod client;
pub mod error;
pub mod fields;
pub mod frame;
pub mod plan;
pub mod session;
pub mod signon;
pub mod tables;

pub use client::{
    Client, SendError, SessionState, Timing, TimingConfigError, Transport, TransportError,
    VerifyOutcome, MAX_LINK_BAUD, MIN_REPLY_GUARD_MS,
};
pub use error::Error;
pub use fields::FieldKind;
pub use frame::{Cmd, Encoder, Reply, ReplyKind};
pub use plan::{build_plan, field_patch, ChunkWrite, Granularity, Patch, WritePlan};
pub use signon::SignOn;
