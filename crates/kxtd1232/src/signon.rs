//! Text sign-on strings used by the login state machine, the BYE confirmation and the
//! simulator (mirrors the prototype's `kxtd1232/signon.py`).
//!
//! Provenance: these are synthetic placeholders, not the PBX's real wording. The exact
//! banner and prompts are not reproduced in this repo (clean room, decision 74). A real
//! deployment supplies them from private configuration via [`crate::Client::with_signon`]
//! or [`crate::session::Login::with_signon`]. `OK`, `NG`, `BYE`, `ECS OF` and `PRG` are
//! interface facts from the spec and stay in code.

/// Sign-on text the PBX sends during login and after logout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignOn {
    /// Banner line(s) before the password prompt (informational only).
    pub banner: String,
    /// The password prompt line.
    pub password_prompt: String,
    /// The line that acknowledges a correct password.
    pub mode_start: String,
    /// The line reporting that another terminal holds the programming port.
    pub in_use: String,
}

impl Default for SignOn {
    fn default() -> Self {
        Self {
            banner: "<SIGNON_BANNER>".into(),
            password_prompt: "Password:".into(),
            mode_start: "<MODE_START>".into(),
            in_use: "<TERMINAL_IN_USE>".into(),
        }
    }
}
