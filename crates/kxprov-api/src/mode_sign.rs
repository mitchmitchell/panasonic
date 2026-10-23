//! Canonical mode.json signing (v2.6 F1).

use crate::protocol::MODE_SIGN_PREFIX;
use crate::OperationalMode;

pub fn mode_sign_message(mode: OperationalMode, counter: u64) -> Vec<u8> {
    let tag = match mode {
        OperationalMode::Testing => "testing",
        OperationalMode::Production => "production",
    };
    format!("{MODE_SIGN_PREFIX}\n{tag}\n{counter}\n").into_bytes()
}
