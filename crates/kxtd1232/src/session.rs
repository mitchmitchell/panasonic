//! Sans-I/O login state machine (RE handoff §1.2-1.3).
//!
//! The caller feeds received bytes and sends whatever [`Login::feed`] returns. Timing
//! (CR LF about 5 ms after XON, never inside the XOFF window) belongs to the transport.

use crate::error::LoginFailure;
use std::fmt;

pub const XOFF: u8 = 0x13;
pub const XON: u8 = 0x11;
/// Longest text line accepted during login before failing closed.
pub const MAX_LINE: usize = 256;
/// Most text lines accepted during login (the real flow has under ten).
pub const MAX_LINES: usize = 32;

/// Login states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginState {
    WaitXon,
    WaitPrompt,
    WaitEia,
    WaitEcsOk,
    WaitPrgOk,
    Binary,
    Failed(LoginFailure),
}

impl LoginState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Binary | Self::Failed(_))
    }
}

/// The login state machine. Its `Debug` never shows the password.
pub struct Login {
    password: Vec<u8>,
    state: LoginState,
    buf: Vec<u8>,
    lines: usize,
}

impl fmt::Debug for Login {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Login(state={:?})", self.state)
    }
}

impl Login {
    pub fn new(password: &str) -> Result<Self, LoginFailure> {
        if password.is_empty() || password.contains(['\r', '\n']) || !password.is_ascii() {
            return Err(LoginFailure::InvalidPassword);
        }
        Ok(Self {
            password: password.as_bytes().to_vec(),
            state: LoginState::WaitXon,
            buf: Vec::new(),
            lines: 0,
        })
    }

    pub fn state(&self) -> &LoginState {
        &self.state
    }

    /// Feed received bytes; returns bytes to send.
    pub fn feed(&mut self, mut data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if self.state == LoginState::WaitXon {
            match data.iter().position(|&b| b == XON) {
                None => {
                    // Text before XON still counts against the line cap.
                    self.lines += data.iter().filter(|&&b| b == b'\n').count();
                    if self.lines > MAX_LINES {
                        self.state =
                            LoginState::Failed(LoginFailure::TooManyLines { max: MAX_LINES });
                    }
                    return out;
                }
                Some(i) => {
                    self.state = LoginState::WaitPrompt;
                    out.extend_from_slice(b"\r\n");
                    data = &data[i + 1..];
                }
            }
        }
        if self.state.is_terminal() {
            return out;
        }
        self.buf.extend_from_slice(data);
        while !self.state.is_terminal() {
            let Some(nl) = self.buf.iter().position(|&b| b == b'\n') else {
                if self.buf.len() > MAX_LINE {
                    self.state = LoginState::Failed(LoginFailure::LineTooLong { max: MAX_LINE });
                }
                break;
            };
            let line: Vec<u8> = self.buf.drain(..=nl).collect();
            self.lines += 1;
            if self.lines > MAX_LINES {
                self.state = LoginState::Failed(LoginFailure::TooManyLines { max: MAX_LINES });
                break;
            }
            if line.len() > MAX_LINE + 1 {
                self.state = LoginState::Failed(LoginFailure::LineTooLong { max: MAX_LINE });
                break;
            }
            let text: String = line
                .iter()
                .filter(|&&b| !matches!(b, b'\r' | b'\n' | 0x00 | XON | XOFF))
                .map(|&b| b as char)
                .collect();
            out.extend(self.line(text.trim()));
        }
        out
    }

    fn line(&mut self, line: &str) -> Vec<u8> {
        if line.is_empty() {
            return Vec::new();
        }
        if line.starts_with("NG") {
            self.state = LoginState::Failed(LoginFailure::Ng);
            return Vec::new();
        }
        if line.contains("Another Terminal Connected") {
            self.state = LoginState::Failed(LoginFailure::AnotherTerminal);
            return Vec::new();
        }
        match (&self.state, line) {
            (LoginState::WaitPrompt, "Enter Password") => {
                self.state = LoginState::WaitEia;
                let mut v = self.password.clone();
                v.push(b'\r');
                v
            }
            // Re-prompt: the real wrong-password reply is UNKNOWN (gate G5).
            (LoginState::WaitEia, "Enter Password") => {
                self.state = LoginState::Failed(LoginFailure::PasswordRejected);
                Vec::new()
            }
            (LoginState::WaitEia, "EIA Mode Start") => {
                self.state = LoginState::WaitEcsOk;
                b"ECS OF\r\n".to_vec()
            }
            (LoginState::WaitEcsOk, "OK") => {
                self.state = LoginState::WaitPrgOk;
                b"PRG\r\n".to_vec()
            }
            (LoginState::WaitPrgOk, "OK") => {
                self.state = LoginState::Binary;
                Vec::new()
            }
            _ => Vec::new(),
        }
    }
}
