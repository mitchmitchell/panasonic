//! Whole-attempt read retry (read-path spec v1 §6, R6; issue #71).
//!
//! A transient failure ends the attempt. The client releases the line as far as the
//! attempt got (§6.4), waits the fixed backoff (§6.3), signs on fresh and re-reads the
//! failed table from its first frame. No frame is ever resent inside a session, and only
//! reads run here: [`read_tables`] never calls a write.

use crate::client::{Client, SessionState, Transport};
use crate::error::{Error, LoginFailure};
use std::collections::BTreeMap;
use std::fmt;

/// Attempts in total, first one included (§6.3).
pub const MAX_ATTEMPTS: u32 = 3;

/// Backoff before attempt 2 and before attempt 3, in milliseconds (§6.3).
pub const BACKOFF_MS: [u64; 2] = [2_000, 5_000];

/// NAK code the spec marks transient: a garbled read request (`04 01 01 02 08`, §6.2).
pub const TRANSIENT_NAK_CODE: u8 = 0x02;

/// How one failure counts toward the attempt budget (§6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Eligible for another attempt.
    Transient,
    /// Never retried; the read fails now.
    Definitive,
}

/// Where in the attempt a failure happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Signing on, before XON was seen: nothing secret has been sent.
    SignOnBeforeXon,
    /// Signing on, after XON was seen: the password may already be on the wire.
    SignOnAfterXon,
    /// Reading a table in binary mode.
    Read,
}

/// The §6.2 rule that decided a failure's [`Disposition`]. Each variant names its
/// source; [`Basis::disposition`] maps it with no default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// Transient (§6.2 list): no reply within the reply timeout.
    ReplyTimeout,
    /// Transient (§6.1, §6.2 list): a busy run outlasted the busy bound.
    BusyBoundExpired,
    /// Transient (§6.2 list): a garbled or bad-checksum reply.
    GarbledReply,
    /// Transient (§6.2 N5): reply command differs from the request, the stale-reply case a
    /// fresh session clears.
    MismatchedReply,
    /// Transient (§6.2 list): an extra or trailing frame after the reply.
    ExtraFrame,
    /// Transient (§6.2 list): read NAK code 02.
    ReadNak,
    /// Transient (§6.2 list): the pre-send drain failed with the link up, so nothing was
    /// sent.
    NothingSent,
    /// Transient (§6.2 list, "no XON / no banner"): sign-on timed out before XON, so the
    /// password was never sent.
    NoXon,
    /// Definitive (D2): the unit refused an address the read plan says is valid. The
    /// end-of-table refusal (D1) is handled by the full-table plan in L1-1, not here.
    AddressRefused,
    /// Definitive (D3, R3): wrong password, or any sign-on failure after XON. After XON
    /// the password may be on the wire, and a second password may count toward a
    /// lock-out. This is stricter than the §6.2 "no banner" row on purpose: a banner
    /// missing after XON is not retried either.
    PasswordMaybeSent,
    /// Definitive (D5): `NG`, or another terminal is connected.
    SessionRefused,
    /// Definitive (D4): a reply whose meaning the spec marks unknown (other NAK codes,
    /// unexpected reply kinds, over-long or too many sign-on lines).
    UnknownReply,
    /// Definitive (D6): link-down or session lost. §6.2 lists a `00` DTR drop mid-binary
    /// as transient, but the client reports it the same way as a PortManager link-down,
    /// so both stay definitive until U7 runs at the unit (#105).
    LinkLost,
    /// Definitive: the password or sign-on configuration is invalid; another attempt would
    /// send the same.
    BadConfig,
    /// Definitive: a local encoding, allow-list, field or state error. It happens before
    /// anything is sent and a fresh session would hit it again.
    LocalError,
    /// Definitive: an error only the write, verify, plan or logout paths raise. This
    /// module never calls them, so seeing one means the client is in a state the read
    /// path does not handle.
    NotReadPath,
}

impl Basis {
    /// The disposition each rule gives.
    pub const fn disposition(self) -> Disposition {
        match self {
            Self::ReplyTimeout
            | Self::BusyBoundExpired
            | Self::GarbledReply
            | Self::MismatchedReply
            | Self::ExtraFrame
            | Self::ReadNak
            | Self::NothingSent
            | Self::NoXon => Disposition::Transient,
            Self::AddressRefused
            | Self::PasswordMaybeSent
            | Self::SessionRefused
            | Self::UnknownReply
            | Self::LinkLost
            | Self::BadConfig
            | Self::LocalError
            | Self::NotReadPath => Disposition::Definitive,
        }
    }
}

/// Classifies a failure from a sign-on or a read per §6.2. The match lists every
/// [`Error`] and [`LoginFailure`] variant, so a new variant needs a decision here.
pub fn classify(error: &Error, phase: Phase) -> Basis {
    if phase == Phase::SignOnAfterXon {
        return classify_after_xon(error);
    }
    match error {
        Error::Timeout => match phase {
            Phase::SignOnBeforeXon => Basis::NoXon,
            Phase::Read | Phase::SignOnAfterXon => Basis::ReplyTimeout,
        },
        Error::BusyTimeout => Basis::BusyBoundExpired,
        Error::Garbled(_) => Basis::GarbledReply,
        Error::MismatchedReply { .. } => Basis::MismatchedReply,
        Error::ExtraFrame => Basis::ExtraFrame,
        Error::Nak { code, .. } => {
            if *code == TRANSIENT_NAK_CODE {
                Basis::ReadNak
            } else {
                Basis::UnknownReply
            }
        }
        Error::PreSend(inner) => match **inner {
            Error::LinkDown(_) => Basis::LinkLost,
            _ => Basis::NothingSent,
        },
        Error::Refused { .. } => Basis::AddressRefused,
        Error::UnexpectedReply(_) => Basis::UnknownReply,
        Error::LinkDown(_) | Error::SessionLost => Basis::LinkLost,
        Error::Login(failure) => classify_login(failure, phase),
        Error::Frame(_) | Error::NotAllowed(_) | Error::Field(_) | Error::BadState { .. } => {
            Basis::LocalError
        }
        Error::Unacked(_)
        | Error::VerifyPending
        | Error::EndBinaryHeld
        | Error::LineNotQuiet
        | Error::Locked
        | Error::Plan(_)
        | Error::NotPendingBlock
        | Error::ByeNotConfirmed(_) => Basis::NotReadPath,
    }
}

/// After XON, every failure is definitive except a local error raised before sending,
/// a link loss, or bad configuration, which keep their own basis for the journal.
fn classify_after_xon(error: &Error) -> Basis {
    match error {
        Error::LinkDown(_) | Error::SessionLost => Basis::LinkLost,
        Error::Login(LoginFailure::InvalidPassword | LoginFailure::InvalidSignOn { .. }) => {
            Basis::BadConfig
        }
        Error::Login(LoginFailure::Ng | LoginFailure::AnotherTerminal) => Basis::SessionRefused,
        Error::Login(
            LoginFailure::PasswordRejected
            | LoginFailure::LineTooLong { .. }
            | LoginFailure::TooManyLines { .. }
            | LoginFailure::TimedOut { .. },
        )
        | Error::Timeout
        | Error::BusyTimeout
        | Error::Garbled(_)
        | Error::MismatchedReply { .. }
        | Error::ExtraFrame
        | Error::Nak { .. }
        | Error::PreSend(_)
        | Error::Refused { .. }
        | Error::UnexpectedReply(_)
        | Error::Frame(_)
        | Error::NotAllowed(_)
        | Error::Field(_)
        | Error::BadState { .. }
        | Error::Unacked(_)
        | Error::VerifyPending
        | Error::EndBinaryHeld
        | Error::LineNotQuiet
        | Error::Locked
        | Error::Plan(_)
        | Error::NotPendingBlock
        | Error::ByeNotConfirmed(_) => Basis::PasswordMaybeSent,
    }
}

fn classify_login(failure: &LoginFailure, phase: Phase) -> Basis {
    match failure {
        LoginFailure::TimedOut { .. } => match phase {
            Phase::SignOnBeforeXon => Basis::NoXon,
            Phase::SignOnAfterXon | Phase::Read => Basis::PasswordMaybeSent,
        },
        LoginFailure::PasswordRejected => Basis::PasswordMaybeSent,
        LoginFailure::Ng | LoginFailure::AnotherTerminal => Basis::SessionRefused,
        LoginFailure::LineTooLong { .. } | LoginFailure::TooManyLines { .. } => Basis::UnknownReply,
        LoginFailure::InvalidPassword | LoginFailure::InvalidSignOn { .. } => Basis::BadConfig,
    }
}

/// What one attempt ended with, for the attempt journal (§6.6). Carries kinds and
/// counts only, never payload bytes or the password (R7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptRecord {
    /// 1-based attempt number.
    pub attempt: u32,
    /// The table that failed, if the attempt failed on a read.
    pub table: Option<u8>,
    /// The rule and the error kind, or `None` when the attempt read every remaining table.
    pub failure: Option<(Basis, &'static str)>,
    /// Backoff waited before this attempt started.
    pub backoff_ms_before: u64,
    /// Transport clock time the attempt took, release included.
    pub duration_ms: u64,
    /// Error kind if the §6.4 release after a failed attempt did not complete. Not
    /// retried: the next sign-on, or the caller's lease release, cycles DTR, which
    /// returns the unit to CLOSED either way (§6.1, §6.4).
    pub release_error: Option<&'static str>,
}

/// A read that ended without every table.
#[derive(Debug)]
pub struct ReadFailure {
    /// The error that ended the last attempt.
    pub error: Error,
    /// The rule that ended the read: definitive, or transient on the last attempt (D7).
    pub basis: Basis,
    /// Tables read in full before the failure; the failed table's partial bytes are
    /// discarded (§6.3).
    pub tables: BTreeMap<u8, Vec<u8>>,
    /// One record per attempt.
    pub attempts: Vec<AttemptRecord>,
}

impl ReadFailure {
    /// Whether the read stopped on a definitive outcome or ran out of attempts.
    pub const fn disposition(&self) -> Disposition {
        self.basis.disposition()
    }
}

impl fmt::Display for ReadFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "read failed after {} attempt(s) ({:?}): {}",
            self.attempts.len(),
            self.basis,
            self.error
        )
    }
}

impl std::error::Error for ReadFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Every requested table, plus the attempt journal.
#[derive(Debug)]
pub struct ReadSuccess {
    /// Wire image of each requested table, by table number.
    pub tables: BTreeMap<u8, Vec<u8>>,
    /// One record per attempt, the last one successful.
    pub attempts: Vec<AttemptRecord>,
}

/// Reads `tables` in order with up to [`MAX_ATTEMPTS`] whole attempts.
///
/// Each attempt signs on with [`Client::login`] (DTR cycle first, §2 step 0), reads the
/// tables not yet read in full, and on success leaves the session in binary mode for the
/// caller to end. On failure the attempt is released per §6.4: end-binary and BYE only
/// when this attempt's sign-on reached binary mode, nothing on the wire otherwise (the
/// next sign-on, or the caller's lease release, cycles DTR). `sleep` waits the backoff,
/// in milliseconds.
pub fn read_tables<T: Transport>(
    client: &mut Client<T>,
    password: &str,
    tables: &[u8],
    sleep: &mut dyn FnMut(u64),
) -> Result<ReadSuccess, Box<ReadFailure>> {
    let mut done = BTreeMap::new();
    let mut records = Vec::new();
    let mut attempt = 1;
    let mut backoff = 0;
    loop {
        if backoff > 0 {
            sleep(backoff);
        }
        let start = client.clock_ms();
        let failed = run_attempt(client, password, tables, &mut done);
        let (error, phase, table) = match failed {
            Ok(()) => {
                records.push(AttemptRecord {
                    attempt,
                    table: None,
                    failure: None,
                    backoff_ms_before: backoff,
                    duration_ms: client.clock_ms().saturating_sub(start),
                    release_error: None,
                });
                return Ok(ReadSuccess {
                    tables: done,
                    attempts: records,
                });
            }
            Err(failed) => failed,
        };
        let basis = classify(&error, phase);
        let release_error = match phase {
            Phase::Read => release(client),
            Phase::SignOnBeforeXon | Phase::SignOnAfterXon => None,
        };
        records.push(AttemptRecord {
            attempt,
            table,
            failure: Some((basis, error.kind())),
            backoff_ms_before: backoff,
            duration_ms: client.clock_ms().saturating_sub(start),
            release_error,
        });
        let next_backoff = BACKOFF_MS.get((attempt - 1) as usize).copied();
        match (basis.disposition(), next_backoff) {
            (Disposition::Transient, Some(wait)) if attempt < MAX_ATTEMPTS => {
                attempt += 1;
                backoff = wait;
            }
            (Disposition::Transient, _) | (Disposition::Definitive, _) => {
                return Err(Box::new(ReadFailure {
                    error,
                    basis,
                    tables: done,
                    attempts: records,
                }))
            }
        }
    }
}

fn run_attempt<T: Transport>(
    client: &mut Client<T>,
    password: &str,
    tables: &[u8],
    done: &mut BTreeMap<u8, Vec<u8>>,
) -> Result<(), (Error, Phase, Option<u8>)> {
    if let Err(e) = client.login(password) {
        let phase = if client.login_trace().is_some_and(|t| t.xon_seen) {
            Phase::SignOnAfterXon
        } else {
            Phase::SignOnBeforeXon
        };
        return Err((e, phase, None));
    }
    for &table in tables {
        if done.contains_key(&table) {
            continue;
        }
        let image = client
            .read_table(table)
            .map_err(|e| (e, Phase::Read, Some(table)))?;
        done.insert(table, image);
    }
    Ok(())
}

/// Releases an attempt that reached binary mode (§6.4) and returns the error kind if
/// that release did not complete. Called only after this attempt's sign-on succeeded,
/// so the session state is this attempt's, not one left over from an earlier session.
fn release<T: Transport>(client: &mut Client<T>) -> Option<&'static str> {
    match client.state() {
        SessionState::Binary | SessionState::Locked | SessionState::ByePending => {
            client.end_binary().err().map(|e| e.kind())
        }
        SessionState::Text
        | SessionState::AwaitingVerify(_)
        | SessionState::NeedsRollback(_)
        | SessionState::Closed
        | SessionState::Disconnected => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{classify, Basis, Disposition, Phase, TRANSIENT_NAK_CODE};
    use crate::client::SessionState;
    use crate::error::{
        Error, FieldError, FrameError, LoginFailure, NotAllowed, Op, PlanError, UnackedReason,
        UnackedWrite,
    };

    fn unacked() -> UnackedWrite {
        UnackedWrite {
            table: 0x24,
            record: 0,
            word: 0,
            payload: Vec::new(),
            reason: UnackedReason::Timeout,
        }
    }

    fn link_down() -> Error {
        Error::LinkDown("gone".into())
    }

    /// Expected basis per error in the read phase and before XON in sign-on. One row per
    /// `Error` and `LoginFailure` variant, so a wrong arm fails its row.
    fn table() -> Vec<(Error, Basis, Basis)> {
        use Basis as B;
        vec![
            (Error::Timeout, B::ReplyTimeout, B::NoXon),
            (Error::BusyTimeout, B::BusyBoundExpired, B::BusyBoundExpired),
            (
                Error::Garbled(FrameError::Empty),
                B::GarbledReply,
                B::GarbledReply,
            ),
            (
                Error::MismatchedReply {
                    expected: 0x01,
                    got: 0x0B,
                },
                B::MismatchedReply,
                B::MismatchedReply,
            ),
            (Error::ExtraFrame, B::ExtraFrame, B::ExtraFrame),
            (
                Error::Nak {
                    cmd: 0x01,
                    code: TRANSIENT_NAK_CODE,
                },
                B::ReadNak,
                B::ReadNak,
            ),
            (
                Error::Nak {
                    cmd: 0x01,
                    code: 0x07,
                },
                B::UnknownReply,
                B::UnknownReply,
            ),
            (
                Error::PreSend(Box::new(Error::Timeout)),
                B::NothingSent,
                B::NothingSent,
            ),
            (
                Error::PreSend(Box::new(link_down())),
                B::LinkLost,
                B::LinkLost,
            ),
            (
                Error::Refused { cmd: 0x01 },
                B::AddressRefused,
                B::AddressRefused,
            ),
            (
                Error::UnexpectedReply("status".into()),
                B::UnknownReply,
                B::UnknownReply,
            ),
            (link_down(), B::LinkLost, B::LinkLost),
            (Error::SessionLost, B::LinkLost, B::LinkLost),
            (
                Error::Login(LoginFailure::TimedOut { ms: 30_000 }),
                B::PasswordMaybeSent,
                B::NoXon,
            ),
            (
                Error::Login(LoginFailure::PasswordRejected),
                B::PasswordMaybeSent,
                B::PasswordMaybeSent,
            ),
            (
                Error::Login(LoginFailure::Ng),
                B::SessionRefused,
                B::SessionRefused,
            ),
            (
                Error::Login(LoginFailure::AnotherTerminal),
                B::SessionRefused,
                B::SessionRefused,
            ),
            (
                Error::Login(LoginFailure::LineTooLong { max: 1 }),
                B::UnknownReply,
                B::UnknownReply,
            ),
            (
                Error::Login(LoginFailure::TooManyLines { max: 1 }),
                B::UnknownReply,
                B::UnknownReply,
            ),
            (
                Error::Login(LoginFailure::InvalidPassword),
                B::BadConfig,
                B::BadConfig,
            ),
            (
                Error::Login(LoginFailure::InvalidSignOn { field: "prompt" }),
                B::BadConfig,
                B::BadConfig,
            ),
            (
                Error::Frame(FrameError::Empty),
                B::LocalError,
                B::LocalError,
            ),
            (
                Error::NotAllowed(NotAllowed::ReadOnlyEncoder),
                B::LocalError,
                B::LocalError,
            ),
            (
                Error::Field(FieldError::NotDigits),
                B::LocalError,
                B::LocalError,
            ),
            (
                Error::BadState {
                    op: Op::Request,
                    state: SessionState::Text,
                },
                B::LocalError,
                B::LocalError,
            ),
            (Error::Unacked(unacked()), B::NotReadPath, B::NotReadPath),
            (Error::VerifyPending, B::NotReadPath, B::NotReadPath),
            (Error::EndBinaryHeld, B::NotReadPath, B::NotReadPath),
            (Error::LineNotQuiet, B::NotReadPath, B::NotReadPath),
            (Error::Locked, B::NotReadPath, B::NotReadPath),
            (
                Error::Plan(PlanError::WrongTable { plan: 1, patch: 2 }),
                B::NotReadPath,
                B::NotReadPath,
            ),
            (Error::NotPendingBlock, B::NotReadPath, B::NotReadPath),
            (
                Error::ByeNotConfirmed("no reply".into()),
                B::NotReadPath,
                B::NotReadPath,
            ),
        ]
    }

    #[test]
    fn classify_read_and_pre_xon_rows() {
        for (error, read, before_xon) in table() {
            assert_eq!(classify(&error, Phase::Read), read, "read {error:?}");
            assert_eq!(
                classify(&error, Phase::SignOnBeforeXon),
                before_xon,
                "before XON {error:?}"
            );
        }
    }

    #[test]
    fn after_xon_nothing_is_transient() {
        for (error, _, _) in table() {
            let basis = classify(&error, Phase::SignOnAfterXon);
            assert_eq!(basis.disposition(), Disposition::Definitive, "{error:?}");
        }
        assert_eq!(
            classify(&Error::Timeout, Phase::SignOnAfterXon),
            Basis::PasswordMaybeSent
        );
        assert_eq!(
            classify(&link_down(), Phase::SignOnAfterXon),
            Basis::LinkLost
        );
    }

    #[test]
    fn transient_bases_are_exactly_the_section_6_2_list() {
        let transient = [
            Basis::ReplyTimeout,
            Basis::BusyBoundExpired,
            Basis::GarbledReply,
            Basis::MismatchedReply,
            Basis::ExtraFrame,
            Basis::ReadNak,
            Basis::NothingSent,
            Basis::NoXon,
        ];
        let definitive = [
            Basis::AddressRefused,
            Basis::PasswordMaybeSent,
            Basis::SessionRefused,
            Basis::UnknownReply,
            Basis::LinkLost,
            Basis::BadConfig,
            Basis::LocalError,
            Basis::NotReadPath,
        ];
        for b in transient {
            assert_eq!(b.disposition(), Disposition::Transient, "{b:?}");
        }
        for b in definitive {
            assert_eq!(b.disposition(), Disposition::Definitive, "{b:?}");
        }
    }
}
