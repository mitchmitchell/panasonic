//! Whole-attempt read retry (read-path spec v1 §6, R6; issue #71).
//!
//! A transient failure ends the attempt. The client releases the line as far as the
//! session got (§6.4), waits the fixed backoff (§6.3), signs on fresh and re-reads the
//! failed table from its first frame. No frame is ever resent inside a session, and only
//! reads run here: [`read_tables`] never calls a write.

use crate::client::{Client, SessionState, Transport};
use crate::error::{Error, LoginFailure};
use std::collections::BTreeMap;

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

/// Classifies an error from a sign-on or a read per §6.2.
///
/// `xon_seen` is whether the attempt's sign-on saw XON. A login timeout before XON is
/// "no XON / no banner" and transient; after XON the password may already be on the
/// wire, so R3 makes it definitive.
pub fn classify(error: &Error, xon_seen: bool) -> Disposition {
    match error {
        Error::Timeout
        | Error::BusyTimeout
        | Error::Garbled(_)
        | Error::MismatchedReply { .. }
        | Error::ExtraFrame => Disposition::Transient,
        Error::Nak { code, .. } if *code == TRANSIENT_NAK_CODE => Disposition::Transient,
        Error::PreSend(inner) if !matches!(**inner, Error::LinkDown(_)) => Disposition::Transient,
        Error::Login(LoginFailure::TimedOut { .. }) if !xon_seen => Disposition::Transient,
        _ => Disposition::Definitive,
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
    /// `None` when the attempt read every remaining table.
    pub failure: Option<(Disposition, &'static str)>,
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
    /// Whether the read stopped on a definitive outcome or ran out of attempts (D7).
    pub disposition: Disposition,
    /// Tables read in full before the failure; the failed table's partial bytes are
    /// discarded (§6.3).
    pub tables: BTreeMap<u8, Vec<u8>>,
    /// One record per attempt.
    pub attempts: Vec<AttemptRecord>,
}

/// Every requested table, plus the attempt journal.
#[derive(Debug)]
pub struct ReadSuccess {
    pub tables: BTreeMap<u8, Vec<u8>>,
    pub attempts: Vec<AttemptRecord>,
}

/// Reads `tables` in order with up to [`MAX_ATTEMPTS`] whole attempts.
///
/// Each attempt signs on with [`Client::login`] (DTR cycle first, §2 step 0), reads the
/// tables not yet read in full, and on success leaves the session in binary mode for the
/// caller to end. On failure the session is released per §6.4: end-binary and BYE when it
/// reached binary mode, nothing on the wire otherwise (the next sign-on, or the caller's
/// lease release, cycles DTR). `sleep` waits the backoff, in milliseconds.
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
        let (error, table) = match failed {
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
        let xon_seen = client.login_trace().is_some_and(|t| t.xon_seen);
        let disposition = classify(&error, xon_seen);
        let release_error = release(client);
        records.push(AttemptRecord {
            attempt,
            table,
            failure: Some((disposition, error.kind())),
            backoff_ms_before: backoff,
            duration_ms: client.clock_ms().saturating_sub(start),
            release_error,
        });
        let next_backoff = BACKOFF_MS.get((attempt - 1) as usize).copied();
        match (disposition, next_backoff) {
            (Disposition::Transient, Some(wait)) if attempt < MAX_ATTEMPTS => {
                attempt += 1;
                backoff = wait;
            }
            _ => {
                return Err(Box::new(ReadFailure {
                    error,
                    disposition,
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
) -> Result<(), (Error, Option<u8>)> {
    client.login(password).map_err(|e| (e, None))?;
    for &table in tables {
        if done.contains_key(&table) {
            continue;
        }
        let image = client.read_table(table).map_err(|e| (e, Some(table)))?;
        done.insert(table, image);
    }
    Ok(())
}

/// Releases the session as far as it got (§6.4) and returns the error kind if that
/// release did not complete.
fn release<T: Transport>(client: &mut Client<T>) -> Option<&'static str> {
    let in_binary = matches!(
        client.state(),
        SessionState::Binary | SessionState::Locked | SessionState::ByePending
    );
    if !in_binary {
        return None;
    }
    client.end_binary().err().map(|e| e.kind())
}

#[cfg(test)]
mod tests {
    use super::{classify, Disposition, TRANSIENT_NAK_CODE};
    use crate::error::FrameError;
    use crate::error::{Error, LoginFailure};

    #[test]
    fn classify_follows_spec_section_6_2() {
        let transient = [
            Error::Timeout,
            Error::BusyTimeout,
            Error::ExtraFrame,
            Error::Garbled(FrameError::Empty),
            Error::MismatchedReply {
                expected: 0x01,
                got: 0x02,
            },
            Error::Nak {
                cmd: 0x01,
                code: TRANSIENT_NAK_CODE,
            },
            Error::PreSend(Box::new(Error::Timeout)),
        ];
        for e in &transient {
            assert_eq!(classify(e, true), Disposition::Transient, "{e:?}");
        }
        let definitive = [
            Error::Refused { cmd: 0x01 },
            Error::Nak {
                cmd: 0x01,
                code: 0x07,
            },
            Error::UnexpectedReply("status".into()),
            Error::LinkDown("gone".into()),
            Error::SessionLost,
            Error::PreSend(Box::new(Error::LinkDown("gone".into()))),
            Error::Login(LoginFailure::PasswordRejected),
            Error::Login(LoginFailure::AnotherTerminal),
            Error::Login(LoginFailure::Ng),
        ];
        for e in &definitive {
            assert_eq!(classify(e, false), Disposition::Definitive, "{e:?}");
        }
    }

    #[test]
    fn login_timeout_is_transient_only_before_xon() {
        let e = Error::Login(LoginFailure::TimedOut { ms: 30_000 });
        assert_eq!(classify(&e, false), Disposition::Transient);
        assert_eq!(classify(&e, true), Disposition::Definitive);
    }
}
