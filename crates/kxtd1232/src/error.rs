//! Typed errors. Every failure the core can report is a variant here; nothing is a
//! string-only error, and callers (the CLI, later the daemon) match on kinds.

use std::fmt;

/// A frame that cannot be built or parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameError {
    /// No bytes at all.
    Empty,
    /// LEN byte below 2.
    InvalidLen(u8),
    /// LEN + 1 does not equal the buffer length.
    LengthMismatch { expected: usize, got: usize },
    /// Checksum byte does not match the 8-bit sum.
    BadChecksum,
    /// Encoded frame would not fit in one LEN byte.
    TooLong(usize),
    /// Read word count outside 1..=126.
    BadWordCount(u8),
    /// Write payload outside 1..=200 bytes or of odd length.
    BadPayloadLen(usize),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty frame"),
            Self::InvalidLen(b) => write!(f, "invalid LEN byte {b:#04x}"),
            Self::LengthMismatch { expected, got } => {
                write!(f, "length mismatch: LEN says {expected}, got {got}")
            }
            Self::BadChecksum => write!(f, "bad checksum"),
            Self::TooLong(n) => write!(f, "frame too long: {n}"),
            Self::BadWordCount(n) => write!(f, "word count {n} outside 1..=126"),
            Self::BadPayloadLen(n) => write!(f, "write payload length {n} not an even 1..=200"),
        }
    }
}

impl std::error::Error for FrameError {}

/// A request the core refuses to encode.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotAllowed {
    /// The encoder is read-only and a write was requested.
    ReadOnlyEncoder,
    /// Table id is not one of the 75 tables in the spec.
    UnknownTable(u8),
    /// Table is never written by DSHSOMT.
    NeverWritten(u8),
    /// Table >= 0x40 (half-table rule): not writable before G6.
    HalfTable(u8),
    /// Table not on the write allow-list (0x24/0x25 until G6/H8).
    NotEditable(u8),
    /// Record index outside the table (for 0x40 and up: >= first-cabinet Recs).
    RecordOutOfRange {
        table: u8,
        record: u16,
        records: u16,
    },
    /// Byte span runs past the end of the table image.
    SpanOutOfRange { table: u8, end: usize, size: usize },
}

impl fmt::Display for NotAllowed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadOnlyEncoder => write!(f, "write command not in the read-only allow-list"),
            Self::UnknownTable(t) => write!(f, "table {t:#04x} is not in the table spec"),
            Self::NeverWritten(t) => write!(f, "table {t:#04x} is never written"),
            Self::HalfTable(t) => {
                write!(
                    f,
                    "table {t:#04x} >= 0x40 is not writable (half-table rule)"
                )
            }
            Self::NotEditable(t) => write!(f, "table {t:#04x} is not on the editable list"),
            Self::RecordOutOfRange {
                table,
                record,
                records,
            } => write!(
                f,
                "record {record} out of range for table {table:#04x} (0..{records})"
            ),
            Self::SpanOutOfRange { table, end, size } => write!(
                f,
                "span ends at byte {end}, past table {table:#04x} size {size}"
            ),
        }
    }
}

impl std::error::Error for NotAllowed {}

/// A field value that cannot be encoded or a record that cannot be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldError {
    NotDigits,
    TooManyDigits { max: usize },
    NotPrintableAscii,
    TooLong { max: usize },
    BadRecordSize { expected: usize, got: usize },
    BadDigitCount(u8),
    BadDigitNibble(u8),
    MissingFfTerminator,
}

impl fmt::Display for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotDigits => write!(f, "caller-ID number must be ASCII digits only"),
            Self::TooManyDigits { max } => write!(f, "at most {max} digits"),
            Self::NotPrintableAscii => write!(f, "name must be printable ASCII"),
            Self::TooLong { max } => write!(f, "at most {max} characters"),
            Self::BadRecordSize { expected, got } => {
                write!(f, "bad record size: expected {expected}, got {got}")
            }
            Self::BadDigitCount(n) => write!(f, "bad digit count {n}"),
            Self::BadDigitNibble(n) => write!(f, "bad digit nibble {n:#x}"),
            Self::MissingFfTerminator => {
                write!(f, "caller-ID name record must be 16 bytes ending in 0xFF")
            }
        }
    }
}

impl std::error::Error for FieldError {}

/// Why the login state machine failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoginFailure {
    /// PBX answered `NG...`.
    Ng,
    /// PBX reports another terminal connected.
    AnotherTerminal,
    /// Password re-prompt (exact wrong-password reply is UNKNOWN, gate G5).
    PasswordRejected,
    /// A text line exceeded the cap without a newline.
    LineTooLong { max: usize },
    /// Password empty or contains CR/LF.
    InvalidPassword,
    /// More text lines than the cap before reaching binary mode.
    TooManyLines { max: usize },
    /// Login did not reach binary mode within the overall time limit.
    TimedOut { ms: u64 },
}

impl fmt::Display for LoginFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ng => write!(f, "PBX answered NG"),
            Self::AnotherTerminal => write!(f, "another terminal connected"),
            Self::PasswordRejected => write!(f, "password rejected"),
            Self::LineTooLong { max } => write!(f, "login line longer than {max} bytes"),
            Self::InvalidPassword => write!(f, "invalid password"),
            Self::TooManyLines { max } => write!(f, "more than {max} login lines"),
            Self::TimedOut { ms } => write!(f, "login not finished within {ms} ms"),
        }
    }
}

/// Details of a write that was not positively acked. Never resent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnackedWrite {
    pub table: u8,
    pub record: u16,
    pub word: u16,
    pub payload: Vec<u8>,
    pub reason: UnackedReason,
}

/// Why a write counts as unacked.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnackedReason {
    Timeout,
    BusyTimeout,
    /// The reply did not decode (bad checksum / length): may or may not have applied.
    Garbled(FrameError),
    /// A reply for another command arrived (stale or misaligned stream).
    MismatchedReply {
        got: u8,
    },
    /// A NAK; the data is believed unchanged, but it is verified like any unacked write.
    Nak(u8),
    /// A well-formed reply that is not an ack.
    NotAnAck,
    /// Another frame followed the ack within the quiet window: the ack may be stale.
    ExtraFrame,
    /// The link dropped while waiting for the ack.
    LinkDown(String),
}

impl fmt::Display for UnackedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "timeout"),
            Self::BusyTimeout => write!(f, "busy run past the bound"),
            Self::Garbled(e) => write!(f, "garbled ack ({e})"),
            Self::MismatchedReply { got } => write!(f, "reply for command {got:#04x}"),
            Self::Nak(c) => write!(f, "NAK code {c:#04x}"),
            Self::NotAnAck => write!(f, "reply is not an ack"),
            Self::ExtraFrame => write!(f, "extra frame after the ack (possibly stale)"),
            Self::LinkDown(s) => write!(f, "link down ({s})"),
        }
    }
}

/// Top-level error of the protocol core.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    Frame(FrameError),
    NotAllowed(NotAllowed),
    Field(FieldError),
    Login(LoginFailure),
    /// The transport reported the link is down.
    LinkDown(String),
    /// The serial session was lost (link drop); log in again before reads, writes, or verify.
    SessionLost,
    /// No reply within the timeout.
    Timeout,
    /// A busy run outlasted the bound: a link failure.
    BusyTimeout,
    /// A reply that does not decode.
    Garbled(FrameError),
    /// A reply whose command byte does not match the request.
    MismatchedReply {
        expected: u8,
        got: u8,
    },
    /// A NAK reply.
    Nak {
        cmd: u8,
        code: u8,
    },
    /// A read past the end of a table, refused by the PBX.
    Refused {
        cmd: u8,
    },
    /// A well-formed reply of the wrong kind or size.
    UnexpectedReply(String),
    /// The pre-send drain failed (line never quiet, or link down); nothing was sent.
    PreSend(Box<Error>),
    /// Another frame arrived within the quiet window after a reply, so the reply may be
    /// stale. The stream was resynced; the data is discarded.
    ExtraFrame,
    /// A write was not positively acked; verify by re-reading, never resend.
    Unacked(UnackedWrite),
    /// A write was attempted while an earlier one still awaits verify or rollback.
    VerifyPending,
    /// `end_binary` refused until verify/rollback reaches a terminal state.
    EndBinaryHeld,
    /// The line never went quiet within the busy bound before a verify re-read.
    LineNotQuiet,
    /// Verify did not match plan or backup, or rollback failed: session is LOCKED.
    Locked,
    /// The plan could not be built.
    Plan(PlanError),
    /// The operation is not valid in the current session state.
    BadState {
        op: Op,
        state: crate::client::SessionState,
    },
    /// `verify_block` or `rollback_block` named a block other than the pending write, or
    /// a different payload or length for it.
    NotPendingBlock,
    /// The PBX did not confirm BYE after end-binary.
    ByeNotConfirmed(String),
}

/// Client operations, for [`Error::BadState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Op {
    Request,
    Write,
    Rollback,
}

/// Why a write plan could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlanError {
    BaseSize {
        table: u8,
        expected: usize,
        got: usize,
    },
    WrongTable {
        plan: u8,
        patch: u8,
    },
    PatchOutsideImage,
    BadChunk(usize),
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BaseSize {
                table,
                expected,
                got,
            } => {
                write!(
                    f,
                    "base image is {got} bytes, table {table:#04x} is {expected}"
                )
            }
            Self::WrongTable { plan, patch } => {
                write!(f, "patch for table {patch:#04x} in a plan for {plan:#04x}")
            }
            Self::PatchOutsideImage => write!(f, "patch outside table image"),
            Self::BadChunk(n) => write!(f, "chunk of {n} bytes"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(e) => write!(f, "frame: {e}"),
            Self::NotAllowed(e) => write!(f, "not allowed: {e}"),
            Self::Field(e) => write!(f, "invalid value: {e}"),
            Self::Login(e) => write!(f, "login failed: {e}"),
            Self::LinkDown(s) => write!(f, "link down: {s}"),
            Self::SessionLost => write!(f, "session lost: login required"),
            Self::Timeout => write!(f, "timeout waiting for reply"),
            Self::BusyTimeout => write!(f, "busy run longer than the bound"),
            Self::Garbled(e) => write!(f, "bad reply: {e}"),
            Self::MismatchedReply { expected, got } => {
                write!(f, "reply for command {got:#04x}, expected {expected:#04x}")
            }
            Self::Nak { cmd, code } => write!(f, "NAK {code:#04x} for command {cmd:#04x}"),
            Self::Refused { cmd } => write!(f, "refused by PBX (command {cmd:#04x})"),
            Self::UnexpectedReply(s) => write!(f, "unexpected reply: {s}"),
            Self::PreSend(e) => write!(f, "not sent: line not ready ({e})"),
            Self::ExtraFrame => write!(f, "extra frame after reply (possibly stale); discarded"),
            Self::Unacked(u) => write!(
                f,
                "write to table {:#04x} record {} not acked: {}",
                u.table, u.record, u.reason
            ),
            Self::VerifyPending => write!(f, "an earlier write still awaits verify"),
            Self::EndBinaryHeld => write!(f, "end_binary held until verify/rollback finishes"),
            Self::LineNotQuiet => write!(f, "line did not go quiet before verify re-read"),
            Self::Locked => write!(f, "session LOCKED: verify or rollback failed"),
            Self::Plan(e) => write!(f, "plan: {e}"),
            Self::BadState { op, state } => write!(f, "{op:?} not allowed in state {state:?}"),
            Self::NotPendingBlock => write!(f, "not the block pending verify or rollback"),
            Self::ByeNotConfirmed(s) => write!(f, "BYE not confirmed: {s}"),
        }
    }
}

impl std::error::Error for PlanError {}
impl std::error::Error for LoginFailure {}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Frame(e) | Self::Garbled(e) => Some(e),
            Self::NotAllowed(e) => Some(e),
            Self::Field(e) => Some(e),
            Self::Login(e) => Some(e),
            Self::Plan(e) => Some(e),
            Self::PreSend(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<FrameError> for Error {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}
impl From<NotAllowed> for Error {
    fn from(e: NotAllowed) -> Self {
        Self::NotAllowed(e)
    }
}
impl From<FieldError> for Error {
    fn from(e: FieldError) -> Self {
        Self::Field(e)
    }
}
