//! Binary frame codec: `[LEN][CMD][...][SUM]`.
//!
//! LEN counts itself and every byte up to (not including) SUM. SUM is the 8-bit sum of all
//! preceding bytes. No escaping; one reply per request; same rule in both directions.

use crate::error::{FrameError, NotAllowed};
use crate::tables;

/// Largest write payload in one frame.
pub const MAX_WRITE_PAYLOAD: usize = 200;
/// A data reply is `LEN CMD 00 <2n> SUM`, so LEN = 3 + 2n must fit in one byte.
pub const MAX_READ_WORDS: u8 = 126;
/// The busy/NAK-style frame the PBX repeats (~128 ms cadence) after malformed frames.
pub const BUSY_FRAME: [u8; 5] = [0x04, 0xFF, 0x01, 0x00, 0x04];

/// Commands this library can send. The full-upload commands `0x0A` and `0x10` (meaning
/// UNKNOWN, gate G3) deliberately have **no variant**, so they cannot be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Cmd {
    Write = 0x00,
    Read = 0x01,
    Clock = 0x03,
    Probe = 0x08,
    EndBinary = 0x0B,
}

impl Cmd {
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// Map a byte to a sendable command. `0x0A`/`0x10` (and anything else) map to `None`.
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Write),
            0x01 => Some(Self::Read),
            0x03 => Some(Self::Clock),
            0x08 => Some(Self::Probe),
            0x0B => Some(Self::EndBinary),
            _ => None,
        }
    }
}

/// 8-bit sum of `data`.
pub fn checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |a, b| a.wrapping_add(*b))
}

/// Encode a frame for `cmd`. Crate-private: the only public way to build a request is
/// [`Encoder`], which applies the read/write guards. Neither this nor a raw-byte variant
/// is reachable from outside the crate:
///
/// ```compile_fail
/// let _ = kxtd1232::frame::encode(kxtd1232::frame::Cmd::Write, &[0x25, 0, 0, 0, 0, 0, 0, 0]);
/// ```
///
/// ```compile_fail
/// let _ = kxtd1232::frame::encode_raw(0x10, &[]);
/// ```
///
/// ```compile_fail
/// // No raw-byte constructor for Cmd either.
/// let _ = kxtd1232::frame::Cmd::from(0x0Au8);
/// ```
///
/// The guarded path refuses a table outside the allow-list:
///
/// ```
/// use kxtd1232::frame::{Access, Encoder};
/// let e = Encoder::new(Access::ReadWrite);
/// assert!(e.write(0x10, 0, 0, &[0, 0]).is_err());
/// assert!(Encoder::new(Access::ReadOnly).write(0x25, 0, 0, &[0, 0]).is_err());
/// ```
pub(crate) fn encode(cmd: Cmd, body: &[u8]) -> Result<Vec<u8>, FrameError> {
    encode_raw(cmd.byte(), body)
}

/// Encode with a raw command byte (crate-private; see [`encode`]).
fn encode_raw(cmd: u8, body: &[u8]) -> Result<Vec<u8>, FrameError> {
    let len = 2 + body.len();
    if len > 0xFF {
        return Err(FrameError::TooLong(len));
    }
    let mut out = Vec::with_capacity(len + 1);
    out.push(len as u8);
    out.push(cmd);
    out.extend_from_slice(body);
    out.push(checksum(&out));
    Ok(out)
}

/// A decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub cmd: u8,
    pub body: Vec<u8>,
}

/// Total length (LEN + 1) of the frame starting `buf`, or `None` if `buf` is empty.
pub fn frame_length(buf: &[u8]) -> Result<Option<usize>, FrameError> {
    match buf.first() {
        None => Ok(None),
        Some(&b) if b < 2 => Err(FrameError::InvalidLen(b)),
        Some(&b) => Ok(Some(b as usize + 1)),
    }
}

/// Decode one complete frame.
pub fn decode(raw: &[u8]) -> Result<Frame, FrameError> {
    let n = frame_length(raw)?.ok_or(FrameError::Empty)?;
    // frame_length rejects LEN < 2, so n >= 3 here.
    if raw.len() != n {
        return Err(FrameError::LengthMismatch {
            expected: n,
            got: raw.len(),
        });
    }
    if checksum(&raw[..n - 1]) != raw[n - 1] {
        return Err(FrameError::BadChecksum);
    }
    Ok(Frame {
        cmd: raw[1],
        body: raw[2..n - 1].to_vec(),
    })
}

/// What an encoder may emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read, clock, probe, end-binary. The default.
    ReadOnly,
    /// Also writes (still limited to the write allow-list).
    ReadWrite,
}

/// Builds request frames, enforcing the command allow-list and table guards.
#[derive(Debug, Clone, Copy)]
pub struct Encoder {
    access: Access,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new(Access::ReadOnly)
    }
}

impl Encoder {
    pub const fn new(access: Access) -> Self {
        Self { access }
    }

    pub const fn access(&self) -> Access {
        self.access
    }

    pub fn version_probe(&self) -> Vec<u8> {
        encode_small(Cmd::Probe, &[0x00])
    }

    pub fn status_probe(&self) -> Vec<u8> {
        encode_small(Cmd::Probe, &[0x01])
    }

    pub fn clock(&self) -> Vec<u8> {
        encode_small(Cmd::Clock, &[])
    }

    pub fn end_binary(&self) -> Vec<u8> {
        encode_small(Cmd::EndBinary, &[])
    }

    /// Read `nwords` words at `(table, record, word)`. Range-checked against the spec,
    /// including the 0x40+ first-half rule.
    pub fn read(
        &self,
        table: u8,
        record: u16,
        word: u16,
        nwords: u8,
    ) -> Result<Vec<u8>, crate::Error> {
        if !(1..=MAX_READ_WORDS).contains(&nwords) {
            return Err(FrameError::BadWordCount(nwords).into());
        }
        tables::check_readable(table, record, word, nwords)?;
        let mut body = vec![table];
        body.extend_from_slice(&record.to_be_bytes());
        body.extend_from_slice(&word.to_be_bytes());
        body.push(nwords);
        Ok(encode(Cmd::Read, &body)?)
    }

    /// Write `payload` at `(table, record, word)`. Refused unless the encoder is
    /// read-write and the table/span passes [`tables::check_writable`].
    pub fn write(
        &self,
        table: u8,
        record: u16,
        word: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>, crate::Error> {
        if self.access != Access::ReadWrite {
            return Err(NotAllowed::ReadOnlyEncoder.into());
        }
        tables::check_writable(table, record, word, payload.len())?;
        if payload.is_empty() || payload.len() > MAX_WRITE_PAYLOAD || payload.len() % 2 != 0 {
            return Err(FrameError::BadPayloadLen(payload.len()).into());
        }
        let mut body = vec![table];
        body.extend_from_slice(&record.to_be_bytes());
        body.extend_from_slice(&word.to_be_bytes());
        body.push(0x00);
        body.extend_from_slice(payload);
        Ok(encode(Cmd::Write, &body)?)
    }
}

/// Encode a frame whose body is known to be tiny (cannot exceed LEN).
fn encode_small(cmd: Cmd, body: &[u8]) -> Vec<u8> {
    let mut out = vec![(2 + body.len()) as u8, cmd.byte()];
    out.extend_from_slice(body);
    out.push(checksum(&out));
    out
}

/// Classified reply kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyKind {
    /// `LEN CMD 00 SUM`.
    Ack,
    /// `LEN CMD 00 <data> SUM`.
    Data(Vec<u8>),
    /// `LEN CMD 01 <code> SUM` (other than a read refusal).
    Nak(u8),
    /// Read past the end of a table: `04 01 01 03 09`.
    Refused,
    /// The busy frame `04 FF 01 00 04`.
    Busy,
    /// Status probe reply `08 01 <v>` (meaning of the value UNKNOWN).
    Status(u8),
    /// Anything else, kept raw.
    Other(Vec<u8>),
}

/// A decoded, classified reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub cmd: u8,
    pub kind: ReplyKind,
}

/// Decode and classify one reply frame.
pub fn classify(raw: &[u8]) -> Result<Reply, FrameError> {
    let f = decode(raw)?;
    let kind = if raw == BUSY_FRAME {
        ReplyKind::Busy
    } else if f.cmd == Cmd::Probe.byte() && f.body == [0x01, 0x03] {
        ReplyKind::Status(0x03)
    } else if f.body.len() == 2 && f.body[0] == 0x01 {
        if f.body[1] == 0x03 && f.cmd == Cmd::Read.byte() {
            ReplyKind::Refused
        } else {
            ReplyKind::Nak(f.body[1])
        }
    } else if f.body.first() == Some(&0x00) {
        if f.body.len() == 1 {
            ReplyKind::Ack
        } else {
            ReplyKind::Data(f.body[1..].to_vec())
        }
    } else {
        ReplyKind::Other(f.body.clone())
    };
    Ok(Reply { cmd: f.cmd, kind })
}
