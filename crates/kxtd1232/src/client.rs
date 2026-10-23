//! Synchronous client over an abstract [`Transport`]. Holds no I/O itself: the transport
//! supplies bytes and the time, so the same rules run under the simulator (virtual time)
//! and, later, under the daemon's serial port.

use crate::error::{Error, FrameError, LoginFailure, UnackedReason, UnackedWrite};
use crate::frame::{self, Access, Cmd, Encoder, Reply, ReplyKind};
use crate::session::{Login, LoginState};
use crate::tables;

/// Transport errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Nothing arrived within the timeout.
    Timeout,
    /// The link is gone.
    LinkDown(String),
}

/// Byte transport plus clock. Implemented by the simulator and (A3) the daemon's port.
pub trait Transport {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError>;
    /// Return whatever bytes arrive within `timeout_ms` (at least one byte), or `Timeout`.
    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError>;
    /// Monotonic time in milliseconds.
    fn now_ms(&mut self) -> u64;
}

/// Timing parameters (defaults until hardware test H5 measures them; design §9b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// Reply timeout for reads/probes.
    pub reply_timeout_ms: u64,
    /// Ack wait per write (every real ack so far: <= 589 ms).
    pub ack_timeout_ms: u64,
    /// Longest busy run tolerated (observed ~7 s at ~128 ms cadence, plus margin).
    pub busy_limit_ms: u64,
    /// Quiet window that ends drain-until-quiet before a verify re-read.
    pub quiet_ms: u64,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            reply_timeout_ms: 5_000,
            ack_timeout_ms: 2_000,
            busy_limit_ms: 12_000,
            quiet_ms: 500,
        }
    }
}

/// Binary-session state. `end_binary` is only allowed from a terminal-safe state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// Not logged in.
    Text,
    /// Logged in, nothing pending.
    Binary,
    /// A write was not positively acked; verify (drain, then re-read) before anything else
    /// writes and before `end_binary`.
    AwaitingVerify(UnackedWrite),
    /// Verify matched neither plan nor base: roll back before `end_binary`.
    NeedsRollback(UnackedWrite),
    /// Rollback failed or the line never went quiet: read-only, end allowed.
    Locked,
    /// `end_binary` acked.
    Closed,
    /// Link lost while in binary mode; [`Client::login`] after transport reconnect.
    Disconnected,
}

/// Result of verifying a block after an unacked write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Re-read equals the new bytes.
    Applied,
    /// Re-read equals the base bytes: nothing was written.
    NotApplied,
    /// Neither: roll back.
    Neither,
}

/// Bytes discarded by a drain, kept for the log (never matched to a request).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drained {
    pub at_ms: u64,
    pub bytes: Vec<u8>,
}

pub struct Client<T: Transport> {
    t: T,
    enc: Encoder,
    timing: Timing,
    rx: Vec<u8>,
    state: SessionState,
    /// Restored after [`Client::login`] following [`SessionState::Disconnected`].
    resume: Option<SessionState>,
    drained: Vec<Drained>,
}

impl<T: Transport> Client<T> {
    /// A read-only client (writes refused by the encoder).
    pub fn new(transport: T) -> Self {
        Self::with(transport, Access::ReadOnly, Timing::default())
    }

    pub fn with(transport: T, access: Access, timing: Timing) -> Self {
        Self {
            t: transport,
            enc: Encoder::new(access),
            timing,
            rx: Vec::new(),
            state: SessionState::Text,
            resume: None,
            drained: Vec::new(),
        }
    }

    fn require_session(&self) -> Result<(), Error> {
        if matches!(self.state, SessionState::Disconnected) {
            return Err(Error::SessionLost);
        }
        Ok(())
    }

    fn note_link_down(&mut self, pending_verify: Option<UnackedWrite>) {
        self.resume = pending_verify
            .map(SessionState::AwaitingVerify)
            .or_else(|| {
                matches!(
                    self.state,
                    SessionState::AwaitingVerify(_) | SessionState::NeedsRollback(_)
                )
                .then(|| self.state.clone())
            });
        self.state = SessionState::Disconnected;
        self.rx.clear();
    }

    pub fn state(&self) -> &SessionState {
        &self.state
    }

    pub fn transport(&self) -> &T {
        &self.t
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.t
    }

    /// Bytes consumed by drains (late acks, busy frames), for the log.
    pub fn drained(&self) -> &[Drained] {
        &self.drained
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, Error> {
        match self.t.recv(timeout_ms) {
            Ok(b) => Ok(b),
            Err(TransportError::Timeout) => Err(Error::Timeout),
            Err(TransportError::LinkDown(s)) => Err(Error::LinkDown(s)),
        }
    }

    fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        self.t.send(data).map_err(|e| match e {
            TransportError::Timeout => Error::Timeout,
            TransportError::LinkDown(s) => Error::LinkDown(s),
        })
    }

    /// Text login to binary mode.
    pub fn login(&mut self, password: &str) -> Result<(), Error> {
        let mut sm = Login::new(password).map_err(Error::Login)?;
        while !sm.state().is_terminal() {
            let data = self.recv(self.timing.reply_timeout_ms)?;
            let out = sm.feed(&data);
            if !out.is_empty() {
                self.send(&out)?;
            }
        }
        match sm.state() {
            LoginState::Failed(f) => Err(Error::Login(f.clone())),
            _ => {
                self.state = self.resume.take().unwrap_or(SessionState::Binary);
                Ok(())
            }
        }
    }

    fn recv_frame(&mut self, timeout_ms: u64) -> Result<Vec<u8>, Error> {
        loop {
            match frame::frame_length(&self.rx) {
                Err(e) => return Err(Error::Garbled(e)),
                Ok(Some(n)) if self.rx.len() >= n => {
                    let raw: Vec<u8> = self.rx.drain(..n).collect();
                    return Ok(raw);
                }
                _ => {}
            }
            let more = self.recv(timeout_ms)?;
            self.rx.extend(more);
        }
    }

    /// Send once and return the reply for `cmd`. Busy frames are waited out (never answered
    /// with a resend) for at most the busy bound. A reply that does not decode, or whose
    /// command byte differs from the request, is an error. On any error the receive buffer
    /// is cleared so the next exchange starts on a frame boundary.
    fn request(&mut self, raw: &[u8], cmd: Cmd, timeout_ms: u64) -> Result<Reply, Error> {
        self.require_session()?;
        if matches!(self.state, SessionState::Text | SessionState::Closed) {
            return Err(Error::UnexpectedReply("not in binary mode".into()));
        }
        if let Err(e @ Error::LinkDown(_)) = self.send(raw) {
            self.note_link_down(None);
            return Err(e);
        }
        let r = self.await_reply(cmd, timeout_ms);
        if matches!(r, Err(Error::LinkDown(_))) {
            self.note_link_down(None);
        }
        if r.is_err() {
            self.rx.clear();
        }
        r
    }

    fn await_reply(&mut self, cmd: Cmd, timeout_ms: u64) -> Result<Reply, Error> {
        let mut busy_since: Option<u64> = None;
        loop {
            let raw = self.recv_frame(timeout_ms)?;
            let reply = frame::classify(&raw).map_err(Error::Garbled)?;
            if reply.kind == ReplyKind::Busy {
                let now = self.t.now_ms();
                let since = *busy_since.get_or_insert(now);
                if now.saturating_sub(since) > self.timing.busy_limit_ms {
                    return Err(Error::BusyTimeout);
                }
                continue;
            }
            if reply.cmd != cmd.byte() {
                return Err(Error::MismatchedReply {
                    expected: cmd.byte(),
                    got: reply.cmd,
                });
            }
            return Ok(reply);
        }
    }

    fn expect_data(&mut self, raw: &[u8], cmd: Cmd, len: usize) -> Result<Vec<u8>, Error> {
        let r = self.request(raw, cmd, self.timing.reply_timeout_ms)?;
        match r.kind {
            ReplyKind::Data(d) if d.len() == len => Ok(d),
            ReplyKind::Nak(code) => Err(Error::Nak { cmd: r.cmd, code }),
            ReplyKind::Refused => Err(Error::Refused { cmd: r.cmd }),
            k => Err(Error::UnexpectedReply(format!("{k:?}"))),
        }
    }

    /// Version probe: the 16-byte ROM id string.
    pub fn version(&mut self) -> Result<String, Error> {
        let raw = self.enc.version_probe();
        let d = self.expect_data(&raw, Cmd::Probe, 16)?;
        Ok(d.iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '?'
                }
            })
            .collect())
    }

    /// One read frame.
    pub fn read(
        &mut self,
        table: u8,
        record: u16,
        word: u16,
        nwords: u8,
    ) -> Result<Vec<u8>, Error> {
        self.require_session()?;
        let raw = self.enc.read(table, record, word, nwords)?;
        self.expect_data(&raw, Cmd::Read, 2 * nwords as usize)
    }

    /// Read `count` whole records from `first`, using the spec's frame chunking.
    pub fn read_records(&mut self, table: u8, first: u16, count: u16) -> Result<Vec<u8>, Error> {
        let s = tables::spec(table).ok_or(crate::error::NotAllowed::UnknownTable(table))?;
        let end = first.checked_add(count).filter(|&e| e <= s.records).ok_or(
            crate::error::NotAllowed::RecordOutOfRange {
                table,
                record: first.saturating_add(count.saturating_sub(1)),
                records: s.records,
            },
        )?;
        let rec_words = s.record_bytes / 2;
        let nn = u16::from(s.words_per_frame);
        let mut out = Vec::with_capacity(count as usize * s.record_bytes as usize);
        let mut rec = first;
        while rec < end {
            if rec_words <= nn {
                let n = s.records_per_frame.min(end - rec);
                out.extend(self.read(table, rec, 0, (n * rec_words) as u8)?);
                rec += n;
            } else {
                let mut w = 0;
                while w < rec_words {
                    let n = nn.min(rec_words - w);
                    out.extend(self.read(table, rec, w, n as u8)?);
                    w += n;
                }
                rec += 1;
            }
        }
        Ok(out)
    }

    /// The whole table image (wire form).
    pub fn read_table(&mut self, table: u8) -> Result<Vec<u8>, Error> {
        let s = tables::spec(table).ok_or(crate::error::NotAllowed::UnknownTable(table))?;
        self.read_records(table, 0, s.records)
    }

    /// One write frame. Never resent. Anything but a clean ack for command 0x00 (timeout,
    /// busy past the bound, a garbled frame, a reply for another command, a NAK, a non-ack
    /// reply) is reported as [`Error::Unacked`] and moves the session to `AwaitingVerify`.
    pub fn write(
        &mut self,
        table: u8,
        record: u16,
        word: u16,
        payload: &[u8],
    ) -> Result<(), Error> {
        self.require_session()?;
        match self.state {
            SessionState::Binary => {}
            SessionState::AwaitingVerify(_) | SessionState::NeedsRollback(_) => {
                return Err(Error::VerifyPending)
            }
            SessionState::Locked => return Err(Error::Locked),
            SessionState::Disconnected => return Err(Error::SessionLost),
            _ => return Err(Error::UnexpectedReply("not in binary mode".into())),
        }
        let raw = self.enc.write(table, record, word, payload)?;
        if let Err(e @ Error::LinkDown(_)) = self.send(&raw) {
            self.note_link_down(None);
            return Err(e);
        }
        let reply = self.await_reply(Cmd::Write, self.timing.ack_timeout_ms);
        if let Err(e @ Error::LinkDown(_)) = reply {
            let u = UnackedWrite {
                table,
                record,
                word,
                payload: payload.to_vec(),
                reason: UnackedReason::Timeout,
            };
            self.note_link_down(Some(u));
            return Err(e);
        }
        if reply.is_err() {
            self.rx.clear();
        }
        let reason = match reply {
            Ok(Reply {
                kind: ReplyKind::Ack,
                ..
            }) => return Ok(()),
            Ok(Reply {
                kind: ReplyKind::Nak(c),
                ..
            }) => UnackedReason::Nak(c),
            Ok(_) => UnackedReason::NotAnAck,
            Err(Error::Timeout) => UnackedReason::Timeout,
            Err(Error::BusyTimeout) => UnackedReason::BusyTimeout,
            Err(Error::Garbled(e)) => UnackedReason::Garbled(e),
            Err(Error::MismatchedReply { got, .. }) => UnackedReason::MismatchedReply { got },
            Err(e) => return Err(e),
        };
        let u = UnackedWrite {
            table,
            record,
            word,
            payload: payload.to_vec(),
            reason,
        };
        self.state = SessionState::AwaitingVerify(u.clone());
        Err(Error::Unacked(u))
    }

    /// Drain until quiet: discard (and log) everything until the line has been silent for
    /// `quiet_ms`, or fail with `LineNotQuiet` once the busy bound expires. A late ack
    /// consumed here is logged and never matched to the following re-read.
    pub fn drain_until_quiet(&mut self) -> Result<(), Error> {
        let start = self.t.now_ms();
        if !self.rx.is_empty() {
            let bytes = std::mem::take(&mut self.rx);
            self.drained.push(Drained {
                at_ms: start,
                bytes,
            });
        }
        loop {
            match self.recv(self.timing.quiet_ms) {
                Ok(bytes) => {
                    let at_ms = self.t.now_ms();
                    self.drained.push(Drained { at_ms, bytes });
                    if at_ms.saturating_sub(start) > self.timing.busy_limit_ms {
                        return Err(Error::LineNotQuiet);
                    }
                }
                Err(Error::Timeout) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    /// Verify a block after a write: drain until quiet, then re-read and compare.
    pub fn verify_block(
        &mut self,
        table: u8,
        record: u16,
        word: u16,
        new: &[u8],
        base: &[u8],
    ) -> Result<VerifyOutcome, Error> {
        self.require_session()?;
        if new.len() != base.len() || new.len() % 2 != 0 || new.is_empty() || new.len() > 252 {
            return Err(FrameError::BadPayloadLen(new.len()).into());
        }
        if let Err(e) = self.drain_until_quiet() {
            if e == Error::LineNotQuiet {
                self.state = SessionState::Locked;
            }
            return Err(e);
        }
        let got = self.read(table, record, word, (new.len() / 2) as u8)?;
        let outcome = if got == new {
            VerifyOutcome::Applied
        } else if got == base {
            VerifyOutcome::NotApplied
        } else {
            VerifyOutcome::Neither
        };
        if let SessionState::AwaitingVerify(u) = &self.state {
            if (u.table, u.record, u.word) == (table, record, word) {
                self.state = match outcome {
                    VerifyOutcome::Neither => SessionState::NeedsRollback(u.clone()),
                    _ => SessionState::Binary,
                };
            }
        }
        Ok(outcome)
    }

    /// Roll a block back to `base` and verify it. Success returns to `Binary`; any failure
    /// leaves the session `Locked` (read-only; `end_binary` allowed).
    pub fn rollback_block(
        &mut self,
        table: u8,
        record: u16,
        word: u16,
        base: &[u8],
    ) -> Result<(), Error> {
        self.require_session()?;
        if !matches!(
            self.state,
            SessionState::NeedsRollback(_) | SessionState::AwaitingVerify(_)
        ) {
            return Err(Error::UnexpectedReply("nothing to roll back".into()));
        }
        self.state = SessionState::Binary;
        let ok = self.write(table, record, word, base).is_ok()
            && matches!(
                self.verify_block(table, record, word, base, base),
                Ok(VerifyOutcome::Applied)
            );
        if ok {
            Ok(())
        } else {
            self.state = SessionState::Locked;
            Err(Error::Locked)
        }
    }

    /// Mark the session LOCKED (the daemon's choice after a failed verify).
    pub fn lock(&mut self) {
        self.state = SessionState::Locked;
    }

    /// Leave binary mode. Held (refused, nothing sent) while a write awaits verify or
    /// rollback.
    pub fn end_binary(&mut self) -> Result<(), Error> {
        if matches!(self.state, SessionState::Disconnected) {
            return Err(Error::SessionLost);
        }
        match self.state {
            SessionState::Binary | SessionState::Locked => {}
            SessionState::AwaitingVerify(_) | SessionState::NeedsRollback(_) => {
                return Err(Error::EndBinaryHeld)
            }
            SessionState::Text | SessionState::Closed => return Ok(()),
            SessionState::Disconnected => return Err(Error::SessionLost),
        }
        let raw = self.enc.end_binary();
        let r = self.request(&raw, Cmd::EndBinary, self.timing.reply_timeout_ms)?;
        match r.kind {
            ReplyKind::Ack => {
                self.state = SessionState::Closed;
                Ok(())
            }
            k => Err(Error::UnexpectedReply(format!("end-binary: {k:?}"))),
        }
    }
}

impl From<LoginFailure> for Error {
    fn from(f: LoginFailure) -> Self {
        Self::Login(f)
    }
}
