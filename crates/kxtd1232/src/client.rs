//! Synchronous client over an abstract [`Transport`]. Holds no I/O itself: the transport
//! supplies bytes and the time, so the same rules run under the simulator (virtual time)
//! and, later, under the daemon's serial port.

use crate::error::{Error, FrameError, LoginFailure, Op, UnackedReason, UnackedWrite};
use crate::frame::{self, Access, Cmd, Encoder, Reply, ReplyKind};
use crate::session::{Login, LoginState};
use crate::signon::SignOn;
use crate::tables;

/// Link loss on the transport (send or receive).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkDownError {
    pub detail: String,
    /// Bytes transmitted before a **`send`** failure (`None` = not applicable, e.g. receive).
    /// Provably zero bytes on send use [`TransportError::NothingWritten`], not `Some(0)`.
    pub bytes_sent: Option<usize>,
}

/// Transport errors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportError {
    /// Nothing arrived within the timeout.
    Timeout,
    /// From `send`: some or all of the data may have reached the line when
    /// [`LinkDownError::bytes_sent`] is `Some(n > 0)`. From `recv`: `bytes_sent` is `None`.
    /// Surfaces to callers as [`Error::LinkDown`].
    LinkDown(LinkDownError),
    /// From `send` only: provably zero bytes were written. The client maps this to
    /// [`Error::PreSend`] wrapping [`Error::LinkDown`], not to a top-level `LinkDown`.
    NothingWritten(String),
}

/// Byte transport plus clock. Implemented by the simulator and (A3) the daemon's port.
pub trait Transport {
    /// Write all of `data`. Return [`TransportError::NothingWritten`] only when no byte
    /// could have left the host; any partial or complete on-wire data is
    /// [`TransportError::LinkDown`] (possibly applied for writes).
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError>;
    /// Return whatever bytes arrive within `timeout_ms` (at least one byte), or `Timeout`.
    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError>;
    /// Monotonic time in milliseconds.
    fn now_ms(&mut self) -> u64;
    fn cycle_dtr(&mut self) -> Result<bool, TransportError> {
        Ok(false)
    }
    fn modem_lines(&mut self) -> ModemLines {
        ModemLines::default()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ModemLines {
    pub dsr: Option<bool>,
    pub cts: Option<bool>,
    pub dcd: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoginTrace {
    pub bytes_received: usize,
    pub xon_seen: bool,
    pub dtr_cycled: bool,
    pub wake_sent: bool,
    pub lines: ModemLines,
}

/// Minimum post-reply turnaround margin (Tester #2: 0 ms with high baud shrinks cutoff).
pub const MIN_REPLY_GUARD_MS: u64 = 20;
/// Upper bound for configured line rate (daemon rejects above this at startup).
pub const MAX_LINK_BAUD: u32 = 9600;

/// Timing parameters (defaults until hardware test H5 measures them; design §9b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// Reply timeout for reads/probes.
    pub reply_timeout_ms: u64,
    /// Ack wait per write (every real ack so far: <= 589 ms).
    pub ack_timeout_ms: u64,
    /// Longest busy run tolerated before giving up (design §9b default until H5).
    pub busy_limit_ms: u64,
    /// Quiet window: ends drain-until-quiet, and is the window after every reply in which
    /// any further non-busy frame makes that reply suspect (possibly stale).
    pub quiet_ms: u64,
    /// Quiet interval required before every send (shorter than `quiet_ms`, which is used
    /// after any failed or unacked request).
    pub presend_quiet_ms: u64,
    /// Overall limit for the text login.
    pub login_timeout_ms: u64,
    /// Line rate for the post-send cutoff (10 bits per byte).
    pub link_baud: u32,
    /// Assumed minimum PBX turnaround, added to the post-send cutoff. This is a lower
    /// bound, not slack: no genuine reply can start before the request has been sent and
    /// the PBX has turned round, so a larger value drops more early (stale) frames, and a
    /// value above the real turnaround would drop a genuine ack (the write then counts as
    /// unacked and is verified by read-back, never resent). 20 ms is a placeholder until
    /// hardware test H5 measures it; the prototype had no margin here.
    pub reply_guard_ms: u64,
    /// Upper bound for a single serial [`Transport::send`] (daemon maps to line I/O).
    pub send_bound_ms: u64,
    pub wake_interval_ms: u64,
}

/// Shortest reply frame (an ack), for the post-send cutoff.
const MIN_REPLY_LEN: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimingConfigError {
    LinkBaudOutOfRange,
    ReplyGuardTooLow,
}

impl std::fmt::Display for TimingConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LinkBaudOutOfRange => {
                write!(f, "link_baud must be between 1 and {MAX_LINK_BAUD}")
            }
            Self::ReplyGuardTooLow => {
                write!(f, "reply_guard_ms must be at least {MIN_REPLY_GUARD_MS} ms")
            }
        }
    }
}

impl std::error::Error for TimingConfigError {}

impl Timing {
    /// Milliseconds to transmit `n` bytes at `link_baud`, 10 bits per byte, rounded up.
    pub fn tx_ms(&self, n: usize) -> u64 {
        let bits = n as u64 * 10 * 1000;
        bits.div_ceil(u64::from(self.link_baud.max(1)))
    }

    /// Earliest time after a send starts at which a genuine reply can have arrived: the
    /// request must finish transmitting, the PBX turn round, and the shortest reply
    /// arrive. Anything before that is stale and dropped.
    pub fn reply_cutoff_ms(&self, request_len: usize) -> u64 {
        self.tx_ms(request_len) + self.tx_ms(MIN_REPLY_LEN) + self.reply_guard_ms
    }

    /// Reject daemon config that would shrink the reply cutoff below a sane floor.
    pub fn validate(self) -> Result<Self, TimingConfigError> {
        if self.link_baud == 0 || self.link_baud > MAX_LINK_BAUD {
            return Err(TimingConfigError::LinkBaudOutOfRange);
        }
        if self.reply_guard_ms < MIN_REPLY_GUARD_MS {
            return Err(TimingConfigError::ReplyGuardTooLow);
        }
        Ok(self)
    }
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            reply_timeout_ms: 5_000,
            ack_timeout_ms: 2_000,
            busy_limit_ms: 12_000,
            quiet_ms: 500,
            presend_quiet_ms: 100,
            login_timeout_ms: 30_000,
            link_baud: 9600,
            reply_guard_ms: MIN_REPLY_GUARD_MS,
            send_bound_ms: 5_000,
            wake_interval_ms: 1_500,
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
    /// End-binary acked and BYE sent, but OK not yet seen. `end_binary` re-sends BYE.
    ByePending,
    /// Logout confirmed (BYE answered OK).
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
    /// Set when a write went unacked (or a resync failed); cleared by a completed
    /// drain-until-quiet. `end_binary` drains first while it is set, and is held if the
    /// drain cannot finish, so a late ack is never matched to the end-binary request.
    needs_drain: bool,
    signon: SignOn,
    login_trace: Option<LoginTrace>,
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
            needs_drain: false,
            signon: SignOn::default(),
            login_trace: None,
        }
    }

    /// Use deployment sign-on text instead of the placeholders.
    pub fn with_signon(mut self, signon: SignOn) -> Self {
        self.signon = signon;
        self
    }

    pub fn login_trace(&self) -> Option<&LoginTrace> {
        self.login_trace.as_ref()
    }

    fn require_session(&self) -> Result<(), Error> {
        if matches!(self.state, SessionState::Disconnected) {
            return Err(Error::SessionLost);
        }
        Ok(())
    }

    /// Link lost: remember any pending verify/rollback so it resumes after a fresh login
    /// (and is drained first), and refuse everything else until then.
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
        if self.resume.is_some() {
            self.needs_drain = true;
        }
        self.state = SessionState::Disconnected;
        self.rx.clear();
    }

    pub fn state(&self) -> &SessionState {
        &self.state
    }

    pub fn transport(&self) -> &T {
        &self.t
    }

    /// Mutable transport access for integration tests (fault injection).
    #[cfg(feature = "test-transport-access")]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.t
    }

    /// Bytes consumed by drains (late acks, busy frames), for the log.
    pub fn drained(&self) -> &[Drained] {
        &self.drained
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, Error> {
        match self.t.recv(timeout_ms) {
            // The trait forbids an empty Ok; treat one as a dead link so no loop spins.
            Ok(b) if b.is_empty() => Err(Error::LinkDown("transport returned no bytes".into())),
            Ok(b) => Ok(b),
            Err(TransportError::Timeout) => Err(Error::Timeout),
            Err(TransportError::LinkDown(e)) => Err(Error::LinkDown(e.detail)),
            Err(TransportError::NothingWritten(s)) => Err(Error::LinkDown(s)),
        }
    }

    /// Text-mode send (login, BYE): any link failure is just a lost link.
    fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        self.t.send(data).map_err(|e| match e {
            TransportError::Timeout => Error::Timeout,
            TransportError::LinkDown(e) => Error::LinkDown(e.detail),
            TransportError::NothingWritten(s) => Error::LinkDown(s),
        })
    }

    /// Binary frame send: [`TransportError::NothingWritten`] becomes [`Error::PreSend`]
    /// (nothing reached the line); [`TransportError::LinkDown`] becomes [`Error::LinkDown`].
    fn send_frame(&mut self, data: &[u8]) -> Result<(), Error> {
        self.t.send(data).map_err(|e| match e {
            TransportError::Timeout => Error::Timeout,
            TransportError::LinkDown(e) => Error::LinkDown(e.detail),
            TransportError::NothingWritten(s) => Error::PreSend(Box::new(Error::LinkDown(s))),
        })
    }

    /// Text login to binary mode, within `login_timeout_ms` overall and at most
    /// [`crate::session::MAX_LINES`] lines.
    pub fn login(&mut self, password: &str) -> Result<(), Error> {
        let mut trace = LoginTrace::default();
        let result = self.login_traced(password, &mut trace);
        if result.is_err() {
            trace.lines = self.t.modem_lines();
        }
        self.login_trace = Some(trace);
        result
    }

    fn login_traced(&mut self, password: &str, trace: &mut LoginTrace) -> Result<(), Error> {
        let mut sm = Login::with_signon(password, self.signon.clone()).map_err(Error::Login)?;
        let start = self.t.now_ms();
        let limit = self.timing.login_timeout_ms;
        let cycled = self.t.cycle_dtr().map_err(|e| match e {
            TransportError::Timeout => Error::Timeout,
            TransportError::LinkDown(e) => Error::LinkDown(e.detail),
            TransportError::NothingWritten(s) => Error::LinkDown(s),
        })?;
        trace.dtr_cycled = cycled;
        let mut wake_due = cycled;
        while !sm.state().is_terminal() {
            let elapsed = self.t.now_ms().saturating_sub(start);
            if elapsed >= limit {
                return Err(Error::Login(LoginFailure::TimedOut { ms: limit }));
            }
            let can_wake = sm.wake_pending() && wake_due;
            let wait = if can_wake {
                self.timing.wake_interval_ms
            } else {
                self.timing.reply_timeout_ms
            };
            let data = match self.recv(wait.min(limit - elapsed)) {
                Ok(d) => d,
                Err(Error::Timeout) if can_wake => {
                    let out = sm.wake();
                    self.send(&out)?;
                    trace.wake_sent = true;
                    wake_due = false;
                    continue;
                }
                Err(e) => return Err(e),
            };
            trace.bytes_received += data.len();
            let out = sm.feed(&data);
            trace.xon_seen |= data.contains(&crate::session::XON);
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

    /// Send once and return the reply for `cmd`.
    ///
    /// 1. Input already waiting is discarded (and logged) before the send, so a stale frame
    ///    of the same command is never taken as this reply.
    /// 2. Busy frames are waited out (never answered with a resend) for at most the bound.
    /// 3. A reply that does not decode, or whose command byte differs, is an error.
    /// 4. After the reply, any further non-busy frame within `quiet_ms` is
    ///    [`Error::ExtraFrame`]: one of the two was stale, so neither is trusted.
    ///
    /// On any error the stream is resynced by drain-until-quiet, so the real reply to a
    /// failed request is never handed to the next one.
    fn request(&mut self, raw: &[u8], cmd: Cmd, timeout_ms: u64) -> Result<Reply, Error> {
        self.require_session()?;
        if matches!(
            self.state,
            SessionState::Text | SessionState::Closed | SessionState::ByePending
        ) {
            return Err(Error::BadState {
                op: Op::Request,
                state: self.state.clone(),
            });
        }
        if let Err(e) = self.flush_pending() {
            if matches!(&e, Error::PreSend(inner) if matches!(**inner, Error::LinkDown(_))) {
                // A verify/rollback is already pending: let that path record disconnect.
                if !self.needs_drain {
                    self.note_link_down(None);
                }
            }
            return Err(e);
        }
        let sent_at = self.t.now_ms();
        match self.send_frame(raw) {
            Ok(()) => {}
            // Every send failure propagates. Writes: `write()` maps LinkDown vs PreSend and
            // saves resume. Reads/other: record disconnect unless a pending drain owns it.
            Err(e) => {
                if cmd != Cmd::Write {
                    match &e {
                        Error::LinkDown(_) if !self.needs_drain => self.note_link_down(None),
                        Error::PreSend(inner)
                            if matches!(inner.as_ref(), Error::LinkDown(_))
                                && !self.needs_drain =>
                        {
                            self.note_link_down(None);
                        }
                        _ => {}
                    }
                }
                return Err(e);
            }
        }
        let r = match self
            .drop_before_cutoff(sent_at + self.timing.reply_cutoff_ms(raw.len()))
            .and_then(|()| self.await_reply(cmd, timeout_ms))
        {
            Ok(reply) => self.check_trailing().map(|()| reply),
            Err(e) => Err(e),
        };
        if matches!(r, Err(Error::LinkDown(_))) {
            self.note_link_down(None);
            return r;
        }
        if r.is_err() {
            self.rx.clear();
            match self.drain_until_quiet() {
                Ok(()) => {}
                // The drain already recorded the disconnect; report the lost link.
                Err(e @ Error::LinkDown(_)) => return Err(e),
                Err(_) => self.needs_drain = true,
            }
        }
        r
    }

    /// Before a send: discard (and log) input until the line has been quiet for
    /// `presend_quiet_ms`. Failure (never quiet within the busy bound, or link down) is
    /// [`Error::PreSend`]: nothing was sent.
    fn flush_pending(&mut self) -> Result<(), Error> {
        let start = self.t.now_ms();
        if !self.rx.is_empty() {
            let bytes = std::mem::take(&mut self.rx);
            self.drained.push(Drained {
                at_ms: start,
                bytes,
            });
        }
        loop {
            match self.recv(self.timing.presend_quiet_ms) {
                Ok(bytes) => {
                    let at_ms = self.t.now_ms();
                    self.drained.push(Drained { at_ms, bytes });
                    if at_ms.saturating_sub(start) > self.timing.busy_limit_ms {
                        return Err(Error::PreSend(Box::new(Error::LineNotQuiet)));
                    }
                }
                Err(Error::Timeout) => return Ok(()),
                Err(e) => return Err(Error::PreSend(Box::new(e))),
            }
        }
    }

    /// After a reply: anything but busy frames within the quiet window is an extra frame.
    fn check_trailing(&mut self) -> Result<(), Error> {
        let mut extra = std::mem::take(&mut self.rx);
        let deadline = self.t.now_ms().saturating_add(self.timing.quiet_ms);
        loop {
            let now = self.t.now_ms();
            if now >= deadline {
                break;
            }
            match self.recv(deadline - now) {
                Ok(b) => extra.extend(b),
                Err(Error::Timeout) => break,
                Err(e) => return Err(e),
            }
        }
        while extra.starts_with(&frame::BUSY_FRAME) {
            extra.drain(..frame::BUSY_FRAME.len());
        }
        if extra.is_empty() {
            Ok(())
        } else {
            let at_ms = self.t.now_ms();
            self.drained.push(Drained {
                at_ms,
                bytes: extra,
            });
            Err(Error::ExtraFrame)
        }
    }

    /// Post-send cutoff (ported from prototype 3741820): drop (and log) every byte that
    /// arrives before `cutoff`, since no genuine reply can be complete that soon. A write
    /// that only saw such frames then times out and is unacked.
    fn drop_before_cutoff(&mut self, cutoff: u64) -> Result<(), Error> {
        loop {
            let now = self.t.now_ms();
            if now >= cutoff {
                return Ok(());
            }
            match self.recv(cutoff - now - 1) {
                Ok(bytes) => {
                    let at_ms = self.t.now_ms();
                    self.drained.push(Drained { at_ms, bytes });
                }
                Err(Error::Timeout) => {
                    self.rx.clear();
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        }
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
        match self.state {
            SessionState::Binary => {}
            SessionState::AwaitingVerify(_) | SessionState::NeedsRollback(_) => {
                return Err(Error::VerifyPending)
            }
            SessionState::Locked => return Err(Error::Locked),
            SessionState::Disconnected => return Err(Error::SessionLost),
            _ => {
                return Err(Error::BadState {
                    op: Op::Write,
                    state: self.state.clone(),
                })
            }
        }
        let raw = self.enc.write(table, record, word, payload)?;
        let reason = match self.request(&raw, Cmd::Write, self.timing.ack_timeout_ms) {
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
            Err(Error::ExtraFrame) => UnackedReason::ExtraFrame,
            // The frame may have reached the PBX before the link dropped: the session is
            // Disconnected and resumes in AwaitingVerify (drain first) after a fresh login.
            Err(Error::LinkDown(s)) => {
                let u = UnackedWrite {
                    table,
                    record,
                    word,
                    payload: payload.to_vec(),
                    reason: UnackedReason::LinkDown(s.clone()),
                };
                self.state = SessionState::Binary;
                self.note_link_down(Some(u));
                return Err(Error::LinkDown(s));
            }
            Err(Error::PreSend(inner)) if matches!(inner.as_ref(), Error::LinkDown(_)) => {
                if !self.needs_drain {
                    self.note_link_down(None);
                }
                return Err(Error::PreSend(inner));
            }
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
        self.needs_drain = true;
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
                Err(Error::Timeout) => {
                    self.needs_drain = false;
                    return Ok(());
                }
                Err(e @ Error::LinkDown(_)) => {
                    // Save any pending verify/rollback as resume before Disconnected.
                    // Already Disconnected: keep the resume saved then.
                    if !matches!(
                        self.state,
                        SessionState::Text | SessionState::Closed | SessionState::Disconnected
                    ) {
                        self.note_link_down(None);
                    }
                    return Err(e);
                }
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
        // Verifying the pending block must cover the whole pending write: same start and
        // the same new bytes, so a prefix can never clear AwaitingVerify.
        if let SessionState::AwaitingVerify(u) = &self.state {
            if (u.table, u.record, u.word) == (table, record, word) && u.payload != new {
                return Err(Error::NotPendingBlock);
            }
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

    /// Roll a block back to `base` and verify it. The rollback write follows the same
    /// rule as any write: if it is not acked the session is `AwaitingVerify`, and the
    /// verify drains until quiet before re-reading, so a late rollback ack is consumed
    /// there. Success returns to `Binary`; otherwise the session is `Locked`, and
    /// `end_binary` still drains first (held if it cannot).
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
            return Err(Error::BadState {
                op: Op::Rollback,
                state: self.state.clone(),
            });
        }
        // Only the block that needs recovery, with a backup of the same length.
        if let SessionState::NeedsRollback(u) | SessionState::AwaitingVerify(u) = &self.state {
            if (u.table, u.record, u.word, u.payload.len()) != (table, record, word, base.len()) {
                return Err(Error::NotPendingBlock);
            }
        }
        let prior = self.state.clone();
        self.state = SessionState::Binary;
        match self.write(table, record, word, base) {
            Ok(()) | Err(Error::Unacked(_)) => {}
            // Disconnected; resumes in AwaitingVerify for this rollback after login.
            Err(e @ Error::LinkDown(_)) => {
                // If the write already recorded disconnect + resume, keep that snapshot.
                if !matches!(self.state, SessionState::Disconnected) {
                    self.state = prior;
                    self.note_link_down(None);
                }
                return Err(e);
            }
            // Nothing was sent: the prior state stands. If the pre-send drain lost the
            // link, the prior state is what resumes after login.
            Err(e @ Error::PreSend(_)) => {
                if matches!(&e, Error::PreSend(inner) if matches!(inner.as_ref(), Error::LinkDown(_)))
                {
                    self.state = prior;
                    if !matches!(self.state, SessionState::Disconnected) {
                        self.note_link_down(None);
                    }
                    return Err(e);
                }
                let lost = matches!(self.state, SessionState::Disconnected);
                self.state = prior;
                if lost {
                    self.note_link_down(None);
                }
                return Err(e);
            }
            Err(_) => {
                self.state = SessionState::Locked;
                self.needs_drain = true;
                return Err(Error::Locked);
            }
        }
        match self.verify_block(table, record, word, base, base) {
            Ok(VerifyOutcome::Applied) => {
                self.state = SessionState::Binary;
                Ok(())
            }
            // Link lost mid-verify: keep Disconnected and the saved resume.
            Err(e) if matches!(self.state, SessionState::Disconnected) => Err(e),
            _ => {
                self.state = SessionState::Locked;
                self.needs_drain = true;
                Err(Error::Locked)
            }
        }
    }

    /// Mark the session LOCKED (the daemon's choice after a failed verify).
    pub fn lock(&mut self) {
        self.state = SessionState::Locked;
    }

    /// Leave binary mode. Held (refused, nothing sent) while a write awaits verify or
    /// rollback, or while a pending drain cannot finish (line busy or link down).
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
            SessionState::ByePending => return self.bye(),
        }
        if self.needs_drain {
            match self.drain_until_quiet() {
                Ok(()) => {}
                Err(e @ Error::LinkDown(_)) => return Err(e),
                Err(_) => return Err(Error::EndBinaryHeld),
            }
        }
        let raw = self.enc.end_binary();
        let r = self.request(&raw, Cmd::EndBinary, self.timing.reply_timeout_ms)?;
        match r.kind {
            ReplyKind::Ack => {}
            k => return Err(Error::UnexpectedReply(format!("end-binary: {k:?}"))),
        }
        self.state = SessionState::ByePending;
        self.bye()
    }

    /// Text logout (recorded exchange step 28): BYE, then wait for OK. The PBX may follow
    /// the OK with its sign-on prompt, which also confirms the logout. Any failure leaves
    /// `ByePending`, so the next `end_binary` sends BYE again.
    fn bye(&mut self) -> Result<(), Error> {
        self.rx.clear();
        self.send(b"BYE\r\n")?;
        let start = self.t.now_ms();
        let mut text = Vec::new();
        loop {
            let s = String::from_utf8_lossy(&text).into_owned();
            let lines: Vec<&str> = s.split('\n').map(str::trim).collect();
            if lines
                .iter()
                .any(|l| *l == "OK" || *l == self.signon.password_prompt)
            {
                self.state = SessionState::Closed;
                return Ok(());
            }
            if let Some(l) = lines.iter().find(|l| l.starts_with("NG")) {
                return Err(Error::ByeNotConfirmed((*l).to_string()));
            }
            if text.len() > crate::session::MAX_LINE * crate::session::MAX_LINES {
                return Err(Error::ByeNotConfirmed("too much text".into()));
            }
            let elapsed = self.t.now_ms().saturating_sub(start);
            if elapsed >= self.timing.reply_timeout_ms {
                return Err(Error::ByeNotConfirmed("no reply".into()));
            }
            match self.recv(self.timing.reply_timeout_ms - elapsed) {
                Ok(b) => text.extend(b),
                Err(Error::Timeout) => return Err(Error::ByeNotConfirmed("no reply".into())),
                Err(e) => return Err(e),
            }
        }
    }
}

impl From<LoginFailure> for Error {
    fn from(f: LoginFailure) -> Self {
        Self::Login(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Scripted transport: `recv` pops queued chunks, then times out.
    struct Script {
        now: u64,
        inbound: VecDeque<Vec<u8>>,
    }

    impl Transport for Script {
        fn send(&mut self, _: &[u8]) -> Result<(), TransportError> {
            Ok(())
        }
        fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
            self.inbound.pop_front().ok_or_else(|| {
                self.now += timeout_ms;
                TransportError::Timeout
            })
        }
        fn now_ms(&mut self) -> u64 {
            self.now
        }
    }

    /// Architect 5629005479: bytes already buffered when a drain starts are logged as
    /// drained and never left in the buffer to be parsed as the next reply.
    #[test]
    fn drain_until_quiet_flushes_buffered_rx() {
        let mut c = Client::new(Script {
            now: 0,
            inbound: VecDeque::new(),
        });
        c.state = SessionState::Binary;
        let stale = vec![0x03, 0x00, 0x00, 0x03];
        c.rx = stale.clone();
        assert_eq!(c.drain_until_quiet(), Ok(()));
        assert!(c.rx.is_empty(), "buffered bytes survived the drain");
        assert_eq!(c.drained().first().map(|d| d.bytes.clone()), Some(stale));
    }

    /// Replies only after a send; the send takes long enough that the post-send guard
    /// window has already passed, so the guard never clears `rx` itself.
    struct ReplyOnSend {
        now: u64,
        reply: Vec<u8>,
        inbound: VecDeque<Vec<u8>>,
    }

    impl Transport for ReplyOnSend {
        fn send(&mut self, _: &[u8]) -> Result<(), TransportError> {
            self.now += 1_000;
            self.inbound.push_back(self.reply.clone());
            Ok(())
        }
        fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
            self.inbound.pop_front().ok_or_else(|| {
                self.now += timeout_ms;
                TransportError::Timeout
            })
        }
        fn now_ms(&mut self) -> u64 {
            self.now
        }
    }

    /// Architect 5632467751: a stale frame already buffered in `rx` before a send is
    /// discarded by the pre-send rx flush in `flush_pending`, so the real ack is the
    /// reply. Without that flush the stale read reply is parsed first and the request
    /// fails (mismatched command), so this test fails.
    #[test]
    fn presend_flush_discards_buffered_rx_before_reply() {
        let ack = vec![0x03, 0x00, 0x00, 0x03];
        let stale = vec![0x03, 0x01, 0x00, 0x04];
        let mut c = Client::new(ReplyOnSend {
            now: 0,
            reply: ack.clone(),
            inbound: VecDeque::new(),
        });
        c.state = SessionState::Binary;
        c.rx = stale.clone();
        let r = c.request(&[0x02, 0x08, 0x0a], Cmd::Write, 500);
        let want = frame::classify(&ack).ok();
        assert!(want.is_some());
        assert_eq!(r.ok(), want);
        assert_eq!(c.drained().first().map(|d| d.bytes.clone()), Some(stale));
    }
}
