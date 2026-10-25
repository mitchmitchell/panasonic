//! Sans-I/O KX-TD1232 simulator built from the behavior spec, plus a virtual-time
//! [`SimTransport`]. All data is synthetic; nothing here comes from a real unit.
//!
//! Fault injection (design §6 / milestone A2) is behind the **`faults`** cargo feature
//! (dev/tests only; production binaries must not enable it). Virtual time models 9600-baud
//! line delay for replies (see [`SimTransport::send`]).

use kxtd1232::fields::{encode_cid_name, encode_cid_number, encode_ext_name};
use kxtd1232::frame::{checksum, Cmd, BUSY_FRAME};
use kxtd1232::tables;
use kxtd1232::{LinkDownError, SignOn, Transport, TransportError};
use std::collections::{HashMap, VecDeque};

pub const PLACEHOLDER_PASSWORD: &str = "0000";
pub const PLACEHOLDER_ROM_ID: &str = "-----PXXXXXXXXXX";
/// Sign-on text the simulator plays: the placeholders from [`SignOn::default`].
fn text_line(s: &str) -> Vec<u8> {
    format!("{s}\r\n").into_bytes()
}

/// Banner then password prompt, as sent after CR LF and after BYE.
pub fn banner() -> Vec<u8> {
    let s = SignOn::default();
    let mut v = text_line(&s.banner);
    v.extend(text_line(&s.password_prompt));
    v
}

/// Frame `[LEN][CMD][body][SUM]` as the PBX would send it. The simulator plays the PBX, so
/// it frames its own replies; the protocol core exposes no raw-byte encoder. Tests use it
/// to inject stale or garbled frames.
pub fn reply_frame(cmd: u8, body: &[u8]) -> Vec<u8> {
    let len = 2 + body.len();
    assert!(len <= 0xFF, "reply body too long");
    let mut out = Vec::with_capacity(len + 1);
    out.push(len as u8);
    out.push(cmd);
    out.extend_from_slice(body);
    out.push(checksum(&out));
    out
}

/// Tunable simulator timing and counts. Defaults are round **placeholders** for tests and
/// fault hooks; they are **not** measured on a real PBX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimConfig {
    /// Placeholder count for the malformed-frame busy train; not a measured value.
    pub busy_lockup_frames: u32,
    /// Placeholder spacing between those busy frames (milliseconds); not a measured value.
    pub busy_lockup_interval_ms: u64,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            busy_lockup_frames: 50,
            busy_lockup_interval_ms: 100,
        }
    }
}

/// Injected faults, consumed in order. Requires the `faults` feature.
#[cfg(feature = "faults")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// Next request gets a bad-checksum NAK (`01 02`).
    Nak,
    /// Next write is acked but not stored.
    SilentWrite,
    /// Next request's reply is preceded by `frames` busy frames at [`SimConfig::busy_lockup_interval_ms`].
    Busy { frames: u32 },
    /// Next write is stored, no ack is sent.
    NoAckApplied,
    /// Next write is stored with no ack; `busy_frames` busy frames follow on the line before verify.
    NoAckThenBusy { busy_frames: u32 },
    /// Next write is dropped, no ack is sent.
    NoAckDropped,
    /// Next write is stored and its ack arrives `delay_ms` later.
    LateAck { delay_ms: u64 },
    /// Next write is stored and its ack has a bad checksum.
    GarbledAck,
    /// Next write is stored and answered with an ack for another command (0x01).
    StaleReply,
    /// Next request's real reply is preceded by a same-command stale one (a read reply
    /// full of 0xEE, or a write ack) arriving 20 ms earlier.
    DuplicateReply,
    /// Next request's reply is followed 10 ms later by one busy frame.
    BusyAfterReply,
    /// Next write is stored; the ack is cut off after `partial_len` bytes, then the link drops.
    LinkDropMidChunk { partial_len: usize },
    /// Drop the link after `after_bytes` of the next outgoing write frame (not stored).
    LinkDropMidSend { after_bytes: usize },
    /// Next read gets end-of-table refusal (`01 03`) even in range.
    ReadRefused,
    /// Next failed password attempt gets the default re-prompt (gate G5 guess).
    WrongPassword,
    /// Next password attempt gets an "another terminal" style line (parameterized text).
    AnotherTerminal(String),
    /// Next password attempt gets a custom login line (tests / unmeasured replies).
    LoginReply(String),
}

#[cfg(feature = "faults")]
impl Fault {
    fn write_only(&self) -> bool {
        !matches!(
            self,
            Self::Nak
                | Self::Busy { .. }
                | Self::DuplicateReply
                | Self::BusyAfterReply
                | Self::ReadRefused
                | Self::WrongPassword
                | Self::AnotherTerminal(_)
                | Self::LoginReply(_)
        )
    }

    fn mid_send_drop(&self) -> Option<usize> {
        match self {
            Self::LinkDropMidSend { after_bytes } => Some(*after_bytes),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Idle,
    AwaitCrlf,
    AwaitPassword,
    AwaitEcs,
    AwaitPrg,
    Binary,
    AwaitBye,
}

/// A fake database sized per the RE table spec, with a few synthetic entries.
pub fn synthetic_db() -> HashMap<u8, Vec<u8>> {
    let mut db = HashMap::new();
    for s in tables::TABLES.iter() {
        db.insert(s.id, vec![0u8; s.wire_bytes()]);
    }
    let n = |t: u8| tables::spec(t).map_or(0, |s| s.records as usize);
    let mut nums = Vec::new();
    let mut names = Vec::new();
    for i in 0..n(tables::CID_NUMBERS) {
        nums.extend(encode_cid_number(if i == 0 { "123" } else { "" }).unwrap_or_default());
    }
    for i in 0..n(tables::CID_NAMES) {
        names.extend(encode_cid_name(if i == 0 { "TEST ONE" } else { "" }).unwrap_or_default());
    }
    let mut exts = Vec::new();
    for i in 0..n(tables::EXT_NAMES) {
        exts.extend(encode_ext_name(&format!("EXT {}", i + 100)).unwrap_or_default());
    }
    db.insert(tables::CID_NUMBERS, nums);
    db.insert(tables::CID_NAMES, names);
    db.insert(tables::EXT_NAMES, exts);
    db
}

/// One stored write: `(table, record, word, payload)`.
pub type WriteRecord = (u8, u16, u16, Vec<u8>);

pub struct SimPbx {
    pub config: SimConfig,
    pub db: HashMap<u8, Vec<u8>>,
    password: Vec<u8>,
    rom_id: [u8; 16],
    mode: Mode,
    buf: Vec<u8>,
    #[cfg(feature = "faults")]
    faults: VecDeque<Fault>,
    /// Writes received with valid checksums (stored or not).
    pub writes: Vec<WriteRecord>,
    /// Command bytes of every binary frame received, in order.
    pub commands: Vec<u8>,
    /// Response latency for every reply.
    pub latency_ms: u64,
    /// When set, BYE gets no answer (logout not confirmed).
    pub silent_bye: bool,
    /// More busy frames to schedule after the first one in a malformed-frame lockup.
    pub(crate) lockup_busy_left: u32,
    /// While true (until [`Self::lockup_end_ms`]), all host input is discarded without parsing.
    pub(crate) lockup_discard: bool,
    pub(crate) lockup_end_ms: u64,
    #[cfg(feature = "faults")]
    pub(crate) link_drop_partial: Option<usize>,
    #[cfg(feature = "faults")]
    pub(crate) post_write_busy: Option<u32>,
}

impl Default for SimPbx {
    fn default() -> Self {
        Self::new(synthetic_db(), PLACEHOLDER_PASSWORD)
    }
}

/// Bytes the simulator emits, each after a delay relative to the triggering input.
pub type Emits = Vec<(u64, Vec<u8>)>;

impl SimPbx {
    pub fn new(db: HashMap<u8, Vec<u8>>, password: &str) -> Self {
        Self::with_config(db, password, SimConfig::default())
    }

    pub fn with_config(db: HashMap<u8, Vec<u8>>, password: &str, config: SimConfig) -> Self {
        let mut rom_id = [b' '; 16];
        for (d, s) in rom_id.iter_mut().zip(PLACEHOLDER_ROM_ID.bytes()) {
            *d = s;
        }
        Self {
            config,
            db,
            password: password.as_bytes().to_vec(),
            rom_id,
            mode: Mode::Idle,
            buf: Vec::new(),
            #[cfg(feature = "faults")]
            faults: VecDeque::new(),
            writes: Vec::new(),
            commands: Vec::new(),
            latency_ms: 30,
            silent_bye: false,
            lockup_busy_left: 0,
            lockup_discard: false,
            lockup_end_ms: 0,
            #[cfg(feature = "faults")]
            link_drop_partial: None,
            #[cfg(feature = "faults")]
            post_write_busy: None,
        }
    }

    #[cfg(feature = "faults")]
    pub fn inject(&mut self, fault: Fault) {
        self.faults.push_back(fault);
    }

    #[cfg(feature = "faults")]
    pub fn pending_faults(&self) -> usize {
        self.faults.len()
    }

    #[cfg(feature = "faults")]
    pub(crate) fn take_mid_send_fault(&mut self, data: &[u8]) -> Option<usize> {
        if data.get(1) != Some(&Cmd::Write.byte()) {
            return None;
        }
        match self.faults.front()? {
            f if f.mid_send_drop().is_some() => {
                let n = f.mid_send_drop()?;
                self.faults.pop_front();
                Some(n)
            }
            _ => None,
        }
    }

    pub fn dtr_up(&mut self) -> Vec<u8> {
        self.mode = Mode::AwaitCrlf;
        self.buf.clear();
        vec![0x13, 0x11]
    }

    pub fn dtr_down(&mut self) {
        self.mode = Mode::Idle;
        self.buf.clear();
    }

    pub(crate) fn advance_lockup(&mut self, now_ms: u64) {
        if self.lockup_discard && now_ms >= self.lockup_end_ms {
            self.lockup_discard = false;
            self.buf.clear();
        }
    }

    pub fn feed(&mut self, data: &[u8], now_ms: u64) -> Emits {
        self.advance_lockup(now_ms);
        if self.lockup_discard {
            return Emits::new();
        }
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            if self.lockup_discard {
                self.buf.clear();
                return out;
            }
            if self.mode == Mode::Binary {
                let Some(&len) = self.buf.first() else {
                    return out;
                };
                if len < 2 {
                    self.buf.drain(..1);
                    out.extend(self.malformed_frame());
                    continue;
                }
                let n = len as usize + 1;
                if self.buf.len() < n {
                    return out;
                }
                let raw: Vec<u8> = self.buf.drain(..n).collect();
                out.extend(self.frame(&raw));
            } else {
                let Some(cr) = self.buf.iter().position(|&b| b == b'\r') else {
                    return out;
                };
                let mut line: Vec<u8> = self.buf.drain(..=cr).collect();
                line.pop();
                if self.buf.first() == Some(&b'\n') {
                    self.buf.remove(0);
                }
                let reply = self.text(line.trim_ascii());
                if !reply.is_empty() {
                    out.push((self.latency_ms, reply));
                }
            }
        }
    }

    #[cfg(feature = "faults")]
    fn take_login_fault(&mut self, wrong_attempt: bool) -> Option<Fault> {
        match self.faults.front() {
            Some(Fault::WrongPassword) if wrong_attempt => self.faults.pop_front(),
            Some(Fault::AnotherTerminal(_) | Fault::LoginReply(_)) => self.faults.pop_front(),
            _ => None,
        }
    }

    fn text(&mut self, line: &[u8]) -> Vec<u8> {
        match self.mode {
            Mode::AwaitCrlf => {
                self.mode = Mode::AwaitPassword;
                banner()
            }
            Mode::AwaitPassword if line == self.password.as_slice() => {
                #[cfg(feature = "faults")]
                if let Some(f) = self.take_login_fault(false) {
                    return match f {
                        Fault::AnotherTerminal(s) | Fault::LoginReply(s) => {
                            format!("{s}\r\n").into_bytes()
                        }
                        _ => text_line(&SignOn::default().mode_start),
                    };
                }
                self.mode = Mode::AwaitEcs;
                text_line(&SignOn::default().mode_start)
            }
            // Wrong-password reply is a guess, like the RE simulator (gate G5).
            Mode::AwaitPassword => {
                #[cfg(feature = "faults")]
                if let Some(f) = self.take_login_fault(true) {
                    return match f {
                        Fault::AnotherTerminal(s) | Fault::LoginReply(s) => {
                            format!("{s}\r\n").into_bytes()
                        }
                        Fault::WrongPassword => text_line(&SignOn::default().password_prompt),
                        _ => text_line(&SignOn::default().password_prompt),
                    };
                }
                text_line(&SignOn::default().password_prompt)
            }
            Mode::AwaitEcs if line == b"ECS OF" => {
                self.mode = Mode::AwaitPrg;
                b"ECS OF\r\nOK\r\n".to_vec()
            }
            Mode::AwaitPrg if line == b"PRG" => {
                self.mode = Mode::Binary;
                b"OK\r\n".to_vec()
            }
            Mode::AwaitBye if line == b"BYE" && self.silent_bye => Vec::new(),
            Mode::AwaitBye if line == b"BYE" => {
                self.mode = Mode::AwaitPassword;
                let mut v = b"OK\r\n".to_vec();
                v.extend(banner());
                v
            }
            _ => b"NG\r\n".to_vec(),
        }
    }

    fn reply(cmd: u8, body: &[u8]) -> Vec<u8> {
        reply_frame(cmd, body)
    }

    fn clear_busy_lockup(&mut self) {
        self.lockup_busy_left = 0;
        self.lockup_discard = false;
        self.lockup_end_ms = 0;
    }

    fn start_busy_lockup(&mut self) {
        self.buf.clear();
        self.lockup_discard = true;
        self.lockup_busy_left = self.config.busy_lockup_frames.saturating_sub(1);
    }

    /// Hypothesis (design §6 / RE busy-lockup fixture): malformed LEN or trailing junk after
    /// a bad frame triggers a busy train; counts in [`SimConfig`] are placeholders, not measured.
    fn malformed_frame(&mut self) -> Emits {
        self.start_busy_lockup();
        vec![(self.latency_ms, BUSY_FRAME.to_vec())]
    }

    fn frame(&mut self, raw: &[u8]) -> Emits {
        let lat = self.latency_ms;
        let cmd = raw.get(1).copied().unwrap_or(0xFF);
        let len_byte = raw.first().copied().unwrap_or(0);
        if raw.len() < 3 || len_byte < 2 || raw.len() != len_byte as usize + 1 {
            return self.malformed_frame();
        }
        if checksum(&raw[..raw.len() - 1]) != raw[raw.len() - 1] {
            let mut out = vec![(lat, Self::reply(cmd, &[0x01, 0x02]))];
            if self.buf.is_empty() {
                return out;
            }
            self.start_busy_lockup();
            out.push((self.latency_ms, BUSY_FRAME.to_vec()));
            return out;
        }
        self.clear_busy_lockup();
        self.commands.push(cmd);
        let body = &raw[2..raw.len() - 1];
        let mut out: Emits = Vec::new();
        #[cfg(feature = "faults")]
        {
            let is_write = cmd == Cmd::Write.byte();
            let fault = match self.faults.front() {
                Some(f) if is_write || !f.write_only() => self.faults.pop_front(),
                _ => None,
            };
            let mut t = lat;
            match fault {
                Some(Fault::Nak) => return vec![(lat, Self::reply(cmd, &[0x01, 0x02]))],
                Some(Fault::Busy { frames }) => {
                    for _ in 0..frames {
                        out.push((t, BUSY_FRAME.to_vec()));
                        t += self.config.busy_lockup_interval_ms;
                    }
                }
                Some(Fault::NoAckApplied) => {
                    self.store(body, true);
                    return out;
                }
                Some(Fault::NoAckThenBusy { busy_frames }) => {
                    self.store(body, true);
                    self.post_write_busy = Some(busy_frames);
                    return out;
                }
                Some(Fault::NoAckDropped) => {
                    self.store(body, false);
                    return out;
                }
                Some(Fault::LateAck { delay_ms }) => {
                    let r = self.store(body, true);
                    return vec![(delay_ms, r)];
                }
                Some(Fault::GarbledAck) => {
                    let mut r = self.store(body, true);
                    if let Some(last) = r.last_mut() {
                        *last = last.wrapping_add(1);
                    }
                    return vec![(lat, r)];
                }
                Some(Fault::StaleReply) => {
                    self.store(body, true);
                    return vec![(lat, Self::reply(Cmd::Read.byte(), &[0x00]))];
                }
                Some(Fault::LinkDropMidChunk { partial_len }) => {
                    let r = self.store(body, true);
                    self.link_drop_partial = Some(partial_len);
                    return vec![(lat, r)];
                }
                Some(Fault::ReadRefused) => {
                    return vec![(lat, Self::reply(Cmd::Read.byte(), &[0x01, 0x03]))];
                }
                Some(Fault::DuplicateReply) => {
                    let stale = match Cmd::from_byte(cmd) {
                        Some(Cmd::Read) if body.len() == 6 => {
                            let mut b = vec![0x00];
                            b.resize(1 + 2 * body[5] as usize, 0xEE);
                            Self::reply(cmd, &b)
                        }
                        _ => Self::reply(cmd, &[0x00]),
                    };
                    out.push((t, stale));
                    t += 20;
                }
                Some(Fault::SilentWrite) | Some(Fault::BusyAfterReply) => {}
                Some(Fault::LinkDropMidSend { .. })
                | Some(Fault::WrongPassword)
                | Some(Fault::AnotherTerminal(_))
                | Some(Fault::LoginReply(_)) => {}
                None => {}
            }
            let silent = fault == Some(Fault::SilentWrite);
            let r = self.frame_reply(cmd, body, silent);
            out.push((t, r));
            if fault == Some(Fault::BusyAfterReply) {
                out.push((t + 10, BUSY_FRAME.to_vec()));
            }
        }
        #[cfg(not(feature = "faults"))]
        {
            out.push((lat, self.frame_reply(cmd, body, false)));
        }
        out
    }

    fn frame_reply(&mut self, cmd: u8, body: &[u8], silent: bool) -> Vec<u8> {
        match Cmd::from_byte(cmd) {
            Some(Cmd::Probe) if body == [0x00] => {
                let mut b = vec![0x00];
                b.extend_from_slice(&self.rom_id);
                Self::reply(cmd, &b)
            }
            Some(Cmd::Probe) if body == [0x01] => Self::reply(cmd, &[0x01, 0x03]),
            Some(Cmd::Read) if body.len() == 6 => self.read(body),
            Some(Cmd::Write) if body.len() > 6 => self.store(body, !silent),
            Some(Cmd::Clock) => Self::reply(cmd, &[0x00, 0x1A, 1, 2, 0, 3, 4, 5, 0]),
            Some(Cmd::EndBinary) => {
                self.mode = Mode::AwaitBye;
                Self::reply(cmd, &[0x00])
            }
            _ => Self::reply(cmd, &[0x00]),
        }
    }

    fn span(&self, body: &[u8], len: usize) -> Option<(u8, usize)> {
        let table = body[0];
        let rec = u16::from_be_bytes([body[1], body[2]]) as usize;
        let word = u16::from_be_bytes([body[3], body[4]]) as usize;
        let s = tables::spec(table)?;
        if rec >= s.records as usize {
            return None;
        }
        let start = rec * s.record_bytes as usize + 2 * word;
        let img = self.db.get(&table)?;
        (start + len <= img.len()).then_some((table, start))
    }

    fn read(&self, body: &[u8]) -> Vec<u8> {
        let n = 2 * body[5] as usize;
        match self.span(body, n) {
            Some((table, start)) => {
                let mut b = vec![0x00];
                b.extend_from_slice(&self.db[&table][start..start + n]);
                Self::reply(Cmd::Read.byte(), &b)
            }
            None => Self::reply(Cmd::Read.byte(), &[0x01, 0x03]),
        }
    }

    fn store(&mut self, body: &[u8], apply: bool) -> Vec<u8> {
        let payload = &body[6..];
        let Some((table, start)) = self.span(body, payload.len()) else {
            return Self::reply(Cmd::Write.byte(), &[0x01, 0x03]); // guess (G4)
        };
        let rec = u16::from_be_bytes([body[1], body[2]]);
        let word = u16::from_be_bytes([body[3], body[4]]);
        self.writes.push((table, rec, word, payload.to_vec()));
        if apply {
            if let Some(img) = self.db.get_mut(&table) {
                img[start..start + payload.len()].copy_from_slice(payload);
            }
        }
        Self::reply(Cmd::Write.byte(), &[0x00])
    }
}

/// Virtual-time loopback transport binding a client to an in-process [`SimPbx`].
pub struct SimTransport {
    pub sim: SimPbx,
    now: u64,
    queue: VecDeque<(u64, Vec<u8>)>,
    /// Every byte the client sent.
    pub sent: Vec<u8>,
    /// When set, the link drops right after the next write frame reaches the simulator.
    pub drop_link_after_write: bool,
    /// Next send fails after this many bytes left the host (`LinkDown` if `n > 0`,
    /// [`TransportError::NothingWritten`] if `n == 0`). A full write frame may be stored
    /// when `n` equals the frame length.
    pub fail_send_after: Option<usize>,
    /// Next [`Transport::send`] returns [`TransportError::Timeout`] (once).
    pub send_timeout_next: bool,
    link_down: bool,
    #[cfg(feature = "faults")]
    link_drop_pending: bool,
}

impl SimTransport {
    /// Opening the port raises DTR; the simulator answers XOFF/XON.
    pub fn new(mut sim: SimPbx) -> Self {
        let first = sim.dtr_up();
        let mut q = VecDeque::new();
        q.push_back((0, first));
        Self {
            sim,
            now: 0,
            queue: q,
            sent: Vec::new(),
            drop_link_after_write: false,
            fail_send_after: None,
            send_timeout_next: false,
            link_down: false,
            #[cfg(feature = "faults")]
            link_drop_pending: false,
        }
    }

    /// Bring a dropped link back: DTR cycles and the PBX greets again, ready for login.
    pub fn reconnect(&mut self) {
        self.link_down = false;
        self.drop_link_after_write = false;
        self.fail_send_after = None;
        self.send_timeout_next = false;
        #[cfg(feature = "faults")]
        {
            self.link_drop_pending = false;
        }
        self.queue.clear();
        self.sim.dtr_down();
        self.sim.clear_busy_lockup();
        self.sim.buf.clear();
        let first = self.sim.dtr_up();
        let now = self.now;
        self.schedule(now, first);
    }

    /// Drop the link now: every later send/recv fails until [`Self::reconnect`].
    pub fn drop_link_now(&mut self) {
        self.link_down = true;
    }

    /// Queue bytes as if they were already waiting in the receive buffer (a stale frame
    /// from an earlier exchange).
    pub fn inject_inbound(&mut self, bytes: Vec<u8>) {
        self.inject_inbound_after(0, bytes);
    }

    /// Queue bytes to arrive `delay_ms` from now, independent of any request.
    pub fn inject_inbound_after(&mut self, delay_ms: u64, bytes: Vec<u8>) {
        let at = self.now + delay_ms;
        self.schedule(at, bytes);
    }

    pub fn now(&self) -> u64 {
        self.now
    }

    fn schedule(&mut self, at: u64, bytes: Vec<u8>) {
        let pos = self
            .queue
            .iter()
            .position(|(t, _)| *t > at)
            .unwrap_or(self.queue.len());
        self.queue.insert(pos, (at, bytes));
    }

    fn schedule_busy_cadence(&mut self, start_ms: u64, frames: u32, interval_ms: u64) {
        if frames == 0 {
            return;
        }
        let tline = kxtd1232::Timing::default();
        for i in 0..frames {
            let at = start_ms + u64::from(i) * interval_ms + tline.tx_ms(BUSY_FRAME.len());
            self.schedule(at, BUSY_FRAME.to_vec());
        }
    }

    fn finish_lockup_train(&mut self, rx_done: u64) {
        if !self.sim.lockup_discard {
            return;
        }
        let busy_iv = self.sim.config.busy_lockup_interval_ms;
        let frames = self.sim.lockup_busy_left;
        self.sim.lockup_busy_left = 0;
        if frames > 0 {
            self.schedule_busy_cadence(rx_done + self.sim.latency_ms, frames, busy_iv);
        }
        let total_busy = u64::from(self.sim.config.busy_lockup_frames);
        let train_ms = self.sim.latency_ms
            + total_busy.saturating_mul(busy_iv)
            + kxtd1232::Timing::default().tx_ms(BUSY_FRAME.len());
        self.sim.lockup_end_ms = rx_done.saturating_add(train_ms);
    }
}

impl Transport for SimTransport {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if self.link_down {
            return Err(TransportError::NothingWritten("sim: link dropped".into()));
        }
        if self.send_timeout_next {
            self.send_timeout_next = false;
            return Err(TransportError::Timeout);
        }
        let tline = kxtd1232::Timing::default();
        if let Some(n) = self.fail_send_after.take() {
            let n = n.min(data.len());
            if n > 0 {
                self.sent.extend_from_slice(&data[..n]);
                let rx_done = self.now + tline.tx_ms(n);
                for (delay, bytes) in self.sim.feed(&data[..n], self.now) {
                    let at = rx_done + delay + tline.tx_ms(bytes.len());
                    self.schedule(at, bytes);
                }
            }
            self.link_down = true;
            if n == 0 {
                return Err(TransportError::NothingWritten(
                    "sim: link dropped mid-send".into(),
                ));
            }
            return Err(TransportError::LinkDown(LinkDownError {
                detail: "sim: link dropped mid-send".into(),
                bytes_sent: Some(n),
            }));
        }
        #[cfg(feature = "faults")]
        if let Some(n) = self.sim.take_mid_send_fault(data) {
            let n = n.min(data.len());
            if n > 0 {
                self.sent.extend_from_slice(&data[..n]);
                let rx_done = self.now + tline.tx_ms(n);
                for (delay, bytes) in self.sim.feed(&data[..n], self.now) {
                    let at = rx_done + delay + tline.tx_ms(bytes.len());
                    self.schedule(at, bytes);
                }
            }
            self.link_down = true;
            if n == 0 {
                return Err(TransportError::NothingWritten(
                    "simulated serial link down mid-send".into(),
                ));
            }
            return Err(TransportError::LinkDown(LinkDownError {
                detail: "simulated serial link down mid-send".into(),
                bytes_sent: Some(n),
            }));
        }
        self.sent.extend_from_slice(data);
        if self.drop_link_after_write && data.get(1) == Some(&Cmd::Write.byte()) {
            self.sim.feed(data, self.now);
            self.link_down = true;
            return Ok(());
        }
        let rx_done = self.now + tline.tx_ms(data.len());
        for (delay, bytes) in self.sim.feed(data, self.now) {
            #[cfg(feature = "faults")]
            let bytes = {
                let mut bytes = bytes;
                if let Some(n) = self.sim.link_drop_partial.take() {
                    let n = n.min(bytes.len());
                    if n < bytes.len() {
                        bytes.truncate(n);
                    }
                    self.link_drop_pending = true;
                }
                bytes
            };
            let at = rx_done + delay + tline.tx_ms(bytes.len());
            self.schedule(at, bytes);
        }
        #[cfg(feature = "faults")]
        if let Some(frames) = self.sim.post_write_busy.take() {
            let busy_iv = self.sim.config.busy_lockup_interval_ms;
            self.schedule_busy_cadence(rx_done + self.sim.latency_ms, frames, busy_iv);
        }
        self.finish_lockup_train(rx_done);
        Ok(())
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        if self.link_down {
            return Err(TransportError::LinkDown(LinkDownError {
                detail: "sim: link dropped".into(),
                bytes_sent: None,
            }));
        }
        match self.queue.front() {
            Some(&(at, _)) if at <= self.now + timeout_ms => {
                self.now = self.now.max(at);
                self.sim.advance_lockup(self.now);
                let mut out = Vec::new();
                while let Some((t, _)) = self.queue.front() {
                    if *t > self.now {
                        break;
                    }
                    if let Some((_, b)) = self.queue.pop_front() {
                        out.extend(b);
                    }
                }
                #[cfg(feature = "faults")]
                if self.link_drop_pending {
                    self.link_drop_pending = false;
                    self.link_down = true;
                }
                Ok(out)
            }
            _ => {
                self.now += timeout_ms;
                self.sim.advance_lockup(self.now);
                Err(TransportError::Timeout)
            }
        }
    }

    fn now_ms(&mut self) -> u64 {
        self.now
    }
}
