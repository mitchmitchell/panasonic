//! Sans-I/O KX-TD1232 simulator built from the behavior spec, plus a virtual-time
//! [`SimTransport`]. All data is synthetic; nothing here comes from a real unit.
//!
//! A1 fault hooks: NAK, silent write, busy run, unacked write (applied / dropped), late
//! ack, garbled ack and stale reply. The rest of design §6 (link drop, wrong-password
//! variants, ...) lands in A2.

use kxtd1232::fields::{encode_cid_name, encode_cid_number, encode_ext_name};
use kxtd1232::frame::{checksum, Cmd, BUSY_FRAME};
use kxtd1232::tables;
use kxtd1232::{LinkDownError, SignOn, Transport, TransportError};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

pub const PLACEHOLDER_PASSWORD: &str = "0000";
pub const PLACEHOLDER_ROM_ID: &str = "-----PXXXXXXXXXX";
/// `.DBH` bytes 0x1E–0xFF (226); filled at sim init as runtime upload metadata, not embedded in kxprovd.
pub const DBH_HEADER_TAIL_LEN: usize = 0x100 - 0x1E;
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
/// Busy-frame cadence observed on the real unit.
pub const BUSY_CADENCE_MS: u64 = 128;

/// Tunable simulator timing and counts (placeholders for fault tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimConfig {
    pub busy_lockup_frames: u32,
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

/// Injected faults, consumed in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// Next request gets a bad-checksum NAK (`01 02`).
    Nak,
    /// Next write is acked but not stored.
    SilentWrite,
    /// Next request's reply is preceded by `frames` busy frames at 128 ms cadence.
    Busy { frames: u32 },
    /// Next write is stored, no ack is sent.
    NoAckApplied,
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
    /// Next write is stored, no ack; busy frames follow before verify.
    NoAckThenBusy { busy_frames: u32 },
    /// Next write ack is cut off after `partial_len` bytes, then link drops.
    LinkDropMidChunk { partial_len: usize },
    /// Drop link after `after_bytes` of the next outgoing write (not stored).
    LinkDropMidSend { after_bytes: usize },
    /// Next read gets end-of-table refusal even in range.
    ReadRefused,
    /// Next failed password attempt gets the default re-prompt.
    WrongPassword,
    /// Next password attempt gets an "another terminal" style line.
    AnotherTerminal(String),
    /// Next password attempt gets a custom login line.
    LoginReply(String),
}

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
    pub db: HashMap<u8, Vec<u8>>,
    /// Vendor header tail bytes (0x1E–0xFF) as if captured from a full upload session.
    dbh_header_tail: [u8; DBH_HEADER_TAIL_LEN],
    password: Vec<u8>,
    rom_id: [u8; 16],
    mode: Mode,
    buf: Vec<u8>,
    faults: VecDeque<Fault>,
    /// Writes received with valid checksums (stored or not).
    pub writes: Vec<WriteRecord>,
    /// Command bytes of every binary frame received, in order.
    pub commands: Vec<u8>,
    /// Response latency for every reply.
    pub latency_ms: u64,
    pub config: SimConfig,
    /// When set, BYE gets no answer (logout not confirmed).
    pub silent_bye: bool,
    #[cfg(feature = "faults")]
    pub(crate) post_write_busy: Option<u32>,
    #[cfg(feature = "faults")]
    pub(crate) link_drop_partial: Option<usize>,
}

impl Default for SimPbx {
    fn default() -> Self {
        Self::new(synthetic_db(), PLACEHOLDER_PASSWORD)
    }
}

/// Bytes the simulator emits, each after a delay relative to the triggering input.
pub type Emits = Vec<(u64, Vec<u8>)>;

fn fresh_dbh_header_tail() -> [u8; DBH_HEADER_TAIL_LEN] {
    let mut tail = [0u8; DBH_HEADER_TAIL_LEN];
    getrandom::fill(&mut tail).expect("getrandom");
    tail
}

impl SimPbx {
    pub fn new(db: HashMap<u8, Vec<u8>>, password: &str) -> Self {
        let mut rom_id = [b' '; 16];
        for (d, s) in rom_id.iter_mut().zip(PLACEHOLDER_ROM_ID.bytes()) {
            *d = s;
        }
        Self {
            db,
            dbh_header_tail: fresh_dbh_header_tail(),
            password: password.as_bytes().to_vec(),
            rom_id,
            mode: Mode::Idle,
            buf: Vec::new(),
            faults: VecDeque::new(),
            writes: Vec::new(),
            commands: Vec::new(),
            latency_ms: 30,
            config: SimConfig::default(),
            silent_bye: false,
            #[cfg(feature = "faults")]
            post_write_busy: None,
            #[cfg(feature = "faults")]
            link_drop_partial: None,
        }
    }

    pub fn inject(&mut self, fault: Fault) {
        self.faults.push_back(fault);
    }

    /// Header bytes 0x1E–0xFF for `.DBH` assembly (runtime upload image in the sim).
    pub fn dbh_header_tail(&self) -> &[u8; DBH_HEADER_TAIL_LEN] {
        &self.dbh_header_tail
    }

    pub fn pending_faults(&self) -> usize {
        self.faults.len()
    }

    #[cfg(feature = "faults")]
    pub(crate) fn take_mid_send_fault(&mut self, data: &[u8]) -> Option<usize> {
        if data.get(1) != Some(&Cmd::Write.byte()) {
            return None;
        }
        match self.faults.front()? {
            Fault::LinkDropMidSend { after_bytes } => {
                let n = *after_bytes;
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
    }

    /// Clear line/session state before a new client attaches (shared PBX, new transport).
    pub fn reset_for_new_session(&mut self) {
        self.mode = Mode::Idle;
        self.buf.clear();
    }

    pub fn feed(&mut self, data: &[u8]) -> Emits {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            if self.mode == Mode::Binary {
                let Some(&len) = self.buf.first() else {
                    return out;
                };
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

    fn text(&mut self, line: &[u8]) -> Vec<u8> {
        match self.mode {
            Mode::AwaitCrlf => {
                self.mode = Mode::AwaitPassword;
                banner()
            }
            Mode::AwaitPassword => {
                if let Some(Fault::WrongPassword) = self.faults.front() {
                    self.faults.pop_front();
                    return text_line(&SignOn::default().password_prompt);
                }
                if let Some(Fault::AnotherTerminal(msg)) = self.faults.front() {
                    let msg = msg.clone();
                    self.faults.pop_front();
                    return text_line(&msg);
                }
                if let Some(Fault::LoginReply(msg)) = self.faults.front() {
                    let msg = msg.clone();
                    self.faults.pop_front();
                    return text_line(&msg);
                }
                if line == self.password.as_slice() {
                    self.mode = Mode::AwaitEcs;
                    return text_line(&SignOn::default().mode_start);
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

    fn frame(&mut self, raw: &[u8]) -> Emits {
        let lat = self.latency_ms;
        let cmd = raw.get(1).copied().unwrap_or(0xFF);
        if raw.len() < 3 || checksum(&raw[..raw.len() - 1]) != raw[raw.len() - 1] {
            return vec![(lat, Self::reply(cmd, &[0x01, 0x02]))];
        }
        self.commands.push(cmd);
        let is_write = cmd == Cmd::Write.byte();
        let fault = match self.faults.front() {
            Some(f) if is_write || !f.write_only() => self.faults.pop_front(),
            _ => None,
        };
        let body = &raw[2..raw.len() - 1];
        let mut out: Emits = Vec::new();
        let mut t = lat;
        match fault {
            Some(Fault::Nak) => return vec![(lat, Self::reply(cmd, &[0x01, 0x02]))],
            Some(Fault::Busy { frames }) => {
                for _ in 0..frames {
                    out.push((t, BUSY_FRAME.to_vec()));
                    t += BUSY_CADENCE_MS;
                }
            }
            Some(Fault::NoAckApplied) => {
                self.store(body, true);
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
            Some(Fault::NoAckThenBusy { busy_frames }) => {
                self.store(body, true);
                #[cfg(feature = "faults")]
                {
                    self.post_write_busy = Some(busy_frames);
                }
                return out;
            }
            Some(Fault::ReadRefused) => {
                return vec![(lat, Self::reply(Cmd::Read.byte(), &[0x01, 0x03]))];
            }
            Some(Fault::LinkDropMidChunk { partial_len }) => {
                let r = self.store(body, true);
                #[cfg(feature = "faults")]
                {
                    self.link_drop_partial = Some(partial_len);
                }
                return vec![(lat, r)];
            }
            Some(Fault::SilentWrite) | Some(Fault::BusyAfterReply) => {}
            Some(Fault::LinkDropMidSend { .. })
            | Some(Fault::WrongPassword)
            | Some(Fault::AnotherTerminal(_))
            | Some(Fault::LoginReply(_)) => {}
            None => {}
        }
        let r = match Cmd::from_byte(cmd) {
            Some(Cmd::Probe) if body == [0x00] => {
                let mut b = vec![0x00];
                b.extend_from_slice(&self.rom_id);
                Self::reply(cmd, &b)
            }
            Some(Cmd::Probe) if body == [0x01] => Self::reply(cmd, &[0x01, 0x03]),
            Some(Cmd::Read) if body.len() == 6 => self.read(body),
            Some(Cmd::Write) if body.len() > 6 => {
                self.store(body, fault != Some(Fault::SilentWrite))
            }
            Some(Cmd::Clock) => Self::reply(cmd, &[0x00, 0x1A, 1, 2, 0, 3, 4, 5, 0]),
            Some(Cmd::EndBinary) => {
                self.mode = Mode::AwaitBye;
                Self::reply(cmd, &[0x00])
            }
            _ => Self::reply(cmd, &[0x00]), // guess, like the RE simulator
        };
        out.push((t, r));
        if fault == Some(Fault::BusyAfterReply) {
            out.push((t + 10, BUSY_FRAME.to_vec()));
        }
        out
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
    sim: Arc<Mutex<SimPbx>>,
    now: u64,
    queue: VecDeque<(u64, Vec<u8>)>,
    /// Every byte the client sent.
    pub sent: Vec<u8>,
    /// When set, the link drops right after the next write frame reaches the simulator.
    pub drop_link_after_write: bool,
    /// Next write send fails with `LinkDown` after this many bytes left the host (a
    /// partial frame, or the whole frame when >= its length, which the PBX then stores).
    pub fail_write_send_after: Option<usize>,
    pub fail_send_after: Option<usize>,
    pub send_timeout_next: bool,
    link_down: bool,
    #[cfg(feature = "faults")]
    link_drop_pending: bool,
}

impl SimTransport {
    /// Opening the port raises DTR; the simulator answers XOFF/XON.
    pub fn new(sim: SimPbx) -> Self {
        Self::with_shared(Arc::new(Mutex::new(sim)))
    }

    /// Attach a fresh virtual-time session to an existing PBX (shared DB).
    pub fn with_shared(sim: Arc<Mutex<SimPbx>>) -> Self {
        let first = {
            let mut pbx = sim.lock().expect("sim pbx lock");
            pbx.reset_for_new_session();
            pbx.dtr_up()
        };
        let mut q = VecDeque::new();
        q.push_back((0, first));
        Self {
            sim,
            now: 0,
            queue: q,
            sent: Vec::new(),
            drop_link_after_write: false,
            fail_write_send_after: None,
            fail_send_after: None,
            send_timeout_next: false,
            link_down: false,
            #[cfg(feature = "faults")]
            link_drop_pending: false,
        }
    }

    pub fn shared_pbx(&self) -> Arc<Mutex<SimPbx>> {
        Arc::clone(&self.sim)
    }

    pub fn sim(&self) -> MutexGuard<'_, SimPbx> {
        self.sim.lock().expect("sim pbx lock")
    }

    pub fn sim_mut(&mut self) -> MutexGuard<'_, SimPbx> {
        self.sim.lock().expect("sim pbx lock")
    }

    /// Bring a dropped link back: DTR cycles and the PBX greets again, ready for login.
    pub fn reconnect(&mut self) {
        self.link_down = false;
        self.drop_link_after_write = false;
        self.fail_write_send_after = None;
        self.fail_send_after = None;
        self.send_timeout_next = false;
        self.queue.clear();
        let first = {
            let mut pbx = self.sim.lock().expect("sim pbx lock");
            pbx.dtr_down();
            pbx.dtr_up()
        };
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
        if let Some(n) = self.fail_send_after.take() {
            let n = n.min(data.len());
            self.sent.extend_from_slice(&data[..n]);
            if n == data.len() {
                self.sim.lock().expect("sim pbx lock").feed(data);
            }
            self.link_down = true;
            return if n == 0 {
                Err(TransportError::NothingWritten(
                    "sim: link dropped mid-send".into(),
                ))
            } else {
                Err(TransportError::LinkDown(LinkDownError {
                    detail: "sim: link dropped mid-send".into(),
                    bytes_sent: n,
                }))
            };
        }
        if data.get(1) == Some(&Cmd::Write.byte()) {
            if let Some(n) = self.fail_write_send_after.take() {
                let n = n.min(data.len());
                self.sent.extend_from_slice(&data[..n]);
                if n == data.len() {
                    self.sim.lock().expect("sim pbx lock").feed(data);
                }
                self.link_down = true;
                return if n == 0 {
                    Err(TransportError::NothingWritten(
                        "sim: link dropped mid-send".into(),
                    ))
                } else {
                    Err(TransportError::LinkDown(LinkDownError {
                        detail: "sim: link dropped mid-send".into(),
                        bytes_sent: n,
                    }))
                };
            }
        }
        #[cfg(feature = "faults")]
        if let Some(n) = self
            .sim
            .lock()
            .expect("sim pbx lock")
            .take_mid_send_fault(data)
        {
            let n = n.min(data.len());
            if n > 0 {
                self.sent.extend_from_slice(&data[..n]);
            }
            self.link_down = true;
            return if n == 0 {
                Err(TransportError::NothingWritten(
                    "simulated serial link down mid-send".into(),
                ))
            } else {
                Err(TransportError::LinkDown(LinkDownError {
                    detail: "simulated serial link down mid-send".into(),
                    bytes_sent: n,
                }))
            };
        }
        self.sent.extend_from_slice(data);
        if self.drop_link_after_write && data.get(1) == Some(&Cmd::Write.byte()) {
            self.sim.lock().expect("sim pbx lock").feed(data);
            self.link_down = true;
            return Ok(());
        }
        let t = kxtd1232::Timing::default();
        let rx_done = self.now + t.tx_ms(data.len());
        let mut pbx = self.sim.lock().expect("sim pbx lock");
        let emits = pbx.feed(data);
        for (delay, mut bytes) in emits {
            #[cfg(feature = "faults")]
            if let Some(n) = pbx.link_drop_partial.take() {
                let orig = bytes.len();
                let n = n.min(orig);
                bytes.truncate(n);
                if n < orig {
                    self.link_drop_pending = true;
                }
            }
            let at = rx_done + delay + t.tx_ms(bytes.len());
            drop(pbx);
            self.schedule(at, bytes);
            pbx = self.sim.lock().expect("sim pbx lock");
        }
        Ok(())
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        if self.link_down {
            return Err(TransportError::LinkDown(LinkDownError {
                detail: "sim: link dropped".into(),
                bytes_sent: 0,
            }));
        }
        match self.queue.front() {
            Some(&(at, _)) if at <= self.now + timeout_ms => {
                self.now = self.now.max(at);
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
                Err(TransportError::Timeout)
            }
        }
    }

    fn now_ms(&mut self) -> u64 {
        self.now
    }
}
