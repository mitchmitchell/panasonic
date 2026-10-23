//! Sans-I/O KX-TD1232 simulator built from the behavior spec, plus a virtual-time
//! [`SimTransport`]. All data is synthetic; nothing here comes from a real unit.
//!
//! Fault hooks for design §6 / milestone A2: NAK, silent write, busy run, unacked write
//! (applied / dropped), late ack, garbled ack, stale reply, and link drop mid-chunk.

use kxtd1232::fields::{encode_cid_name, encode_cid_number, encode_ext_name};
use kxtd1232::frame::{checksum, encode_raw, Cmd, BUSY_FRAME};
use kxtd1232::tables;
use kxtd1232::{Transport, TransportError};
use std::collections::{HashMap, VecDeque};

pub const PLACEHOLDER_PASSWORD: &str = "0000";
pub const PLACEHOLDER_ROM_ID: &str = "-----PXXXXXXXXXX";
pub const BANNER: &[u8] = b"Welcome To KX-TD1232  Ver 2.0 Panasonic CO.,LTD.\r\nEnter Password\r\n";
/// Busy-frame cadence observed on the real unit.
pub const BUSY_CADENCE_MS: u64 = 128;

/// Injected faults, consumed in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Next write is stored; the ack is cut off after `partial_len` bytes, then the link drops.
    LinkDropMidChunk { partial_len: usize },
}

impl Fault {
    const fn write_only(self) -> bool {
        !matches!(self, Self::Nak | Self::Busy { .. })
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
    /// When set, the transport delivers this many ack bytes then reports link down.
    pub(crate) link_drop_partial: Option<usize>,
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
        let mut rom_id = [b' '; 16];
        for (d, s) in rom_id.iter_mut().zip(PLACEHOLDER_ROM_ID.bytes()) {
            *d = s;
        }
        Self {
            db,
            password: password.as_bytes().to_vec(),
            rom_id,
            mode: Mode::Idle,
            buf: Vec::new(),
            faults: VecDeque::new(),
            writes: Vec::new(),
            commands: Vec::new(),
            latency_ms: 30,
            link_drop_partial: None,
        }
    }

    pub fn inject(&mut self, fault: Fault) {
        self.faults.push_back(fault);
    }

    pub fn pending_faults(&self) -> usize {
        self.faults.len()
    }

    pub fn dtr_up(&mut self) -> Vec<u8> {
        self.mode = Mode::AwaitCrlf;
        self.buf.clear();
        vec![0x13, 0x11]
    }

    pub fn dtr_down(&mut self) {
        self.mode = Mode::Idle;
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
                BANNER.to_vec()
            }
            Mode::AwaitPassword if line == self.password.as_slice() => {
                self.mode = Mode::AwaitEcs;
                b"EIA Mode Start\r\n".to_vec()
            }
            // Wrong-password reply is a guess, like the RE simulator (gate G5).
            Mode::AwaitPassword => b"Enter Password\r\n".to_vec(),
            Mode::AwaitEcs if line == b"ECS OF" => {
                self.mode = Mode::AwaitPrg;
                b"ECS OF\r\nOK\r\n".to_vec()
            }
            Mode::AwaitPrg if line == b"PRG" => {
                self.mode = Mode::Binary;
                b"OK\r\n".to_vec()
            }
            Mode::AwaitBye if line == b"BYE" => {
                self.mode = Mode::AwaitPassword;
                let mut v = b"OK\r\n".to_vec();
                v.extend_from_slice(BANNER);
                v
            }
            _ => b"NG\r\n".to_vec(),
        }
    }

    fn reply(cmd: u8, body: &[u8]) -> Vec<u8> {
        encode_raw(cmd, body).unwrap_or_default()
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
            Some(Fault::LinkDropMidChunk { partial_len }) => {
                let r = self.store(body, true);
                self.link_drop_partial = Some(partial_len);
                return vec![(lat, r)];
            }
            _ => {}
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
    pub sim: SimPbx,
    now: u64,
    queue: VecDeque<(u64, Vec<u8>)>,
    /// Every byte the client sent.
    pub sent: Vec<u8>,
    /// Sticky until [`Self::clear_link_down`]: send and recv fail with [`TransportError::LinkDown`].
    link_down: bool,
    /// Set when a truncated reply was queued; the link drops after that data is delivered once.
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
            link_down: false,
            link_drop_pending: false,
        }
    }

    pub fn now(&self) -> u64 {
        self.now
    }

    /// Clear a simulated link-down so a test can "reconnect" without rebuilding the PBX image.
    pub fn clear_link_down(&mut self) {
        self.link_down = false;
        self.link_drop_pending = false;
    }

    pub fn is_link_down(&self) -> bool {
        self.link_down
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
            return Err(TransportError::LinkDown(
                "simulated serial link down".into(),
            ));
        }
        self.sent.extend_from_slice(data);
        for (delay, mut bytes) in self.sim.feed(data) {
            if let Some(n) = self.sim.link_drop_partial.take() {
                let n = n.min(bytes.len());
                if n < bytes.len() {
                    bytes.truncate(n);
                    self.link_drop_pending = true;
                }
            }
            let at = self.now + delay;
            self.schedule(at, bytes);
        }
        Ok(())
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        if self.link_down {
            return Err(TransportError::LinkDown(
                "simulated serial link down".into(),
            ));
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
