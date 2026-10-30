pub const LINE_WIDTH: usize = 80;

pub const MODEM_INIT_WIDTH: usize = 17;

pub const SPEC_HEADER: &str =
    "  Date     Time    Ext CO        Dial Number        Ring Duration  Acc code  CD ";

const NUL: u8 = 0x00;
const XON: u8 = 0x11;
const XOFF: u8 = 0x13;
const FF: u8 = 0x0C;
const CR: u8 = b'\r';
const LF: u8 = b'\n';
const MIN_RULE_LEN: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    Blank,
    ModemInit,
    Header,
    Rule,
    Record,
    Unknown,
}

impl LineKind {
    pub fn is_page_header(self) -> bool {
        matches!(self, LineKind::Header | LineKind::Rule | LineKind::Blank)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmdrLine {
    pub kind: LineKind,
    pub raw: String,
}

impl SmdrLine {
    pub fn new(raw: String) -> Self {
        Self {
            kind: classify(&raw),
            raw,
        }
    }

    pub fn header_matches_spec(&self) -> bool {
        self.kind == LineKind::Header && self.raw == SPEC_HEADER
    }
}

#[derive(Debug, Default)]
pub struct LineSplitter {
    buf: Vec<u8>,
    after_cr: bool,
}

impl LineSplitter {
    pub fn new() -> Self {
        Self::default()
    }

    // https://github.com/mitchmitchell/panasonic/issues/11
    pub fn push(&mut self, bytes: &[u8]) -> Vec<SmdrLine> {
        let mut out = Vec::new();
        for &b in bytes {
            let after_cr = std::mem::replace(&mut self.after_cr, false);
            match b {
                LF if after_cr => {}
                CR | LF => {
                    self.after_cr = b == CR;
                    out.push(SmdrLine::new(decode(&std::mem::take(&mut self.buf))));
                }
                NUL | XON | XOFF | FF => {}
                _ => self.buf.push(b),
            }
        }
        out
    }

    pub fn finish(&mut self) -> Option<SmdrLine> {
        self.after_cr = false;
        if self.buf.is_empty() {
            None
        } else {
            Some(SmdrLine::new(decode(&std::mem::take(&mut self.buf))))
        }
    }
}

// https://github.com/mitchmitchell/panasonic/issues/20
fn decode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii() {
                char::from(b)
            } else {
                char::REPLACEMENT_CHARACTER
            }
        })
        .collect()
}

// https://github.com/mitchmitchell/panasonic/issues/13
// https://github.com/mitchmitchell/panasonic/issues/19
// https://github.com/mitchmitchell/panasonic/issues/21
pub fn classify(line: &str) -> LineKind {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        LineKind::Blank
    } else if line.starts_with("AT") {
        LineKind::ModemInit
    } else if is_header(line) {
        LineKind::Header
    } else if trimmed.len() >= MIN_RULE_LEN && trimmed.bytes().all(|b| b == b'-') {
        LineKind::Rule
    } else if line.len() == LINE_WIDTH && is_record(line) {
        LineKind::Record
    } else {
        LineKind::Unknown
    }
}

fn is_header(line: &str) -> bool {
    let mut words = line.split_ascii_whitespace();
    words.next() == Some("Date") && words.next() == Some("Time")
}

fn is_record(line: &str) -> bool {
    let b = line.as_bytes();
    let digit = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    let at = |i: usize, c: u8| b.get(i) == Some(&c);
    [0, 1, 3, 4, 6, 7, 9, 10, 12, 13].into_iter().all(digit)
        && at(2, b'/')
        && at(5, b'/')
        && at(8, b' ')
        && at(11, b':')
        && (at(14, b'A') || at(14, b'P'))
        && at(15, b'M')
}
