pub const LINE_WIDTH: usize = 80;

pub const MAX_PENDING_BYTES: usize = 2 * LINE_WIDTH;

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
    #[must_use]
    pub fn is_page_header(self) -> bool {
        matches!(self, LineKind::Header | LineKind::Rule | LineKind::Blank)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmdrLine {
    kind: LineKind,
    raw: String,
}

impl SmdrLine {
    #[must_use]
    pub fn new(raw: String) -> Self {
        Self {
            kind: classify(&raw),
            raw,
        }
    }

    fn overflow(raw: String) -> Self {
        Self {
            kind: LineKind::Unknown,
            raw,
        }
    }

    #[must_use]
    pub fn kind(&self) -> LineKind {
        self.kind
    }

    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    #[must_use]
    pub fn into_raw(self) -> String {
        self.raw
    }

    #[must_use]
    pub fn header_matches_spec(&self) -> bool {
        self.kind == LineKind::Header && self.raw == SPEC_HEADER
    }
}

#[derive(Debug, Default)]
pub struct LineSplitter {
    buf: Vec<u8>,
    after_cr: bool,
    after_overflow: bool,
}

impl LineSplitter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // https://github.com/mitchmitchell/panasonic/issues/11
    #[must_use]
    pub fn push(&mut self, bytes: &[u8]) -> Vec<SmdrLine> {
        let mut out = Vec::new();
        for &b in bytes {
            if matches!(b, NUL | XON | XOFF | FF) {
                continue;
            }
            let after_cr = std::mem::replace(&mut self.after_cr, false);
            match b {
                LF if after_cr => {}
                CR | LF => {
                    self.after_cr = b == CR;
                    if !std::mem::replace(&mut self.after_overflow, false) {
                        out.push(SmdrLine::new(decode(&std::mem::take(&mut self.buf))));
                    }
                }
                _ => {
                    self.after_overflow = false;
                    self.buf.push(b);
                    if self.buf.len() >= MAX_PENDING_BYTES {
                        self.after_overflow = true;
                        out.push(SmdrLine::overflow(decode(&std::mem::take(&mut self.buf))));
                    }
                }
            }
        }
        out
    }

    #[must_use]
    pub fn finish(&mut self) -> Option<SmdrLine> {
        self.after_cr = false;
        self.after_overflow = false;
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
#[must_use]
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
    } else if line.chars().count() == LINE_WIDTH && is_record(line) {
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

// https://github.com/mitchmitchell/panasonic/issues/10
pub const TWO_DIGIT_YEAR_BASE: u16 = 2000;

// https://github.com/mitchmitchell/panasonic/issues/10
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DateOrder {
    #[default]
    Mdy,
    Dmy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Incoming,
    Outgoing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PbxDate {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PbxTime {
    pub hour: u8,
    pub minute: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmdrRecord {
    pub date_raw: String,
    pub date: PbxDate,
    pub time_raw: String,
    pub time: PbxTime,
    pub ext: String,
    pub co: String,
    pub direction: Direction,
    pub number: String,
    pub cid_name: String,
    pub ring_raw: String,
    pub ring_s: Option<u32>,
    pub duration_raw: String,
    pub duration_s: Option<u32>,
    pub acc_code: String,
    // https://github.com/mitchmitchell/panasonic/issues/12
    pub cd: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    NotRecord(LineKind),
    BadDate,
    BadTime,
    BadSeparator(usize),
    BadExt,
    BadCo,
    BadNumber,
    BadRing,
    BadDuration,
    BadCd,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::NotRecord(kind) => write!(f, "not a record line ({kind:?})"),
            ParseError::BadDate => write!(f, "invalid date"),
            ParseError::BadTime => write!(f, "invalid time"),
            ParseError::BadSeparator(col) => write!(f, "expected a space at column {col}"),
            ParseError::BadExt => write!(f, "invalid extension"),
            ParseError::BadCo => write!(f, "invalid CO line"),
            ParseError::BadNumber => write!(f, "invalid dial area"),
            ParseError::BadRing => write!(f, "invalid ring time"),
            ParseError::BadDuration => write!(f, "invalid duration"),
            ParseError::BadCd => write!(f, "invalid CD code"),
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedLine {
    Record {
        line: SmdrLine,
        record: Box<SmdrRecord>,
    },
    // https://github.com/mitchmitchell/panasonic/issues/13
    PageHeader(SmdrLine),
    ModemInit(SmdrLine),
    // https://github.com/mitchmitchell/panasonic/issues/19
    Unparsed {
        line: SmdrLine,
        error: ParseError,
    },
}

#[must_use]
pub fn parse_line(line: SmdrLine, order: DateOrder) -> ParsedLine {
    match line.kind {
        LineKind::Header | LineKind::Rule | LineKind::Blank => ParsedLine::PageHeader(line),
        LineKind::ModemInit => ParsedLine::ModemInit(line),
        LineKind::Record | LineKind::Unknown => match parse_record(&line.raw, order) {
            Ok(record) => ParsedLine::Record {
                line,
                record: Box::new(record),
            },
            Err(error) => ParsedLine::Unparsed { line, error },
        },
    }
}

const SEPARATORS: [usize; 6] = [8, 22, 25, 56, 65, 79];
const SEPARATOR_RUNS: [(usize, usize); 2] = [(16, 19), (65, 67)];

pub fn parse_record(line: &str, order: DateOrder) -> Result<SmdrRecord, ParseError> {
    let kind = classify(line);
    if kind != LineKind::Record || !line.is_ascii() {
        return Err(ParseError::NotRecord(kind));
    }
    for col in SEPARATORS {
        if &line[col..=col] != " " {
            return Err(ParseError::BadSeparator(col));
        }
    }
    for (a, b) in SEPARATOR_RUNS {
        if let Some(off) = line[a..b].bytes().position(|c| c != b' ') {
            return Err(ParseError::BadSeparator(a + off));
        }
    }
    let date_raw = &line[0..8];
    let time_raw = &line[9..16];
    let ext = line[19..22].trim_start();
    if !ext.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseError::BadExt);
    }
    let co = &line[23..25];
    if !co.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseError::BadCo);
    }
    let (direction, number, cid_name) = parse_dial(&line[26..52])?;
    let ring_raw = line[52..56].trim();
    let ring_s = parse_ring(ring_raw)?;
    let duration_raw = line[57..65].trim();
    let duration_s = parse_duration(duration_raw)?;
    let acc_code = line[67..77].trim();
    let cd = line[77..79].trim();
    if !cd.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(ParseError::BadCd);
    }
    Ok(SmdrRecord {
        date_raw: date_raw.to_string(),
        date: parse_date(date_raw, order)?,
        time_raw: time_raw.to_string(),
        time: parse_time(time_raw)?,
        ext: ext.to_string(),
        co: co.to_string(),
        direction,
        number,
        cid_name,
        ring_raw: ring_raw.to_string(),
        ring_s,
        duration_raw: duration_raw.to_string(),
        duration_s,
        acc_code: acc_code.to_string(),
        cd: cd.to_string(),
    })
}

fn two_digits(s: &str) -> Option<u8> {
    if s.len() == 2 && s.bytes().all(|b| b.is_ascii_digit()) {
        s.parse().ok()
    } else {
        None
    }
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// https://github.com/mitchmitchell/panasonic/issues/10
pub fn parse_date(raw: &str, order: DateOrder) -> Result<PbxDate, ParseError> {
    let mut parts = raw.split('/');
    let (Some(a), Some(b), Some(y), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ParseError::BadDate);
    };
    let (Some(a), Some(b), Some(y)) = (two_digits(a), two_digits(b), two_digits(y)) else {
        return Err(ParseError::BadDate);
    };
    let (month, day) = match order {
        DateOrder::Mdy => (a, b),
        DateOrder::Dmy => (b, a),
    };
    let year = TWO_DIGIT_YEAR_BASE + u16::from(y);
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return Err(ParseError::BadDate);
    }
    Ok(PbxDate { year, month, day })
}

pub fn parse_time(raw: &str) -> Result<PbxTime, ParseError> {
    let (hh, rest) = raw.split_at_checked(2).ok_or(ParseError::BadTime)?;
    let (colon, rest) = rest.split_at_checked(1).ok_or(ParseError::BadTime)?;
    let (mm, ampm) = rest.split_at_checked(2).ok_or(ParseError::BadTime)?;
    let (Some(h12), Some(minute)) = (two_digits(hh), two_digits(mm)) else {
        return Err(ParseError::BadTime);
    };
    if colon != ":" || !(1..=12).contains(&h12) || minute > 59 {
        return Err(ParseError::BadTime);
    }
    let hour = match ampm {
        "AM" => h12 % 12,
        "PM" => h12 % 12 + 12,
        _ => return Err(ParseError::BadTime),
    };
    Ok(PbxTime { hour, minute })
}

fn parse_dial(area: &str) -> Result<(Direction, String, String), ParseError> {
    if let Some(rest) = area.strip_prefix("<I>") {
        let number = &rest[0..10];
        if !number.bytes().all(|b| b.is_ascii_digit()) || &rest[10..12] != "  " {
            return Err(ParseError::BadNumber);
        }
        Ok((
            Direction::Incoming,
            number.to_string(),
            rest[12..].trim().to_string(),
        ))
    } else {
        let number = area.trim_end();
        if number.is_empty()
            || number.starts_with(' ')
            || !number
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'*' || b == b'#')
        {
            return Err(ParseError::BadNumber);
        }
        Ok((Direction::Outgoing, number.to_string(), String::new()))
    }
}

fn parse_ring(raw: &str) -> Result<Option<u32>, ParseError> {
    if raw.is_empty() {
        return Ok(None);
    }
    let (m, s) = raw.split_once('\'').ok_or(ParseError::BadRing)?;
    let ss = two_digits(s).ok_or(ParseError::BadRing)?;
    if m.len() != 1 || !m.bytes().all(|b| b.is_ascii_digit()) || ss > 59 {
        return Err(ParseError::BadRing);
    }
    Ok(Some(u32::from(m.as_bytes()[0] - b'0') * 60 + u32::from(ss)))
}

fn parse_duration(raw: &str) -> Result<Option<u32>, ParseError> {
    if raw.is_empty() {
        return Ok(None);
    }
    let (hm, s) = raw.split_once('\'').ok_or(ParseError::BadDuration)?;
    let (h, m) = hm.split_once(':').ok_or(ParseError::BadDuration)?;
    let (Some(h), Some(m), Some(s)) = (two_digits(h), two_digits(m), two_digits(s)) else {
        return Err(ParseError::BadDuration);
    };
    if m > 59 || s > 59 {
        return Err(ParseError::BadDuration);
    }
    Ok(Some(u32::from(h) * 3600 + u32::from(m) * 60 + u32::from(s)))
}
