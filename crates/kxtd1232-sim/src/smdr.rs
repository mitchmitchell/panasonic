use kxtd1232::smdr::{LINE_WIDTH, SPEC_HEADER};
use std::collections::VecDeque;

// https://github.com/mitchmitchell/panasonic/issues/14
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferPolicy {
    ReplayAfterBye,
    Drop,
}

// https://github.com/mitchmitchell/panasonic/issues/11
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LineEnding {
    #[default]
    CrLf,
    Cr,
}

impl LineEnding {
    fn bytes(self) -> &'static [u8] {
        match self {
            LineEnding::CrLf => b"\r\n",
            LineEnding::Cr => b"\r",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyntheticCall {
    pub date: String,
    pub time: String,
    pub ext: String,
    pub co: String,
    pub incoming: bool,
    pub number: String,
    pub cid_name: String,
    pub ring: String,
    pub duration: String,
    pub acc_code: String,
    pub cd: String,
}

impl SyntheticCall {
    pub fn to_line(&self) -> Result<String, SyntheticCallError> {
        let dial = if self.incoming {
            format!("<I>{:<10}  {}", self.number, self.cid_name)
        } else {
            self.number.clone()
        };
        for (field, text, max) in [
            ("date", self.date.as_str(), 8),
            ("time", self.time.as_str(), 7),
            ("ext", self.ext.as_str(), 3),
            ("co", self.co.as_str(), 2),
            ("dial", dial.as_str(), 26),
            ("ring", self.ring.as_str(), 4),
            ("duration", self.duration.as_str(), 8),
            ("acc_code", self.acc_code.as_str(), 10),
            ("cd", self.cd.as_str(), 2),
        ] {
            if text.len() > max || !text.is_ascii() || text.contains(['\r', '\n']) {
                return Err(SyntheticCallError { field, max });
            }
        }
        if self.incoming && self.number.len() != 10 {
            return Err(SyntheticCallError {
                field: "number",
                max: 10,
            });
        }
        Ok(format!(
            "{:<8} {:<7}   {:>3} {:<2} {:<26}{:>4} {:>8}  {:<10}{:<2} ",
            self.date,
            self.time,
            self.ext,
            self.co,
            dial,
            self.ring,
            self.duration,
            self.acc_code,
            self.cd,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntheticCallError {
    pub field: &'static str,
    pub max: usize,
}

impl std::fmt::Display for SyntheticCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "synthetic field {} must be at most {} ASCII bytes",
            self.field, self.max
        )
    }
}

impl std::error::Error for SyntheticCallError {}

#[derive(Debug)]
pub struct SmdrEmitter {
    policy: BufferPolicy,
    ending: LineEnding,
    programming: bool,
    pending: VecDeque<String>,
    dropped: usize,
    out: Vec<u8>,
}

impl SmdrEmitter {
    #[must_use]
    pub fn new(policy: BufferPolicy, ending: LineEnding) -> Self {
        Self {
            policy,
            ending,
            programming: false,
            pending: VecDeque::new(),
            dropped: 0,
            out: Vec::new(),
        }
    }

    #[must_use]
    pub fn is_programming(&self) -> bool {
        self.programming
    }

    #[must_use]
    pub fn dropped(&self) -> usize {
        self.dropped
    }

    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    // https://github.com/mitchmitchell/panasonic/issues/13
    pub fn page_header(&mut self) {
        let rule = "-".repeat(LINE_WIDTH);
        for line in [SPEC_HEADER, rule.as_str(), ""] {
            self.print(line);
        }
    }

    pub fn call_ended(&mut self, call: &SyntheticCall) -> Result<(), SyntheticCallError> {
        let line = call.to_line()?;
        match (self.programming, self.policy) {
            (false, _) => self.print(&line),
            (true, BufferPolicy::ReplayAfterBye) => self.pending.push_back(line),
            (true, BufferPolicy::Drop) => self.dropped += 1,
        }
        Ok(())
    }

    pub fn begin_programming(&mut self) {
        self.programming = true;
    }

    pub fn end_programming(&mut self) {
        self.programming = false;
        while let Some(line) = self.pending.pop_front() {
            self.print(&line);
        }
    }

    #[must_use]
    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    fn print(&mut self, line: &str) {
        self.out.extend_from_slice(line.as_bytes());
        self.out.extend_from_slice(self.ending.bytes());
    }
}
