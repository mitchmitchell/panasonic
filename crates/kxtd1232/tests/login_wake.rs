#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::frame::Access;
use kxtd1232::session::{Login, LoginState, XON};
use kxtd1232::{Client, Error, ModemLines, SignOn, Timing, Transport, TransportError};
use std::collections::VecDeque;

const PROMPT: &str = "<FIXTURE_PROMPT>";
const MODE_START: &str = "<FIXTURE_MODE_START>";
const PASSWORD: &str = "<FIXTURE_PW>";
const LINES: ModemLines = ModemLines {
    dsr: Some(true),
    cts: Some(false),
    dcd: None,
};

fn fixture_signon() -> SignOn {
    SignOn {
        banner: "<FIXTURE_BANNER>".into(),
        password_prompt: PROMPT.into(),
        mode_start: MODE_START.into(),
        in_use: "<FIXTURE_IN_USE>".into(),
    }
}

fn greeting(xon: bool) -> Vec<u8> {
    let mut g = if xon { vec![XON] } else { Vec::new() };
    g.extend_from_slice(format!("<FIXTURE_BANNER>\r\n{PROMPT}\r\n").as_bytes());
    g
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Dtr,
    Xon,
    Sent(Vec<u8>),
}

struct ScriptedPbx {
    now: u64,
    dtr_control: bool,
    greets_on_dtr: bool,
    answers_crlf: bool,
    events: Vec<Event>,
    pending: VecDeque<Vec<u8>>,
}

impl ScriptedPbx {
    fn silent() -> Self {
        Self {
            now: 0,
            dtr_control: true,
            greets_on_dtr: false,
            answers_crlf: false,
            events: Vec::new(),
            pending: VecDeque::new(),
        }
    }

    fn crlfs(&self) -> usize {
        self.events
            .iter()
            .take_while(|e| **e != Event::Xon)
            .filter(|e| matches!(e, Event::Sent(d) if d.starts_with(b"\r\n")))
            .count()
    }

    fn dtr_cycles(&self) -> usize {
        self.events.iter().filter(|e| **e == Event::Dtr).count()
    }
}

impl Transport for ScriptedPbx {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.events.push(Event::Sent(data.to_vec()));
        let reply: Option<Vec<u8>> = match data {
            b"\r\n" => self.answers_crlf.then(|| greeting(false)),
            b"ECS OF\r\n" => Some(b"ECS OF\r\nOK\r\n".to_vec()),
            b"PRG\r\n" => Some(b"OK\r\n".to_vec()),
            d if d.ends_with(b"\r") => Some(format!("{MODE_START}\r\n").into_bytes()),
            _ => None,
        };
        if let Some(r) = reply {
            self.pending.push_back(r);
        }
        Ok(())
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        match self.pending.pop_front() {
            Some(b) => {
                if b.contains(&XON) {
                    self.events.push(Event::Xon);
                }
                Ok(b)
            }
            None => {
                self.now += timeout_ms;
                Err(TransportError::Timeout)
            }
        }
    }

    fn now_ms(&mut self) -> u64 {
        self.now
    }

    fn cycle_dtr(&mut self) -> Result<bool, TransportError> {
        if !self.dtr_control {
            return Ok(false);
        }
        self.events.push(Event::Dtr);
        if self.greets_on_dtr {
            self.pending.push_back(greeting(true));
        }
        Ok(true)
    }

    fn modem_lines(&mut self) -> ModemLines {
        LINES
    }
}

fn client(t: ScriptedPbx) -> Client<ScriptedPbx> {
    Client::with(t, Access::ReadOnly, Timing::default()).with_signon(fixture_signon())
}

#[test]
fn xon_on_open_needs_no_dtr_cycle_and_no_crlf() {
    let mut t = ScriptedPbx::silent();
    t.pending.push_back(greeting(true));
    let mut c = client(t);
    c.login(PASSWORD).unwrap();
    assert_eq!(c.transport().dtr_cycles(), 0);
    assert_eq!(c.transport().crlfs(), 0);
}

#[test]
fn fresh_dtr_cycle_that_yields_xon_sends_no_crlf() {
    let mut t = ScriptedPbx::silent();
    t.greets_on_dtr = true;
    let mut c = client(t);
    c.login(PASSWORD).unwrap();
    assert_eq!(c.transport().dtr_cycles(), 1);
    assert_eq!(c.transport().crlfs(), 0);
    let trace = c.login_trace().unwrap();
    assert!(trace.xon_seen && trace.dtr_cycled && !trace.wake_sent);
}

#[test]
fn one_crlf_only_after_a_silent_dtr_cycle() {
    let mut t = ScriptedPbx::silent();
    t.answers_crlf = true;
    let mut c = client(t);
    c.login(PASSWORD).unwrap();
    let events = &c.transport().events;
    assert_eq!(events[0], Event::Dtr);
    assert_eq!(events[1], Event::Sent(b"\r\n".to_vec()));
    assert_eq!(c.transport().crlfs(), 1);
}

#[test]
fn silent_line_gets_exactly_one_crlf_then_times_out_with_a_trace() {
    let mut c = client(ScriptedPbx::silent());
    assert!(matches!(c.login(PASSWORD), Err(Error::Timeout)));
    assert_eq!(c.transport().dtr_cycles(), 1);
    assert_eq!(c.transport().crlfs(), 1);
    assert_eq!(c.transport().events.len(), 2);
    let trace = c.login_trace().unwrap();
    assert_eq!(trace.bytes_received, 0);
    assert!(!trace.xon_seen);
    assert!(trace.dtr_cycled && trace.wake_sent);
    assert_eq!(trace.lines, LINES);
    assert!(!format!("{trace:?}").contains(PASSWORD));
}

#[test]
fn no_crlf_when_the_transport_cannot_cycle_dtr() {
    let mut t = ScriptedPbx::silent();
    t.dtr_control = false;
    let mut c = client(t);
    assert!(c.login(PASSWORD).is_err());
    assert!(c.transport().events.is_empty());
    let trace = c.login_trace().unwrap();
    assert!(!trace.dtr_cycled && !trace.wake_sent);
}

#[test]
fn trace_counts_bytes_and_xon_when_the_prompt_never_matches() {
    let mut t = ScriptedPbx::silent();
    t.pending.push_back(greeting(true));
    let mut c = Client::with(t, Access::ReadOnly, Timing::default());
    assert!(c.login(PASSWORD).is_err());
    assert!(!c
        .transport()
        .events
        .iter()
        .any(|e| matches!(e, Event::Sent(d) if d.ends_with(format!("{PASSWORD}\r").as_bytes()))));
    let trace = c.login_trace().unwrap();
    assert_eq!(trace.bytes_received, greeting(true).len());
    assert!(trace.xon_seen && !trace.dtr_cycled && !trace.wake_sent);
}

#[test]
fn wake_is_only_pending_before_xon() {
    let mut l = Login::with_signon(PASSWORD, fixture_signon()).unwrap();
    assert!(l.wake_pending());
    assert_eq!(l.feed(&[XON]), b"\r\n");
    assert_eq!(l.state(), &LoginState::WaitPrompt);
    assert!(!l.wake_pending());
    assert_eq!(l.wake(), b"");
}
