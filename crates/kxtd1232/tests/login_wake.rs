#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::frame::Access;
use kxtd1232::session::{Login, LoginState, XON};
use kxtd1232::{Client, Error, SignOn, Timing, Transport, TransportError};
use std::collections::VecDeque;

const PROMPT: &str = "<FIXTURE_PROMPT>";
const MODE_START: &str = "<FIXTURE_MODE_START>";

fn fixture_signon() -> SignOn {
    SignOn {
        banner: "<FIXTURE_BANNER>".into(),
        password_prompt: PROMPT.into(),
        mode_start: MODE_START.into(),
        in_use: "<FIXTURE_IN_USE>".into(),
    }
}

struct SilentUntilWoken {
    now: u64,
    wakes_needed: usize,
    wakes_seen: usize,
    sent: Vec<Vec<u8>>,
    pending: VecDeque<Vec<u8>>,
}

impl SilentUntilWoken {
    fn new(wakes_needed: usize) -> Self {
        Self {
            now: 0,
            wakes_needed,
            wakes_seen: 0,
            sent: Vec::new(),
            pending: VecDeque::new(),
        }
    }

    fn wakes_sent(&self) -> usize {
        self.sent.iter().filter(|s| s.as_slice() == b"\r\n").count()
    }
}

impl Transport for SilentUntilWoken {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.sent.push(data.to_vec());
        let reply: Option<String> = match data {
            b"\r\n" => {
                self.wakes_seen += 1;
                (self.wakes_seen == self.wakes_needed)
                    .then(|| format!("<FIXTURE_BANNER>\r\n{PROMPT}\r\n"))
            }
            b"ECS OF\r\n" => Some("ECS OF\r\nOK\r\n".into()),
            b"PRG\r\n" => Some("OK\r\n".into()),
            d if d.ends_with(b"\r") => Some(format!("{MODE_START}\r\n")),
            _ => None,
        };
        if let Some(r) = reply {
            self.pending.push_back(r.into_bytes());
        }
        Ok(())
    }

    fn recv(&mut self, timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        match self.pending.pop_front() {
            Some(b) => Ok(b),
            None => {
                self.now += timeout_ms;
                Err(TransportError::Timeout)
            }
        }
    }

    fn now_ms(&mut self) -> u64 {
        self.now
    }
}

fn client(t: SilentUntilWoken) -> Client<SilentUntilWoken> {
    Client::with(t, Access::ReadOnly, Timing::default()).with_signon(fixture_signon())
}

#[test]
fn silent_line_is_woken_and_login_completes() {
    let mut c = client(SilentUntilWoken::new(2));
    c.login("1234").unwrap();
    assert_eq!(c.transport().wakes_sent(), 2);
    assert_eq!(c.transport().now, 2 * Timing::default().wake_interval_ms);
}

#[test]
fn wakes_are_bounded_then_login_times_out() {
    let attempts = Timing::default().wake_attempts as usize;
    let mut c = client(SilentUntilWoken::new(attempts + 1));
    assert!(matches!(c.login("1234"), Err(Error::Timeout)));
    assert_eq!(c.transport().wakes_sent(), attempts);
}

#[test]
fn placeholder_signon_does_not_match_deployment_prompt() {
    let mut c = Client::with(
        SilentUntilWoken::new(1),
        Access::ReadOnly,
        Timing::default(),
    );
    assert!(c.login("1234").is_err());
    assert!(!c.transport().sent.iter().any(|s| s.as_slice() == b"1234\r"));
}

#[test]
fn wake_is_a_noop_once_the_prompt_was_seen() {
    let mut l = Login::with_signon("1234", fixture_signon()).unwrap();
    assert!(l.wake_pending());
    assert_eq!(l.wake(), b"\r\n");
    assert_eq!(l.state(), &LoginState::WaitPrompt);
    assert_eq!(l.feed(format!("{PROMPT}\r\n").as_bytes()), b"1234\r");
    assert!(!l.wake_pending());
    assert_eq!(l.wake(), b"");
    assert_eq!(l.state(), &LoginState::WaitEia);
}

#[test]
fn xon_after_a_wake_does_not_send_a_second_crlf() {
    let mut l = Login::with_signon("1234", fixture_signon()).unwrap();
    assert_eq!(l.wake(), b"\r\n");
    assert_eq!(l.feed(&[XON]), b"");
    assert_eq!(l.state(), &LoginState::WaitPrompt);
}
