//! Login state machine tests (ported from #1 tests/unit/test_session.py, plus the
//! line-length cap from Claude's review on #1).

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::error::LoginFailure;
use kxtd1232::session::{Login, LoginState, MAX_LINE, XON};

#[test]
fn test_happy_path() {
    let mut l = Login::new("1234").unwrap();
    assert_eq!(l.feed(&[0x13, XON]), b"\r\n");
    assert_eq!(
        l.feed(b"Welcome To KX-TD1232  Ver 2.0 Panasonic CO.,LTD.\r\nEnter Password\r\n"),
        b"1234\r"
    );
    assert_eq!(l.feed(b"EIA Mode Start\r\n"), b"ECS OF\r\n");
    assert_eq!(l.feed(b"ECS OF\r\nOK\r\n"), b"PRG\r\n");
    assert_eq!(l.feed(b"OK\r\n"), b"");
    assert_eq!(l.state(), &LoginState::Binary);
}

#[test]
fn test_crlf_only_after_xon() {
    let mut l = Login::new("1234").unwrap();
    assert_eq!(l.feed(&[0x13]), b"");
    assert_eq!(l.state(), &LoginState::WaitXon);
    assert_eq!(l.feed(&[XON]), b"\r\n");
    assert_eq!(l.feed(&[XON]), b"");
}

#[test]
fn test_failures() {
    let cases: [(&[u8], LoginFailure); 3] = [
        (b"NG\r\n", LoginFailure::Ng),
        (
            b"Another Terminal Connected\r\n",
            LoginFailure::AnotherTerminal,
        ),
        (b"Enter Password\r\n", LoginFailure::PasswordRejected),
    ];
    for (reply, why) in cases {
        let mut l = Login::new("1234").unwrap();
        l.feed(&[XON]);
        l.feed(b"Enter Password\r\n");
        l.feed(reply);
        assert_eq!(l.state(), &LoginState::Failed(why));
    }
    assert_eq!(Login::new("").unwrap_err(), LoginFailure::InvalidPassword);
    assert_eq!(
        Login::new("a\rb").unwrap_err(),
        LoginFailure::InvalidPassword
    );
}

#[test]
fn test_repr_hides_password() {
    let l = Login::new("s3cr3t").unwrap();
    assert!(!format!("{l:?}").contains("s3cr3t"));
}

#[test]
fn test_login_line_length_capped() {
    let mut l = Login::new("1234").unwrap();
    l.feed(&[XON]);
    l.feed(&vec![b'A'; MAX_LINE + 1]);
    assert_eq!(
        l.state(),
        &LoginState::Failed(LoginFailure::LineTooLong { max: MAX_LINE })
    );
    // A long line delivered with its newline in one chunk is also refused.
    let mut l = Login::new("1234").unwrap();
    l.feed(&[XON]);
    let mut long = vec![b'B'; MAX_LINE + 5];
    long.extend_from_slice(b"\r\n");
    l.feed(&long);
    assert!(matches!(
        l.state(),
        LoginState::Failed(LoginFailure::LineTooLong { .. })
    ));
}
