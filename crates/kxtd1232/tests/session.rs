//! Login state machine tests (ported from #1 tests/unit/test_session.py, plus the
//! line-length cap from Claude's review on #1).

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::error::LoginFailure;
use kxtd1232::session::{Login, LoginState, MAX_LINE, XON};

#[test]
fn test_happy_path() {
    let mut l = Login::new("1234").unwrap();
    assert_eq!(l.feed(&[0x13, XON]), b"\r\n");
    assert_eq!(l.feed(b"<SIGNON_BANNER>\r\nPassword:\r\n"), b"1234\r");
    assert_eq!(l.feed(b"<MODE_START>\r\n"), b"ECS OF\r\n");
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
        (b"<TERMINAL_IN_USE>\r\n", LoginFailure::AnotherTerminal),
        (b"Password:\r\n", LoginFailure::PasswordRejected),
    ];
    for (reply, why) in cases {
        let mut l = Login::new("1234").unwrap();
        l.feed(&[XON]);
        l.feed(b"Password:\r\n");
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

#[test]
fn test_total_line_cap_after_and_before_xon() {
    use kxtd1232::session::MAX_LINES;
    let mut l = Login::new("1234").unwrap();
    let mut v = vec![0x11];
    for _ in 0..=MAX_LINES {
        v.extend(b"x\r\n");
    }
    l.feed(&v);
    assert_eq!(
        l.state(),
        &LoginState::Failed(LoginFailure::TooManyLines { max: MAX_LINES })
    );
    let mut l = Login::new("1234").unwrap();
    for _ in 0..=MAX_LINES {
        l.feed(b"noise\r\n");
    }
    assert_eq!(
        l.state(),
        &LoginState::Failed(LoginFailure::TooManyLines { max: MAX_LINES })
    );
}

#[test]
fn test_signon_text_is_configurable() {
    use kxtd1232::SignOn;
    let s = SignOn {
        banner: "<B>".into(),
        password_prompt: "<P>".into(),
        mode_start: "<M>".into(),
        in_use: "<U>".into(),
    };
    let mut l = Login::with_signon("1234", s.clone()).unwrap();
    l.feed(&[0x11]);
    // The default placeholder prompt is not this deployment's prompt.
    assert_eq!(l.feed(b"Password:\r\n"), b"");
    assert_eq!(l.feed(b"<B>\r\n<P>\r\n"), b"1234\r");
    assert_eq!(l.feed(b"<M>\r\n"), b"ECS OF\r\n");
    let mut l = Login::with_signon("1234", s).unwrap();
    l.feed(&[0x11]);
    l.feed(b"xx <U> xx\r\n");
    assert_eq!(
        l.state(),
        &LoginState::Failed(LoginFailure::AnotherTerminal)
    );
}

#[test]
fn test_default_signon_matches_prototype_placeholders() {
    let s = kxtd1232::SignOn::default();
    assert_eq!(
        (
            s.banner.as_str(),
            s.password_prompt.as_str(),
            s.mode_start.as_str(),
            s.in_use.as_str()
        ),
        (
            "<SIGNON_BANNER>",
            "Password:",
            "<MODE_START>",
            "<TERMINAL_IN_USE>"
        )
    );
}

#[test]
fn test_plan_error_is_an_error_source() {
    use kxtd1232::error::PlanError;
    use std::error::Error as _;
    let e = kxtd1232::Error::Plan(PlanError::PatchOutsideImage);
    assert_eq!(
        e.source().unwrap().to_string(),
        PlanError::PatchOutsideImage.to_string()
    );
    let p = kxtd1232::Error::PreSend(Box::new(kxtd1232::Error::LineNotQuiet));
    assert!(p.source().is_some());
    assert!(kxtd1232::Error::Timeout.source().is_none());
}
