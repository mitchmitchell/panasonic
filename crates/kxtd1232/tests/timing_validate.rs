use kxtd1232::{Timing, MAX_LINK_BAUD, MIN_REPLY_GUARD_MS};

#[test]
fn default_timing_passes_validate() {
    assert!(Timing::default().validate().is_ok());
}

#[test]
fn zero_reply_guard_rejected() {
    let t = Timing {
        reply_guard_ms: 0,
        ..Timing::default()
    };
    let err = match t.validate() {
        Err(e) => e,
        Ok(_) => panic!("expected validate to fail for zero reply_guard_ms"),
    };
    assert_eq!(
        err.to_string(),
        format!("reply_guard_ms must be at least {MIN_REPLY_GUARD_MS} ms")
    );
}

#[test]
fn high_baud_with_zero_guard_would_shrink_cutoff() {
    let t_bad = Timing {
        link_baud: MAX_LINK_BAUD,
        reply_guard_ms: 0,
        ..Timing::default()
    };
    assert!(t_bad.validate().is_err());
    let t = Timing {
        link_baud: MAX_LINK_BAUD,
        ..Timing::default()
    };
    let cut = t.reply_cutoff_ms(25);
    assert!(
        cut >= MIN_REPLY_GUARD_MS,
        "cutoff must include at least the guard margin"
    );
}

#[test]
fn baud_above_max_rejected() {
    let t = Timing {
        link_baud: MAX_LINK_BAUD + 1,
        ..Timing::default()
    };
    assert!(t.validate().is_err());
}
