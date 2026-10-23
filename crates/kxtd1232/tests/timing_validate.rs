#![allow(clippy::unwrap_used, clippy::field_reassign_with_default)]

use kxtd1232::{Timing, MAX_LINK_BAUD, MIN_REPLY_GUARD_MS};

#[test]
fn default_timing_passes_validate() {
    Timing::default().validate().unwrap();
}

#[test]
fn zero_reply_guard_rejected() {
    let mut t = Timing::default();
    t.reply_guard_ms = 0;
    assert_eq!(
        t.validate().unwrap_err().to_string(),
        format!("reply_guard_ms must be at least {MIN_REPLY_GUARD_MS} ms")
    );
}

#[test]
fn high_baud_with_zero_guard_would_shrink_cutoff() {
    let mut t = Timing::default();
    t.link_baud = MAX_LINK_BAUD;
    t.reply_guard_ms = 0;
    assert!(t.validate().is_err());
    t.reply_guard_ms = MIN_REPLY_GUARD_MS;
    let cut = t.reply_cutoff_ms(25);
    assert!(
        cut >= MIN_REPLY_GUARD_MS,
        "cutoff must include at least the guard margin"
    );
}

#[test]
fn baud_above_max_rejected() {
    let mut t = Timing::default();
    t.link_baud = MAX_LINK_BAUD + 1;
    assert!(t.validate().is_err());
}
