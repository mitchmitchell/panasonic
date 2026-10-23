//! Write allow-list and range guards (ported from #1 tests/unit/test_write_guards.py, plus
//! the range checks from Claude's review on #1).

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::error::NotAllowed;
use kxtd1232::frame::{Access, Encoder};
use kxtd1232::tables::{self, check_writable, check_writable_table, TABLES};
use kxtd1232::{build_plan, Error, Granularity};

#[test]
fn test_editable_is_caller_id_only() {
    assert_eq!(tables::EDITABLE_TABLES, [0x24, 0x25]);
}

#[test]
fn test_every_other_table_write_and_plan_refused() {
    let enc = Encoder::new(Access::ReadWrite);
    for t in 0u8..=0xFF {
        if t == 0x24 || t == 0x25 {
            continue;
        }
        assert!(check_writable_table(t).is_err(), "{t:#04x}");
        assert!(matches!(
            enc.write(t, 0, 0, &[0; 2]),
            Err(Error::NotAllowed(_))
        ));
        let size = tables::spec(t).map_or(2, |s| s.wire_bytes());
        assert!(build_plan(t, &vec![0; size], &[], Granularity::Table).is_err());
    }
}

#[test]
fn test_caller_id_writes_allowed() {
    let enc = Encoder::new(Access::ReadWrite);
    assert!(enc.write(0x24, 0, 0, &[0; 150]).is_ok());
    assert!(enc.write(0x25, 490, 0, &[0; 160]).is_ok());
}

#[test]
fn test_half_table_rule_message() {
    for s in TABLES.iter().filter(|s| s.id >= 0x40) {
        let e = check_writable_table(s.id).unwrap_err();
        assert_eq!(e, NotAllowed::HalfTable(s.id));
        assert!(e.to_string().contains("half-table rule"));
    }
}

#[test]
fn test_reads_and_decodes_of_other_tables_still_work() {
    let enc = Encoder::default();
    for s in TABLES.iter() {
        for (r, w, n) in s.frames() {
            assert!(enc.read(s.id, r, w, n).is_ok(), "{:#04x} {r} {w} {n}", s.id);
        }
    }
}

#[test]
fn test_write_range_checks() {
    assert_eq!(
        check_writable(0x24, 500, 0, 6),
        Err(NotAllowed::RecordOutOfRange {
            table: 0x24,
            record: 500,
            records: 500
        })
    );
    assert_eq!(
        check_writable(0x24, 499, 0, 12),
        Err(NotAllowed::SpanOutOfRange {
            table: 0x24,
            end: 3006,
            size: 3000
        })
    );
    assert!(matches!(
        check_writable(0x25, 0, 4000, 2),
        Err(NotAllowed::SpanOutOfRange { .. })
    ));
    assert!(check_writable(0x25, 499, 0, 16).is_ok());
    let enc = Encoder::new(Access::ReadWrite);
    assert!(enc.write(0x25, 0xFFFF, 0, &[0; 16]).is_err());
}
