use std::path::PathBuf;

use kxtd1232::smdr::{
    parse_date, parse_line, parse_record, parse_time, DateOrder, Direction, LineKind, LineSplitter,
    ParseError, ParsedLine, PbxDate, PbxTime, SmdrLine, TWO_DIGIT_YEAR_BASE,
};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/smdr-v1")
}

fn read_lines(name: &str) -> Vec<SmdrLine> {
    let bytes = std::fs::read(fixture_dir().join(name)).expect("fixture");
    let mut s = LineSplitter::new();
    let mut out = s.push(&bytes);
    out.extend(s.finish());
    out
}

fn outgoing_line() -> String {
    read_lines("outgoing.txt").remove(0).into_raw()
}

#[test]
fn every_v1_fixture_parses_to_expected_json() {
    let text = std::fs::read_to_string(fixture_dir().join("expected.json")).expect("json");
    let exp: serde_json::Value = serde_json::from_str(&text).expect("valid json");
    let mut records = 0;
    for (name, spec) in exp.as_object().expect("object") {
        let want = spec["lines"].as_array().expect("lines");
        let lines = read_lines(name);
        assert_eq!(lines.len(), want.len(), "{name}");
        for (line, w) in lines.into_iter().zip(want) {
            let s = |k: &str| w[k].as_str().expect(k).to_string();
            match (
                w["kind"].as_str().expect("kind"),
                parse_line(line, DateOrder::Mdy),
            ) {
                ("record", ParsedLine::Record { record: r, .. }) => {
                    records += 1;
                    assert_eq!(r.date_raw, s("date"), "{name}");
                    assert_eq!(r.time_raw, s("time"), "{name}");
                    assert_eq!(r.ext, s("ext"), "{name}");
                    assert_eq!(r.co, s("co"), "{name}");
                    let dir = match r.direction {
                        Direction::Incoming => "incoming",
                        Direction::Outgoing => "outgoing",
                    };
                    assert_eq!(dir, s("direction"), "{name}");
                    assert_eq!(r.number, s("number"), "{name}");
                    assert_eq!(r.cid_name, s("cid_name"), "{name}");
                    assert_eq!(r.ring_raw, s("ring"), "{name}");
                    assert_eq!(r.duration_raw, s("duration"), "{name}");
                    assert_eq!(r.acc_code, s("acc_code"), "{name}");
                    assert_eq!(r.cd, s("cd"), "{name}");
                    assert_eq!(r.ring_s.is_some(), !r.ring_raw.is_empty());
                    assert_eq!(r.duration_s.is_some(), !r.duration_raw.is_empty());
                }
                ("header" | "rule" | "blank", ParsedLine::PageHeader(_)) => {}
                ("unknown", ParsedLine::Unparsed { line, error }) => {
                    assert_eq!(w["parse_ok"].as_bool(), Some(false));
                    assert_eq!(
                        line.raw().len() as u64,
                        w["raw_len"].as_u64().expect("raw_len")
                    );
                    assert_eq!(error, ParseError::NotRecord(LineKind::Unknown));
                }
                (k, got) => panic!("{name}: expected {k}, got {got:?}"),
            }
        }
    }
    assert_eq!(records, 16);
}

#[test]
fn parsed_values_for_incoming_answered_call() {
    let line = read_lines("incoming_cid.txt").remove(0);
    let r = parse_record(line.raw(), DateOrder::Mdy).expect("record");
    assert_eq!(
        r.date,
        PbxDate {
            year: 2026,
            month: 10,
            day: 23
        }
    );
    assert_eq!(
        r.time,
        PbxTime {
            hour: 13,
            minute: 12
        }
    );
    assert_eq!(r.ring_s, Some(7));
    assert_eq!(r.duration_s, Some(41));
    assert_eq!(r.direction, Direction::Incoming);
}

#[test]
fn outgoing_duration_in_seconds() {
    let r = parse_record(&outgoing_line(), DateOrder::Mdy).expect("record");
    assert_eq!(r.duration_s, Some(2 * 60 + 14));
    assert_eq!(r.ring_s, None);
    assert_eq!(r.direction, Direction::Outgoing);
}

#[test]
fn date_order_is_configurable_and_years_pivot_to_full_dates() {
    assert_eq!(TWO_DIGIT_YEAR_BASE, 2000);
    assert_eq!(
        parse_date("03/04/26", DateOrder::Mdy),
        Ok(PbxDate {
            year: 2026,
            month: 3,
            day: 4
        })
    );
    assert_eq!(
        parse_date("03/04/26", DateOrder::Dmy),
        Ok(PbxDate {
            year: 2026,
            month: 4,
            day: 3
        })
    );
    assert_eq!(
        parse_date("01/01/00", DateOrder::Mdy),
        Ok(PbxDate {
            year: 2000,
            month: 1,
            day: 1
        })
    );
    assert_eq!(
        parse_date("12/31/99", DateOrder::Mdy),
        Ok(PbxDate {
            year: 2099,
            month: 12,
            day: 31
        })
    );
    assert_eq!(
        parse_date("10/23/26", DateOrder::Dmy),
        Err(ParseError::BadDate)
    );
    assert_eq!(
        parse_date("02/29/28", DateOrder::Mdy).map(|d| d.day),
        Ok(29)
    );
    assert_eq!(
        parse_date("02/29/26", DateOrder::Mdy),
        Err(ParseError::BadDate)
    );
    assert_eq!(
        parse_date("02/29/00", DateOrder::Mdy).map(|d| d.day),
        Ok(29)
    );
    for bad in [
        "00/10/26", "13/10/26", "10/00/26", "1/10/26 ", "10-10-26", "aa/bb/cc",
    ] {
        assert_eq!(
            parse_date(bad, DateOrder::Mdy),
            Err(ParseError::BadDate),
            "{bad}"
        );
    }
}

#[test]
fn record_whose_date_fails_for_the_order_is_kept_unparsed() {
    let line = SmdrLine::new(outgoing_line());
    match parse_line(line.clone(), DateOrder::Dmy) {
        ParsedLine::Unparsed { line: kept, error } => {
            assert_eq!(kept, line);
            assert_eq!(error, ParseError::BadDate);
        }
        other => panic!("expected unparsed, got {other:?}"),
    }
}

#[test]
fn twelve_hour_clock_converts_to_24_hour() {
    assert_eq!(parse_time("12:00AM"), Ok(PbxTime { hour: 0, minute: 0 }));
    assert_eq!(
        parse_time("12:30PM"),
        Ok(PbxTime {
            hour: 12,
            minute: 30
        })
    );
    assert_eq!(
        parse_time("01:05PM"),
        Ok(PbxTime {
            hour: 13,
            minute: 5
        })
    );
    assert_eq!(
        parse_time("11:59PM"),
        Ok(PbxTime {
            hour: 23,
            minute: 59
        })
    );
    for bad in ["00:10AM", "13:00PM", "10:60AM", "10:10XM", "1010AM", ""] {
        assert_eq!(parse_time(bad), Err(ParseError::BadTime), "{bad}");
    }
}

fn with(line: &str, col: usize, text: &str) -> String {
    let mut s = line.to_string();
    s.replace_range(col..col + text.len(), text);
    s
}

#[test]
fn malformed_fields_are_rejected_not_guessed() {
    let base = outgoing_line();
    let incoming = read_lines("incoming_cid.txt").remove(0).into_raw();
    let cases = [
        (
            with(&base, 8, "x"),
            ParseError::NotRecord(LineKind::Unknown),
        ),
        (with(&base, 17, "x"), ParseError::BadSeparator(17)),
        (with(&base, 56, "x"), ParseError::BadSeparator(56)),
        (with(&base, 19, "1x1"), ParseError::BadExt),
        (with(&base, 19, "10 "), ParseError::BadExt),
        (with(&base, 23, "0x"), ParseError::BadCo),
        (with(&base, 26, " 555"), ParseError::BadNumber),
        (with(&base, 26, "55a"), ParseError::BadNumber),
        (with(&base, 52, "0'7x"), ParseError::BadRing),
        (with(&base, 52, "0'75"), ParseError::BadRing),
        (with(&base, 57, "00:61'00"), ParseError::BadDuration),
        (with(&base, 57, "0002'140"), ParseError::BadDuration),
        (with(&base, 77, "*!"), ParseError::BadCd),
        (with(&incoming, 29, "55598x0000"), ParseError::BadNumber),
        (with(&incoming, 39, "X"), ParseError::BadNumber),
        (with(&base, 0, "10/32/26"), ParseError::BadDate),
        (with(&base, 9, "13:05PM"), ParseError::BadTime),
    ];
    for (line, want) in cases {
        assert_eq!(parse_record(&line, DateOrder::Mdy), Err(want), "{line:?}");
    }
}

#[test]
fn cd_is_kept_raw_even_when_unmapped() {
    let line = read_lines("transfer_cd.txt").remove(0).into_raw();
    let r = parse_record(&with(&line, 77, "Q9"), DateOrder::Mdy).expect("record");
    assert_eq!(r.cd, "Q9");
}

#[test]
fn page_header_and_modem_init_are_skipped_not_parsed() {
    for line in read_lines("page_header.txt") {
        assert!(matches!(
            parse_line(line, DateOrder::Mdy),
            ParsedLine::PageHeader(_)
        ));
    }
    let init = SmdrLine::new("ATQ0E0V1X0S0=0&D0".to_string());
    assert!(matches!(
        parse_line(init, DateOrder::Mdy),
        ParsedLine::ModemInit(_)
    ));
}

#[test]
fn parse_never_panics_on_random_ascii_80_column_lines() {
    let mut x: u64 = 0xD1B5_4A32_D192_ED03;
    let base = outgoing_line().into_bytes();
    for _ in 0..5000 {
        let mut b = base.clone();
        for _ in 0..(x % 6) + 1 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let col = (x % 80) as usize;
            b[col] = 0x20 + ((x >> 8) % 95) as u8;
        }
        let line = SmdrLine::new(String::from_utf8(b).expect("ascii"));
        for order in [DateOrder::Mdy, DateOrder::Dmy] {
            let _ = parse_line(line.clone(), order);
        }
    }
}
