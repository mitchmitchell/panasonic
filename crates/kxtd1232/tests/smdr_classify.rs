use std::path::PathBuf;

use kxtd1232::smdr::{
    classify, LineKind, LineSplitter, SmdrLine, LINE_WIDTH, MODEM_INIT_WIDTH, SPEC_HEADER,
};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/smdr-v1")
}

fn expected() -> serde_json::Value {
    let text = std::fs::read_to_string(fixture_dir().join("expected.json")).expect("expected.json");
    serde_json::from_str(&text).expect("valid json")
}

fn kind_name(kind: LineKind) -> &'static str {
    match kind {
        LineKind::Blank => "blank",
        LineKind::ModemInit => "modem_init",
        LineKind::Header => "header",
        LineKind::Rule => "rule",
        LineKind::Record => "record",
        LineKind::Unknown => "unknown",
    }
}

fn split_all(bytes: &[u8], chunk: usize) -> Vec<SmdrLine> {
    let mut s = LineSplitter::new();
    let mut out = Vec::new();
    for c in bytes.chunks(chunk.max(1)) {
        out.extend(s.push(c));
    }
    out.extend(s.finish());
    out
}

#[test]
fn every_v1_fixture_classifies_as_expected() {
    let exp = expected();
    let files = exp.as_object().expect("object");
    assert_eq!(files.len(), 11);
    for (name, spec) in files {
        let bytes = std::fs::read(fixture_dir().join(name)).expect("fixture");
        let want: Vec<&str> = spec["lines"]
            .as_array()
            .expect("lines")
            .iter()
            .map(|l| l["kind"].as_str().expect("kind"))
            .collect();
        for chunk in [1, 2, 3, 79, 80, 81, bytes.len()] {
            let lines = split_all(&bytes, chunk);
            let got: Vec<&str> = lines.iter().map(|l| kind_name(l.kind)).collect();
            assert_eq!(got, want, "{name} chunk {chunk}");
            for (line, l) in lines.iter().zip(spec["lines"].as_array().expect("lines")) {
                if let Some(len) = l["raw_len"].as_u64() {
                    assert_eq!(line.raw.len() as u64, len, "{name}");
                }
                if line.kind == LineKind::Record {
                    assert_eq!(line.raw.len(), LINE_WIDTH, "{name}");
                    assert_eq!(&line.raw[0..8], l["date"].as_str().expect("date"));
                }
            }
        }
    }
}

#[test]
fn eol_variants_yield_identical_lines() {
    let read = |n: &str| {
        split_all(
            &std::fs::read(fixture_dir().join(n)).expect("fixture"),
            4096,
        )
    };
    let crlf = read("eol_crlf.txt");
    assert_eq!(read("eol_lf.txt"), crlf);
    assert_eq!(read("eol_cr.txt"), crlf);
}

#[test]
fn page_header_title_matches_spec_and_block_is_skippable() {
    let lines = split_all(
        &std::fs::read(fixture_dir().join("page_header.txt")).expect("fixture"),
        4096,
    );
    assert_eq!(SPEC_HEADER.len(), LINE_WIDTH);
    assert!(lines[0].header_matches_spec());
    assert!(lines.iter().all(|l| l.kind.is_page_header()));
    assert!(!LineKind::Record.is_page_header());
    assert!(!LineKind::Unknown.is_page_header());
}

#[test]
fn shifted_header_is_header_but_not_spec() {
    let line = SmdrLine::new(" Date Time Ext CO Dial".to_string());
    assert_eq!(line.kind, LineKind::Header);
    assert!(!line.header_matches_spec());
}

#[test]
fn modem_init_is_recognised() {
    let init = "AT".to_string() + &"0".repeat(MODEM_INIT_WIDTH - 2);
    assert_eq!(classify(&init), LineKind::ModemInit);
}

#[test]
fn record_prefix_without_full_width_is_unknown() {
    let rec = std::fs::read_to_string(fixture_dir().join("outgoing.txt")).expect("fixture");
    let rec = rec.trim_end_matches(['\r', '\n']);
    assert_eq!(classify(rec), LineKind::Record);
    assert_eq!(classify(&rec[..79]), LineKind::Unknown);
    assert_eq!(classify(&format!("{rec} ")), LineKind::Unknown);
}

#[test]
fn near_miss_lines_are_unknown() {
    assert_eq!(classify("---------"), LineKind::Unknown);
    assert_eq!(
        classify(&format!("{:<80}", "10-23-26 01:05PM")),
        LineKind::Unknown
    );
    assert_eq!(
        classify(&format!("{:<80}", "10/23/26 01:05XM")),
        LineKind::Unknown
    );
    assert_eq!(
        classify(&format!("{:<80}", "10/23/26 1:05PM")),
        LineKind::Unknown
    );
    assert_eq!(classify("   \t "), LineKind::Blank);
}

#[test]
fn crlf_is_one_terminator_but_double_cr_or_lf_is_a_blank_line() {
    let kinds: Vec<LineKind> = split_all(b"a\r\rb\n\nc\r\n\r\nd\r\n", 4096)
        .into_iter()
        .map(|l| l.kind)
        .collect();
    use LineKind::{Blank, Unknown};
    assert_eq!(
        kinds,
        [Unknown, Blank, Unknown, Blank, Unknown, Blank, Unknown]
    );
}

#[test]
fn control_bytes_are_stripped_and_high_bytes_kept_lossy() {
    let rec = std::fs::read(fixture_dir().join("outgoing.txt")).expect("fixture");
    let mut bytes = vec![0x0C, 0x00, 0x11];
    bytes.extend_from_slice(&rec[..40]);
    bytes.push(0x13);
    bytes.extend_from_slice(&rec[40..]);
    bytes.extend_from_slice(b"x\xFFy\r\n");
    let lines = split_all(&bytes, 4096);
    assert_eq!(lines[0].kind, LineKind::Record);
    assert_eq!(lines[1].raw, "x\u{FFFD}y");
    assert_eq!(lines[1].kind, LineKind::Unknown);
}

#[test]
fn unterminated_tail_is_kept_by_finish() {
    let mut s = LineSplitter::new();
    assert!(s.push(b"partial").is_empty());
    let tail = s.finish().expect("tail kept");
    assert_eq!(tail.raw, "partial");
    assert_eq!(tail.kind, LineKind::Unknown);
    assert!(s.finish().is_none());
}

#[test]
fn no_input_panics_and_no_payload_byte_is_lost() {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..2000 {
        let mut bytes = Vec::new();
        for _ in 0..(x % 300) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            bytes.push(x.to_le_bytes()[0]);
        }
        let lines = split_all(&bytes, (x % 17) as usize + 1);
        let kept: usize = lines.iter().map(|l| l.raw.chars().count()).sum();
        let payload = bytes
            .iter()
            .filter(|b| !matches!(b, 0x00 | 0x11 | 0x13 | 0x0C | b'\r' | b'\n'))
            .count();
        assert_eq!(kept, payload);
        for l in &lines {
            assert_eq!(l.kind, classify(&l.raw));
        }
    }
}
