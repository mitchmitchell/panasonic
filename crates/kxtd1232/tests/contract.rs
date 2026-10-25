//! Contract tests against Reverse Engineer's synthetic fixtures (tests/fixtures/).

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::error::NotAllowed;
use kxtd1232::frame::{checksum, classify, Encoder, ReplyKind};
use kxtd1232::tables::{self, TABLES};
use kxtd1232::Error;
use serde_json::Value;

fn lines(name: &str) -> Vec<Value> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|h| u8::from_str_radix(h, 16).unwrap())
        .collect()
}

fn exchange(step: u64) -> Vec<u8> {
    let v = lines("exchanges.jsonl");
    hex(v[step as usize]["data"].as_str().unwrap())
}

#[test]
fn test_table_spec_matches_full_upload_headers() {
    let headers = lines("full-upload-headers.jsonl");
    let mut expected = Vec::new();
    for s in TABLES.iter() {
        for (rec, word, nwords) in s.frames() {
            expected.push((s.id, rec, word, 2 * nwords as u64));
        }
    }
    assert_eq!(expected.len(), 288);
    for (i, (t, r, w, n)) in expected.iter().enumerate() {
        let h = &headers[i];
        let table = u8::from_str_radix(&h["table"].as_str().unwrap()[2..], 16).unwrap();
        assert_eq!(
            (
                table,
                h["record"].as_u64().unwrap(),
                h["word"].as_u64().unwrap(),
                h["payload_len"].as_u64().unwrap()
            ),
            (*t, u64::from(*r), u64::from(*w), *n),
            "frame {i}"
        );
        let hdr = hex(h["header_hex"].as_str().unwrap());
        assert_eq!(hdr[0] as u64, 8 + n, "LEN of frame {i}");
        assert_eq!(hdr[2], *t);
        assert_eq!(u16::from_be_bytes([hdr[3], hdr[4]]), *r);
        assert_eq!(u16::from_be_bytes([hdr[5], hdr[6]]), *w);
    }
}

#[test]
fn test_table_spec_internal_consistency() {
    let mut prev = 0u8;
    let mut total = 0usize;
    for s in TABLES.iter() {
        assert!(s.id > prev || prev == 0, "ascending");
        prev = s.id;
        assert_eq!(s.record_bytes % 2, 0);
        if s.record_bytes / 2 <= u16::from(s.words_per_frame) {
            assert_eq!(
                s.records_per_frame * s.record_bytes / 2,
                u16::from(s.words_per_frame),
                "{:#04x}",
                s.id
            );
        }
        assert!(!tables::NEVER_WRITTEN.contains(&s.id));
        total += s.wire_bytes();
    }
    // Sum of the Wire B column.
    assert_eq!(total, TABLES.iter().map(|s| s.wire_bytes()).sum::<usize>());
    assert_eq!(tables::spec(0x24).unwrap().wire_bytes(), 3000);
    assert_eq!(tables::spec(0x25).unwrap().wire_bytes(), 8000);
    assert_eq!(tables::spec(0xC3).unwrap().wire_bytes(), 8000);
}

#[test]
fn test_exchange_requests_match_encoder() {
    let e = Encoder::default();
    assert_eq!(exchange(8), e.version_probe());
    assert_eq!(exchange(10), e.status_probe());
    assert_eq!(exchange(12), e.read(0x06, 0, 0, 3).unwrap());
    assert_eq!(exchange(26), e.end_binary());
}

#[test]
fn test_exchange_replies_classify() {
    assert_eq!(classify(&exchange(11)).unwrap().kind, ReplyKind::Status(3));
    assert_eq!(
        classify(&exchange(13)).unwrap().kind,
        ReplyKind::Data(vec![1, 2, 3, 4, 5, 6])
    );
    assert_eq!(classify(&exchange(15)).unwrap().kind, ReplyKind::Nak(2));
    assert_eq!(classify(&exchange(17)).unwrap().kind, ReplyKind::Refused);
    assert_eq!(classify(&exchange(19)).unwrap().kind, ReplyKind::Ack);
    assert_eq!(classify(&exchange(21)).unwrap().kind, ReplyKind::Nak(2));
    assert_eq!(classify(&exchange(27)).unwrap().kind, ReplyKind::Ack);
    // The deliberately broken requests really carry checksum + 1.
    for step in [14, 20] {
        let f = exchange(step);
        assert_eq!(f[f.len() - 1], checksum(&f[..f.len() - 1]).wrapping_add(1));
    }
}

#[test]
fn test_reads_past_first_half_refused() {
    // Step 16: reading 0x40 record 1 (past the first-cabinet half) is refused by the PBX;
    // the encoder refuses to build it at all.
    let f = exchange(16);
    assert_eq!(&f[2..5], &[0x40, 0x00, 0x01]);
    assert_eq!(
        Encoder::default().read(0x40, 1, 0, 1),
        Err(Error::NotAllowed(NotAllowed::RecordOutOfRange {
            table: 0x40,
            record: 1,
            records: 1
        }))
    );
    for s in TABLES.iter().filter(|s| s.id >= 0x40) {
        assert!(
            Encoder::default().read(s.id, s.records, 0, 1).is_err(),
            "{:#04x}",
            s.id
        );
        assert!(
            Encoder::default().read(s.id, s.records - 1, 0, 1).is_ok(),
            "{:#04x}",
            s.id
        );
    }
}

#[test]
fn test_unknown_tables_refused() {
    for t in tables::NEVER_WRITTEN {
        assert_eq!(
            Encoder::default().read(t, 0, 0, 1),
            Err(Error::NotAllowed(NotAllowed::UnknownTable(t)))
        );
    }
}
