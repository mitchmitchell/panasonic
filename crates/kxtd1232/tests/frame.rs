//! Frame codec tests (ported from #1 tests/unit/test_frame.py).

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::error::{FrameError, NotAllowed};
use kxtd1232::frame::{
    checksum, classify, decode, Access, Cmd, Encoder, ReplyKind, MAX_READ_WORDS,
};
use kxtd1232::Error;

fn rw() -> Encoder {
    Encoder::new(Access::ReadWrite)
}

#[test]
fn test_checksum_and_encode_probe() {
    assert_eq!(checksum(&[0x03, 0x08, 0x00]), 0x0B);
    assert_eq!(
        Encoder::default().version_probe(),
        vec![0x03, 0x08, 0x00, 0x0B]
    );
    assert_eq!(
        Encoder::default().status_probe(),
        vec![0x03, 0x08, 0x01, 0x0C]
    );
}

#[test]
fn test_requests_match_spec() {
    let e = Encoder::default();
    assert_eq!(e.end_binary(), vec![0x02, 0x0B, 0x0D]);
    assert_eq!(e.clock(), vec![0x02, 0x03, 0x05]);
    assert_eq!(
        e.read(0x06, 0, 0, 3).unwrap(),
        vec![0x08, 0x01, 0x06, 0, 0, 0, 0, 0x03, 0x12]
    );
}

#[test]
fn test_write_frame_matches_spec() {
    // Layout LEN 00 TT RRRR WWWW 00 <payload> SUM, on an allowed table.
    let f = rw().write(0x24, 1, 0, &[1, 2, 3, 4, 5, 6]).unwrap();
    assert_eq!(&f[..8], &[0x0E, 0x00, 0x24, 0x00, 0x01, 0x00, 0x00, 0x00]);
    assert_eq!(*f.last().unwrap(), checksum(&f[..f.len() - 1]));
    assert_eq!(f.len(), 0x0E + 1);
}

#[test]
fn test_read_only_encoder_blocks_writes() {
    let e = Encoder::default();
    assert_eq!(
        e.write(0x24, 0, 0, &[0; 6]),
        Err(Error::NotAllowed(NotAllowed::ReadOnlyEncoder))
    );
}

#[test]
fn test_write_blocked_tables() {
    for t in [
        0x0B, 0x17, 0x32, 0x33, 0x3C, 0x42, 0x48, 0x4A, 0x4B, 0x05, 0x06, 0x40, 0xC3,
    ] {
        assert!(
            matches!(rw().write(t, 0, 0, &[0; 2]), Err(Error::NotAllowed(_))),
            "table {t:#04x}"
        );
    }
}

#[test]
fn test_write_payload_bounds() {
    assert_eq!(
        rw().write(0x25, 0, 0, &[]),
        Err(Error::Frame(FrameError::BadPayloadLen(0)))
    );
    assert_eq!(
        rw().write(0x25, 0, 0, &[0; 3]),
        Err(Error::Frame(FrameError::BadPayloadLen(3)))
    );
    // 201 bytes also runs past nothing here but exceeds the cap.
    assert!(rw().write(0x25, 0, 0, &[0; 202]).is_err());
    assert!(rw().write(0x25, 0, 0, &[0; 160]).is_ok());
}

#[test]
fn test_classify_replies() {
    let cases: &[(&[u8], ReplyKind)] = &[
        (&[0x03, 0x00, 0x00, 0x03], ReplyKind::Ack),
        (&[0x04, 0x00, 0x01, 0x02, 0x07], ReplyKind::Nak(0x02)),
        (&[0x04, 0x01, 0x01, 0x02, 0x08], ReplyKind::Nak(0x02)),
        (&[0x04, 0x01, 0x01, 0x03, 0x09], ReplyKind::Refused),
        (&[0x04, 0xFF, 0x01, 0x00, 0x04], ReplyKind::Busy),
        (&[0x04, 0x08, 0x01, 0x03, 0x10], ReplyKind::Status(0x03)),
        (&[0x03, 0x0B, 0x00, 0x0E], ReplyKind::Ack),
    ];
    for (raw, kind) in cases {
        assert_eq!(&classify(raw).unwrap().kind, kind, "{raw:02x?}");
    }
}

#[test]
fn test_read_word_limit_fits_one_frame() {
    // 0xC3 is 8000 bytes, so 126 words at record 0 is in range.
    assert!(Encoder::default().read(0xC3, 0, 0, MAX_READ_WORDS).is_ok());
    assert_eq!(
        Encoder::default().read(0xC3, 0, 0, MAX_READ_WORDS + 1),
        Err(Error::Frame(FrameError::BadWordCount(127)))
    );
    assert_eq!(
        Encoder::default().read(0xC3, 0, 0, 0),
        Err(Error::Frame(FrameError::BadWordCount(0)))
    );
    // A full data reply for 126 words fits in one LEN byte.
    assert!(Encoder::new(Access::ReadOnly).read(0x24, 0, 0, 126).is_ok());
}

#[test]
fn test_probe_nak_is_not_status() {
    assert_eq!(
        classify(&[0x04, 0x08, 0x01, 0x02, 0x0F]).unwrap().kind,
        ReplyKind::Nak(0x02)
    );
}

#[test]
fn test_read_reply_data() {
    let r = classify(&[0x09, 0x01, 0x00, 1, 2, 3, 4, 5, 6, 0x1F]).unwrap();
    assert_eq!(r.cmd, 0x01);
    assert_eq!(r.kind, ReplyKind::Data(vec![1, 2, 3, 4, 5, 6]));
}

#[test]
fn test_decode_rejects_bad_checksum_and_length() {
    assert_eq!(
        decode(&[0x03, 0x00, 0x00, 0x04]),
        Err(FrameError::BadChecksum)
    );
    assert!(matches!(
        decode(&[0x03, 0x00, 0x00]),
        Err(FrameError::LengthMismatch { .. })
    ));
    assert_eq!(decode(&[0x01, 0x00]), Err(FrameError::InvalidLen(1)));
}

#[test]
fn test_full_upload_commands_cannot_be_encoded() {
    // 0x0A and 0x10 have no Cmd variant: structurally unencodable (G3).
    assert_eq!(Cmd::from_byte(0x0A), None);
    assert_eq!(Cmd::from_byte(0x10), None);
    for b in 0u8..=0xFF {
        if let Some(c) = Cmd::from_byte(b) {
            assert_eq!(c.byte(), b);
            assert!(![0x0A, 0x10].contains(&b));
        }
    }
    // Bytes out of every public encoding path: no frame carries command 0x0A or 0x10.
    // (encode/encode_raw are crate-private: see the compile_fail doctests on frame::encode.)
    let e = Encoder::new(Access::ReadWrite);
    let mut frames = vec![
        e.version_probe(),
        e.status_probe(),
        e.clock(),
        e.end_binary(),
    ];
    for t in 0u8..=0xFF {
        frames.extend(e.read(t, 0, 0, 1).ok());
        frames.extend(e.write(t, 0, 0, &[0, 0]).ok());
    }
    assert!(frames.len() > 70);
    for f in &frames {
        assert!(![0x0A, 0x10].contains(&f[1]), "{f:02x?}");
        assert_eq!(decode(f).unwrap().cmd, f[1]);
    }
}

#[test]
fn test_decode_empty_is_its_own_error() {
    assert_eq!(decode(&[]), Err(FrameError::Empty));
}
