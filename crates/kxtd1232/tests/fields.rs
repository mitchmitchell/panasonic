//! Field codec tests (ported from #1 tests/unit/test_fields.py).

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::error::FieldError;
use kxtd1232::fields::*;
use kxtd1232::FieldKind;

#[test]
fn test_cid_number_spec_example() {
    assert_eq!(
        encode_cid_number("123").unwrap(),
        vec![0x31, 0x23, 0xFF, 0xFF, 0xFF, 0xFF]
    );
    assert_eq!(
        encode_cid_number("").unwrap(),
        vec![0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    );
}

#[test]
fn test_cid_number_roundtrip() {
    for n in ["", "0", "5551234", "18005550100", "90210", "00000000000"] {
        assert_eq!(
            decode_cid_number(&encode_cid_number(n).unwrap()).unwrap(),
            n
        );
    }
}

#[test]
fn test_zero_digit_is_a() {
    assert_eq!(encode_cid_number("0").unwrap()[0], 0x1A);
}

#[test]
fn test_cid_number_rejects() {
    assert_eq!(encode_cid_number("12a"), Err(FieldError::NotDigits));
    assert_eq!(encode_cid_number("+1"), Err(FieldError::NotDigits));
    assert_eq!(
        encode_cid_number("123456789012"),
        Err(FieldError::TooManyDigits { max: 11 })
    );
    assert!(decode_cid_number(&[0xC0, 0, 0, 0, 0, 0]).is_err());
    assert!(decode_cid_number(&[0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
    assert!(decode_cid_number(&[0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
    assert!(decode_cid_number(&[0; 5]).is_err());
}

#[test]
fn test_cid_number_rejects_unicode_digits() {
    for bad in ["١٢٣", "１２３", "²"] {
        assert_eq!(encode_cid_number(bad), Err(FieldError::NotDigits), "{bad}");
    }
}

#[test]
fn test_cid_name_layout() {
    let r = encode_cid_name("TEST ONE").unwrap();
    assert_eq!(r.len(), 16);
    assert_eq!(&r[..8], b"TEST ONE");
    assert!(r[8..15].iter().all(|&b| b == 0));
    assert_eq!(r[15], 0xFF);
    assert_eq!(decode_cid_name(&r).unwrap(), "TEST ONE");
}

#[test]
fn test_empty_records_are_zero() {
    let mut empty_name = vec![0u8; 15];
    empty_name.push(0xFF);
    assert_eq!(encode_cid_name("").unwrap(), empty_name);
    assert_eq!(encode_ext_name("").unwrap(), vec![0u8; 10]);
}

#[test]
fn test_cid_name_15_chars_untested_so_refused() {
    assert_eq!(
        encode_cid_name(&"A".repeat(15)),
        Err(FieldError::TooLong { max: 14 })
    );
    assert!(encode_cid_name(&"A".repeat(14)).is_ok());
}

#[test]
fn test_cid_name_requires_ff_terminator() {
    assert_eq!(
        decode_cid_name(&[0u8; 16]),
        Err(FieldError::MissingFfTerminator)
    );
    assert!(decode_cid_name(&[0u8; 15]).is_err());
}

#[test]
fn test_ext_name_layout() {
    assert_eq!(
        encode_ext_name("FRONT DESK").unwrap(),
        b"FRONT DESK".to_vec()
    );
    assert_eq!(
        encode_ext_name("EXT 100").unwrap(),
        b"EXT 100\0\0\0".to_vec()
    );
    assert!(encode_ext_name("ELEVEN CHAR").is_err());
    assert_eq!(encode_ext_name("tab\t"), Err(FieldError::NotPrintableAscii));
    assert_eq!(encode_ext_name("café"), Err(FieldError::NotPrintableAscii));
}

#[test]
fn test_field_kind_enum() {
    assert_eq!("cid_name".parse::<FieldKind>(), Ok(FieldKind::CidName));
    assert!("nope".parse::<FieldKind>().is_err());
    assert_eq!(FieldKind::CidNumber.records(), 500);
    assert_eq!(FieldKind::CidName.records(), 500);
    assert_eq!(FieldKind::ExtName.records(), 128);
    for k in FieldKind::ALL {
        assert_eq!(k.encode("").unwrap().len(), k.record_size());
    }
}
