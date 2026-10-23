//! Typed field codecs. Layouts are HYPOTHESIS unless noted (RE handoff §2.6, table spec §3).

use crate::error::FieldError;
use crate::tables;
use std::fmt;
use std::str::FromStr;

pub const CID_NUMBER_SIZE: usize = 6;
pub const CID_NAME_SIZE: usize = 16;
pub const EXT_NAME_SIZE: usize = 10;
pub const MAX_CID_DIGITS: usize = 11;
/// A full 15-character caller-ID name (no `00` before the `FF`) is UNTESTED on hardware,
/// so at most 14 characters are accepted until Reverse Engineer confirms it.
pub const MAX_CID_NAME_CHARS: usize = CID_NAME_SIZE - 2;

/// The typed fields the library knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldKind {
    /// Table 0x24: nibble 0 = digit count, `A` = digit 0, `F` pad.
    CidNumber,
    /// Table 0x25: 15 ASCII bytes `00`-padded, then a fixed `FF`.
    CidName,
    /// Table 0x05: 10 ASCII bytes `00`-padded (readable; not writable before G6).
    ExtName,
}

impl FieldKind {
    pub const ALL: [FieldKind; 3] = [Self::CidName, Self::CidNumber, Self::ExtName];

    pub const fn table(self) -> u8 {
        match self {
            Self::CidNumber => tables::CID_NUMBERS,
            Self::CidName => tables::CID_NAMES,
            Self::ExtName => tables::EXT_NAMES,
        }
    }

    pub const fn record_size(self) -> usize {
        match self {
            Self::CidNumber => CID_NUMBER_SIZE,
            Self::CidName => CID_NAME_SIZE,
            Self::ExtName => EXT_NAME_SIZE,
        }
    }

    /// Record count from the table spec (single-cabinet KX-TD1232).
    pub fn records(self) -> u16 {
        tables::spec(self.table()).map_or(0, |s| s.records)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::CidNumber => "cid_number",
            Self::CidName => "cid_name",
            Self::ExtName => "ext_name",
        }
    }

    pub fn encode(self, value: &str) -> Result<Vec<u8>, FieldError> {
        match self {
            Self::CidNumber => encode_cid_number(value),
            Self::CidName => encode_cid_name(value),
            Self::ExtName => encode_ext_name(value),
        }
    }

    pub fn decode(self, raw: &[u8]) -> Result<String, FieldError> {
        match self {
            Self::CidNumber => decode_cid_number(raw),
            Self::CidName => decode_cid_name(raw),
            Self::ExtName => decode_ext_name(raw),
        }
    }
}

impl fmt::Display for FieldKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for FieldKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|k| k.name() == s)
            .ok_or_else(|| format!("unknown field kind {s:?} (cid_name, cid_number, ext_name)"))
    }
}

pub fn encode_cid_number(number: &str) -> Result<Vec<u8>, FieldError> {
    // ASCII only: char::is_numeric would accept non-ASCII digits.
    if !number.bytes().all(|b| b.is_ascii_digit()) {
        return Err(FieldError::NotDigits);
    }
    if number.len() > MAX_CID_DIGITS {
        return Err(FieldError::TooManyDigits {
            max: MAX_CID_DIGITS,
        });
    }
    let mut nibbles = vec![number.len() as u8];
    nibbles.extend(number.bytes().map(|b| match b - b'0' {
        0 => 0xA,
        d => d,
    }));
    nibbles.resize(2 * CID_NUMBER_SIZE, 0xF);
    Ok(nibbles.chunks(2).map(|p| (p[0] << 4) | p[1]).collect())
}

pub fn decode_cid_number(raw: &[u8]) -> Result<String, FieldError> {
    if raw.len() != CID_NUMBER_SIZE {
        return Err(FieldError::BadRecordSize {
            expected: CID_NUMBER_SIZE,
            got: raw.len(),
        });
    }
    let nibbles: Vec<u8> = raw.iter().flat_map(|b| [b >> 4, b & 0xF]).collect();
    let count = nibbles[0];
    if count as usize > MAX_CID_DIGITS {
        return Err(FieldError::BadDigitCount(count));
    }
    nibbles[1..=count as usize]
        .iter()
        .map(|&d| match d {
            0xA => Ok('0'),
            1..=9 => Ok((b'0' + d) as char),
            _ => Err(FieldError::BadDigitNibble(d)),
        })
        .collect()
}

fn encode_ascii(text: &str, room: usize) -> Result<Vec<u8>, FieldError> {
    if !text.bytes().all(|b| (0x20..0x7F).contains(&b)) {
        return Err(FieldError::NotPrintableAscii);
    }
    if text.len() > room {
        return Err(FieldError::TooLong { max: room });
    }
    let mut v = text.as_bytes().to_vec();
    v.resize(room, 0x00);
    Ok(v)
}

fn decode_ascii(raw: &[u8]) -> Result<String, FieldError> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let s = &raw[..end];
    if !s.iter().all(|b| (0x20..0x7F).contains(b)) {
        return Err(FieldError::NotPrintableAscii);
    }
    Ok(s.iter().map(|&b| b as char).collect())
}

pub fn encode_cid_name(name: &str) -> Result<Vec<u8>, FieldError> {
    let mut v = encode_ascii(name, MAX_CID_NAME_CHARS)?;
    v.resize(CID_NAME_SIZE - 1, 0x00);
    v.push(0xFF);
    Ok(v)
}

pub fn decode_cid_name(raw: &[u8]) -> Result<String, FieldError> {
    if raw.len() != CID_NAME_SIZE || raw[CID_NAME_SIZE - 1] != 0xFF {
        return Err(FieldError::MissingFfTerminator);
    }
    decode_ascii(&raw[..CID_NAME_SIZE - 1])
}

pub fn encode_ext_name(name: &str) -> Result<Vec<u8>, FieldError> {
    encode_ascii(name, EXT_NAME_SIZE)
}

pub fn decode_ext_name(raw: &[u8]) -> Result<String, FieldError> {
    if raw.len() != EXT_NAME_SIZE {
        return Err(FieldError::BadRecordSize {
            expected: EXT_NAME_SIZE,
            got: raw.len(),
        });
    }
    decode_ascii(raw)
}
