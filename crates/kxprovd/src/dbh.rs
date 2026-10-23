//! Synthetic TD1232 `.DBH` assembly from wire table images (clean-room, no real captures).

use kxtd1232::tables::{self, TableSpec, NEVER_WRITTEN, TABLES};
use thiserror::Error;

pub const DBH_SIZE: usize = 60_692;

#[derive(Debug, Error)]
pub enum DbhError {
    #[error("wrong size: got {0}, want {DBH_SIZE}")]
    Size(usize),
    #[error("layout: {0}")]
    Layout(String),
}

fn tag_of(table: u8) -> u8 {
    table
}

fn dir_length(spec: &TableSpec) -> u16 {
    let wire = spec.wire_bytes() as u16;
    if spec.id == tables::CID_NUMBERS
        || spec.id == tables::CID_NAMES
        || spec.id >= tables::HALF_TABLE_THRESHOLD
    {
        wire * 2
    } else {
        wire
    }
}

fn wire_to_disk(wire: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(wire.len());
    let mut i = 0;
    while i + 1 < wire.len() {
        out.push(wire[i + 1]);
        out.push(wire[i]);
        i += 2;
    }
    if i < wire.len() {
        out.push(wire[i]);
    }
    out
}

fn append_table_body(out: &mut Vec<u8>, spec: &TableSpec, wire: &[u8]) {
    let want = spec.wire_bytes();
    if wire.len() != want {
        return;
    }
    let mut disk = wire_to_disk(wire);
    if spec.id >= tables::HALF_TABLE_THRESHOLD {
        disk.extend(std::iter::repeat_n(0xFF, want));
    }
    out.extend_from_slice(&disk);
}

/// Tables that appear in the directory (73 tags), ascending tag 1..=81 minus never-written.
fn directory_tables() -> Vec<&'static TableSpec> {
    TABLES
        .iter()
        .filter(|s| {
            let tag = tag_of(s.id);
            tag <= 0x51 && !NEVER_WRITTEN.contains(&s.id)
        })
        .collect()
}

fn trailing_tables() -> [&'static TableSpec; 3] {
    [
        tables::spec(0x52).expect("0x52"),
        tables::spec(0xA7).expect("0xA7"),
        tables::spec(0xC3).expect("0xC3"),
    ]
}

fn build_header(dir_entries: &[(u8, u16)]) -> [u8; 256] {
    let mut h = [0u8; 256];
    h[..30].copy_from_slice(b"SYNTHETIC KX-TD1232 BACKUP    ");
    h[0x20..0x26].copy_from_slice(b"3.11K\0");
    let mut off = 0x26usize;
    for (tag, len) in dir_entries {
        if off + 3 > 0x100 {
            break;
        }
        h[off] = *tag;
        h[off + 1] = (len & 0xFF) as u8;
        h[off + 2] = (len >> 8) as u8;
        off += 3;
    }
    h
}

/// Build a full `.DBH` from wire-form table payloads keyed by table id.
pub fn assemble(
    wire_by_table: &std::collections::HashMap<u8, Vec<u8>>,
) -> Result<Vec<u8>, DbhError> {
    let dir_specs = directory_tables();
    let dir_entries: Vec<(u8, u16)> = dir_specs
        .iter()
        .map(|s| (tag_of(s.id), dir_length(s)))
        .collect();
    let mut out = Vec::with_capacity(DBH_SIZE);
    out.extend_from_slice(&build_header(&dir_entries));
    out.resize(0x100, 0);

    for spec in &dir_specs {
        let wire = wire_by_table
            .get(&spec.id)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        if wire.len() == spec.wire_bytes() {
            append_table_body(&mut out, spec, wire);
        } else {
            let zeros = vec![0u8; spec.wire_bytes()];
            append_table_body(&mut out, spec, &zeros);
        }
    }
    for spec in trailing_tables() {
        let wire = wire_by_table
            .get(&spec.id)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        if wire.len() == spec.wire_bytes() {
            append_table_body(&mut out, spec, wire);
        } else {
            let zeros = vec![0u8; spec.wire_bytes()];
            append_table_body(&mut out, spec, &zeros);
        }
    }

    if out.len() != DBH_SIZE {
        return Err(DbhError::Size(out.len()));
    }
    Ok(out)
}

pub fn parse_size(data: &[u8]) -> Result<(), DbhError> {
    if data.len() != DBH_SIZE {
        Err(DbhError::Size(data.len()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kxtd1232_sim::synthetic_db;

    #[test]
    fn synthetic_dbh_size() {
        let db = synthetic_db();
        let bh = assemble(&db).expect("assemble");
        parse_size(&bh).expect("60692");
    }
}
