//! Synthetic TD1232 `.DBH` assembly from wire table images (clean-room).
//!
//! v2.4: bytes **0x1E–0xFF** are never embedded in the repo. They are copied at runtime
//! from the latest verified backup, or from the PBX/sim upload before the first backup.

use kxtd1232::tables::{self, TableSpec, NEVER_WRITTEN, TABLES};
use thiserror::Error;

pub const DBH_SIZE: usize = 60_692;
pub const HEADER_TAIL_START: usize = 0x1E;
pub const HEADER_TAIL_LEN: usize = 0x100 - HEADER_TAIL_START;

const LABEL: &[u8; 30] = b"SYNTHETIC KX-TD1232 BACKUP    ";

#[derive(Debug, Error)]
pub enum DbhError {
    #[error("wrong size: got {0}, want {DBH_SIZE}")]
    Size(usize),
    #[error("layout: {0}")]
    Layout(String),
    #[error("header tail must be {HEADER_TAIL_LEN} bytes")]
    BadHeaderTail,
}

fn tag_of(table: u8) -> u8 {
    table
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

pub fn copy_header_tail_from_dbh(dbh: &[u8]) -> Result<[u8; HEADER_TAIL_LEN], DbhError> {
    if dbh.len() != DBH_SIZE {
        return Err(DbhError::Size(dbh.len()));
    }
    let mut tail = [0u8; HEADER_TAIL_LEN];
    tail.copy_from_slice(&dbh[HEADER_TAIL_START..0x100]);
    Ok(tail)
}

fn write_header_prefix(out: &mut [u8; 256], tail: &[u8; HEADER_TAIL_LEN]) {
    out[..30].copy_from_slice(LABEL);
    out[0x1E..0x100].copy_from_slice(tail);
}

/// Build a full `.DBH` from wire images and a runtime header tail (0x1E–0xFF).
pub fn assemble_with_tail(
    wire_by_table: &std::collections::HashMap<u8, Vec<u8>>,
    header_tail: &[u8; HEADER_TAIL_LEN],
) -> Result<Vec<u8>, DbhError> {
    let mut header = [0u8; 256];
    write_header_prefix(&mut header, header_tail);

    let dir_specs = directory_tables();
    let mut out = Vec::with_capacity(DBH_SIZE);
    out.extend_from_slice(&header);

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

#[cfg(all(test, feature = "inprocess-sim"))]
mod tests {
    use super::*;
    use kxtd1232_sim::synthetic_db;

    #[test]
    fn synthetic_dbh_size_with_sim_upload_tail() {
        let db = synthetic_db();
        let sim = kxtd1232_sim::SimPbx::default();
        let tail = sim.dbh_header_tail();
        let mut fixed = [0u8; HEADER_TAIL_LEN];
        fixed.copy_from_slice(tail);
        let bh = assemble_with_tail(&db, &fixed).expect("assemble");
        parse_size(&bh).expect("60692");
    }
}
