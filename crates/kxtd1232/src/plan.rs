//! WritePlan: a dry-run list of chunk writes computed from a base image and edits.
//! Unchanged bytes inside a chunk are re-sent exactly as read (design §3).

use crate::error::Error;
use crate::fields::FieldKind;
use crate::frame::MAX_WRITE_PAYLOAD;
use crate::tables;

/// Raw edit: bytes at `offset` within a table image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    pub table: u8,
    pub offset: usize,
    pub data: Vec<u8>,
}

/// Typed edit compiled to a raw [`Patch`]. Validates the index and the value.
pub fn field_patch(kind: FieldKind, index: u16, value: &str) -> Result<Patch, Error> {
    if index >= kind.records() {
        return Err(crate::error::NotAllowed::RecordOutOfRange {
            table: kind.table(),
            record: index,
            records: kind.records(),
        }
        .into());
    }
    Ok(Patch {
        table: kind.table(),
        offset: index as usize * kind.record_size(),
        data: kind.encode(value)?,
    })
}

/// One write frame of a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkWrite {
    pub table: u8,
    pub record: u16,
    pub word: u16,
    pub base: Vec<u8>,
    pub new: Vec<u8>,
}

/// Which chunks a plan includes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granularity {
    /// Only frames whose bytes change.
    Chunk,
    /// Every frame of the table.
    Table,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritePlan {
    pub table: u8,
    pub record_size: usize,
    pub writes: Vec<ChunkWrite>,
}

impl WritePlan {
    pub fn changed_bytes(&self) -> usize {
        self.writes
            .iter()
            .map(|w| w.base.iter().zip(&w.new).filter(|(a, b)| a != b).count())
            .sum()
    }

    /// One line per changed byte: `T25 +0x0010: 00 -> 41`.
    pub fn diff(&self) -> Vec<String> {
        let mut out = Vec::new();
        for w in &self.writes {
            for (i, (a, b)) in w.base.iter().zip(&w.new).enumerate() {
                if a != b {
                    let off = w.record as usize * self.record_size + 2 * w.word as usize + i;
                    out.push(format!(
                        "T{:02X} +{off:#06x}: {a:02X} -> {b:02X}",
                        self.table
                    ));
                }
            }
        }
        out
    }
}

/// Build a plan for `table` from the full table image `base`. Chunking follows the spec
/// (same frames as reads and the full upload). Every chunk is checked at build time:
/// write allow-list, record range and payload size (<= 200 bytes, even).
pub fn build_plan(
    table: u8,
    base: &[u8],
    patches: &[Patch],
    granularity: Granularity,
) -> Result<WritePlan, Error> {
    let spec = tables::check_writable_table(table)?;
    if base.len() != spec.wire_bytes() {
        return Err(Error::Plan(format!(
            "base image is {} bytes, table {table:#04x} is {}",
            base.len(),
            spec.wire_bytes()
        )));
    }
    let mut new = base.to_vec();
    for p in patches {
        if p.table != table {
            return Err(Error::Plan(format!("patch for table {:#04x}", p.table)));
        }
        let end = p.offset.checked_add(p.data.len()).unwrap_or(usize::MAX);
        if end > base.len() {
            return Err(Error::Plan("patch outside table image".into()));
        }
        new[p.offset..end].copy_from_slice(&p.data);
    }
    let rs = spec.record_bytes as usize;
    let mut plan = WritePlan {
        table,
        record_size: rs,
        writes: Vec::new(),
    };
    for (record, word, nwords) in spec.frames() {
        let start = record as usize * rs + 2 * word as usize;
        let end = start + 2 * nwords as usize;
        let len = end - start;
        if len == 0 || len > MAX_WRITE_PAYLOAD || len % 2 != 0 {
            return Err(Error::Plan(format!("chunk of {len} bytes")));
        }
        tables::check_writable(table, record, word, len)?;
        if granularity == Granularity::Table || base[start..end] != new[start..end] {
            plan.writes.push(ChunkWrite {
                table,
                record,
                word,
                base: base[start..end].to_vec(),
                new: new[start..end].to_vec(),
            });
        }
    }
    Ok(plan)
}
