//! The 75 KX-TD1232 tables from Reverse Engineer's table spec (DRAFT 2026-10-22, §1),
//! single-cabinet only. For tables >= 0x40, `records` is the first-cabinet count: the
//! only half that goes over the wire. The `.DBH` second half is opaque (never on the wire).

use crate::error::NotAllowed;

/// One table's wire geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableSpec {
    pub id: u8,
    /// Record size in bytes on the wire.
    pub record_bytes: u16,
    /// Record count (first-cabinet half for 0x40 and up).
    pub records: u16,
    /// Records per read/write frame (same chunking both ways).
    pub records_per_frame: u16,
    /// Words per frame (NN byte of the read request).
    pub words_per_frame: u8,
}

impl TableSpec {
    /// Total wire bytes of the table.
    pub const fn wire_bytes(&self) -> usize {
        self.record_bytes as usize * self.records as usize
    }

    /// Frames as `(record, word, nwords)` in upload order (reads use the same chunking).
    pub fn frames(&self) -> Vec<(u16, u16, u8)> {
        let rec_words = self.record_bytes / 2;
        let nn = u16::from(self.words_per_frame);
        let mut out = Vec::new();
        if rec_words <= nn {
            let mut rec = 0u16;
            while rec < self.records {
                let n = self.records_per_frame.min(self.records - rec);
                out.push((rec, 0, (n * rec_words) as u8));
                rec += n;
            }
        } else {
            // Only 0x10: each 600-byte record goes as three 200-byte frames at words 0/100/200.
            for rec in 0..self.records {
                let mut w = 0u16;
                while w < rec_words {
                    let n = nn.min(rec_words - w);
                    out.push((rec, w, n as u8));
                    w += n;
                }
            }
        }
        out
    }
}

const fn t(id: u8, record_bytes: u16, records: u16, rpf: u16, nn: u8) -> TableSpec {
    TableSpec {
        id,
        record_bytes,
        records,
        records_per_frame: rpf,
        words_per_frame: nn,
    }
}

/// All 75 tables, strictly ascending (= full-upload order).
pub const TABLES: [TableSpec; 75] = [
    t(0x01, 14, 100, 10, 70),
    t(0x02, 10, 100, 20, 100),
    t(0x03, 2, 128, 64, 64),
    t(0x04, 30, 1, 1, 15),
    t(0x05, 10, 128, 16, 80),
    t(0x06, 6, 1, 1, 3),
    t(0x07, 162, 1, 1, 81),
    t(0x08, 200, 1, 1, 100),
    t(0x09, 86, 1, 1, 43),
    t(0x0A, 4, 1, 1, 2),
    t(0x0C, 6, 128, 32, 96),
    t(0x0D, 120, 5, 1, 60),
    t(0x0E, 150, 1, 1, 75),
    t(0x0F, 120, 1, 1, 60),
    t(0x10, 600, 8, 1, 100),
    t(0x11, 128, 1, 1, 64),
    t(0x12, 96, 1, 1, 48),
    t(0x13, 24, 1, 1, 12),
    t(0x14, 16, 1, 1, 8),
    t(0x15, 6, 1, 1, 3),
    t(0x16, 8, 1, 1, 4),
    t(0x18, 32, 1, 1, 16),
    t(0x19, 32, 1, 1, 16),
    t(0x1A, 16, 1, 1, 8),
    t(0x1B, 32, 1, 1, 16),
    t(0x1C, 128, 1, 1, 64),
    t(0x1D, 4, 1, 1, 2),
    t(0x1E, 16, 1, 1, 8),
    t(0x1F, 64, 1, 1, 32),
    t(0x20, 4, 1, 1, 2),
    t(0x21, 64, 1, 1, 32),
    t(0x22, 64, 1, 1, 32),
    t(0x23, 48, 1, 1, 24),
    t(0x24, 6, 500, 25, 75),
    t(0x25, 16, 500, 10, 80),
    t(0x26, 160, 1, 1, 80),
    t(0x27, 20, 1, 1, 10),
    t(0x28, 40, 1, 1, 20),
    t(0x29, 16, 1, 1, 8),
    t(0x2A, 40, 1, 1, 20),
    t(0x2B, 32, 1, 1, 16),
    t(0x2C, 16, 1, 1, 8),
    t(0x2D, 20, 1, 1, 10),
    t(0x2E, 80, 1, 1, 40),
    t(0x2F, 12, 1, 1, 6),
    t(0x30, 40, 1, 1, 20),
    t(0x31, 10, 24, 12, 60),
    t(0x34, 64, 1, 1, 32),
    t(0x35, 8, 1, 1, 4),
    t(0x36, 8, 1, 1, 4),
    t(0x37, 6, 400, 25, 75),
    t(0x38, 2, 128, 64, 64),
    t(0x39, 80, 1, 1, 40),
    t(0x3A, 80, 1, 1, 40),
    t(0x3B, 80, 1, 1, 40),
    t(0x3D, 8, 1, 1, 4),
    t(0x3E, 16, 1, 1, 8),
    t(0x3F, 16, 1, 1, 8),
    t(0x40, 2, 1, 1, 1),
    t(0x41, 4, 1, 1, 2),
    t(0x43, 2, 12, 12, 12),
    t(0x44, 2, 12, 12, 12),
    t(0x45, 2, 64, 64, 64),
    t(0x46, 12, 64, 16, 96),
    t(0x47, 12, 64, 16, 96),
    t(0x49, 4, 4, 4, 8),
    t(0x4C, 48, 32, 4, 96),
    t(0x4D, 24, 64, 8, 96),
    t(0x4E, 64, 4, 2, 64),
    t(0x4F, 32, 4, 4, 64),
    t(0x50, 2, 64, 64, 64),
    t(0x51, 4, 64, 32, 64),
    t(0x52, 4, 64, 32, 64),
    t(0xA7, 100, 32, 2, 100),
    t(0xC3, 10, 800, 20, 100),
];

/// Table ids DSHSOMT never reads or writes. Writes are refused.
pub const NEVER_WRITTEN: [u8; 9] = [0x0B, 0x17, 0x32, 0x33, 0x3C, 0x42, 0x48, 0x4A, 0x4B];

/// Tables at or above this id exist on the wire only in their first-cabinet half.
pub const HALF_TABLE_THRESHOLD: u8 = 0x40;

/// Write allow-list: caller-ID only, until gate G6 is closed by hardware test H8.
pub const EDITABLE_TABLES: [u8; 2] = [CID_NUMBERS, CID_NAMES];

pub const EXT_NAMES: u8 = 0x05;
pub const CID_NUMBERS: u8 = 0x24;
pub const CID_NAMES: u8 = 0x25;

/// Look up a table by id.
pub fn spec(table: u8) -> Option<&'static TableSpec> {
    TABLES.iter().find(|s| s.id == table)
}

fn check_span(s: &TableSpec, record: u16, word: u16, len: usize) -> Result<(), NotAllowed> {
    if record >= s.records {
        return Err(NotAllowed::RecordOutOfRange {
            table: s.id,
            record,
            records: s.records,
        });
    }
    let end = record as usize * s.record_bytes as usize + 2 * word as usize + len;
    if end > s.wire_bytes() {
        return Err(NotAllowed::SpanOutOfRange {
            table: s.id,
            end,
            size: s.wire_bytes(),
        });
    }
    Ok(())
}

/// Range check for a read of `nwords` words. Applies to every table; for 0x40 and up
/// this rejects any record index >= the first-cabinet `Recs` (the PBX refuses them with
/// `04 01 01 03 09`).
pub fn check_readable(table: u8, record: u16, word: u16, nwords: u8) -> Result<(), NotAllowed> {
    let s = spec(table).ok_or(NotAllowed::UnknownTable(table))?;
    check_span(s, record, word, 2 * nwords as usize)
}

/// Table-level write guard (allow-list, never-written, half-table rule).
pub fn check_writable_table(table: u8) -> Result<&'static TableSpec, NotAllowed> {
    if NEVER_WRITTEN.contains(&table) {
        return Err(NotAllowed::NeverWritten(table));
    }
    if table >= HALF_TABLE_THRESHOLD {
        return Err(NotAllowed::HalfTable(table));
    }
    if !EDITABLE_TABLES.contains(&table) {
        return Err(NotAllowed::NotEditable(table));
    }
    spec(table).ok_or(NotAllowed::UnknownTable(table))
}

/// Full write guard: table guard plus record/span range checks and the payload cap.
pub fn check_writable(table: u8, record: u16, word: u16, len: usize) -> Result<(), NotAllowed> {
    let s = check_writable_table(table)?;
    check_span(s, record, word, len)
}
