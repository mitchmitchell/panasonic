//! WritePlan tests (ported from #1 tests/unit/test_writeplan.py).

#![allow(clippy::unwrap_used)] // tests: a panic is the failure report

use kxtd1232::fields::encode_cid_name;
use kxtd1232::{build_plan, field_patch, Error, FieldKind, Granularity, Patch};

fn cid_names() -> Vec<u8> {
    (0..500)
        .flat_map(|_| encode_cid_name("").unwrap())
        .collect()
}

#[test]
fn test_single_field_edit_one_chunk() {
    let base = cid_names();
    let p = field_patch(FieldKind::CidName, 23, "HELLO").unwrap();
    let plan = build_plan(0x25, &base, &[p], Granularity::Chunk).unwrap();
    assert_eq!(plan.writes.len(), 1);
    let w = &plan.writes[0];
    assert_eq!((w.table, w.record, w.word), (0x25, 20, 0));
    assert_eq!(w.new.len(), 160);
    assert_eq!(plan.changed_bytes(), 5);
    assert_eq!(plan.diff()[0], "T25 +0x0170: 00 -> 48");
}

#[test]
fn test_table_granularity_writes_everything() {
    let base = cid_names();
    let plan = build_plan(0x25, &base, &[], Granularity::Table).unwrap();
    assert_eq!(plan.writes.len(), 50);
    assert_eq!(plan.changed_bytes(), 0);
    assert_eq!(
        build_plan(0x24, &[0; 3000], &[], Granularity::Table)
            .unwrap()
            .writes
            .len(),
        20
    );
}

#[test]
fn test_fuzz_no_bytes_outside_span() {
    let base = cid_names();
    let mut seed: u64 = 0x2545F4914F6CDD1D;
    for _ in 0..500 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let off = (seed % 7990) as usize;
        let len = 1 + (seed >> 20) as usize % 10;
        let data: Vec<u8> = (0..len).map(|i| (seed >> (i % 8)) as u8 | 1).collect();
        let plan = build_plan(
            0x25,
            &base,
            &[Patch {
                table: 0x25,
                offset: off,
                data: data.clone(),
            }],
            Granularity::Chunk,
        )
        .unwrap();
        for w in &plan.writes {
            let start = w.record as usize * 16;
            for (i, (a, b)) in w.base.iter().zip(&w.new).enumerate() {
                if a != b {
                    let at = start + i;
                    assert!(
                        at >= off && at < off + len,
                        "byte {at} outside {off}..{}",
                        off + len
                    );
                }
            }
            assert_eq!(w.base, base[start..start + w.base.len()]);
        }
    }
}

#[test]
fn test_no_change_no_writes() {
    let base = cid_names();
    let p = field_patch(FieldKind::CidName, 5, "").unwrap();
    assert!(build_plan(0x25, &base, &[p], Granularity::Chunk)
        .unwrap()
        .writes
        .is_empty());
}

#[test]
fn test_rejects_bad_tables_and_ranges() {
    let base = cid_names();
    assert!(matches!(
        build_plan(0x05, &[0; 1280], &[], Granularity::Chunk),
        Err(Error::NotAllowed(_))
    ));
    assert!(matches!(
        build_plan(
            0x25,
            &base,
            &[Patch {
                table: 0x24,
                offset: 0,
                data: vec![1]
            }],
            Granularity::Chunk
        ),
        Err(Error::Plan(_))
    ));
    assert!(matches!(
        build_plan(
            0x25,
            &base,
            &[Patch {
                table: 0x25,
                offset: 7999,
                data: vec![1, 2]
            }],
            Granularity::Chunk
        ),
        Err(Error::Plan(_))
    ));
    assert!(matches!(
        build_plan(
            0x25,
            &base,
            &[Patch {
                table: 0x25,
                offset: usize::MAX,
                data: vec![1]
            }],
            Granularity::Chunk
        ),
        Err(Error::Plan(_))
    ));
    assert!(field_patch(FieldKind::CidName, 500, "X").is_err());
}

#[test]
fn test_plan_checks_base_size_and_chunks_at_build() {
    // A base image of the wrong size is refused before any chunk is computed.
    assert!(matches!(
        build_plan(0x25, &[0; 160], &[], Granularity::Table),
        Err(Error::Plan(_))
    ));
    // Every chunk the plan emits is an encodable write (<= 200 bytes, even).
    let plan = build_plan(0x24, &[0; 3000], &[], Granularity::Table).unwrap();
    assert!(plan.writes.iter().all(|w| w.new.len() == 150));
}
