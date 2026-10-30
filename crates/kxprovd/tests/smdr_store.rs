use chrono::{DateTime, Duration, TimeZone, Utc};
use kxprovd::smdr_store::{
    IngestOutcome, SmdrStore, SmdrStoreError, DEFAULT_RETENTION_DAYS, SMDR_DB_NAME,
};
use kxtd1232::smdr::{DateOrder, LineSplitter, SmdrLine};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../kxtd1232/tests/fixtures/smdr-v1")
}

fn fixture_lines(name: &str) -> Vec<SmdrLine> {
    let bytes = std::fs::read(fixture_dir().join(name)).expect("fixture");
    let mut s = LineSplitter::new();
    let mut lines = s.push(&bytes);
    lines.extend(s.finish());
    lines
}

fn rx() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 23, 18, 5, 0)
        .single()
        .expect("rx")
}

fn open(tmp: &tempfile::TempDir) -> SmdrStore {
    SmdrStore::open(tmp.path(), &[&tmp.path().join("backups")], DateOrder::Mdy).expect("open")
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).expect("meta").permissions().mode() & 0o777
}

fn journal(store: &SmdrStore, at: DateTime<Utc>) -> Vec<String> {
    std::fs::read_to_string(store.journal_path(at.date_naive()))
        .expect("journal")
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn every_v1_fixture_lands_raw_then_parsed_or_unparsed() {
    let tmp = tempfile::tempdir().expect("tmp");
    let mut store = open(&tmp);
    let expected: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixture_dir().join("expected.json")).expect("json"),
    )
    .expect("json");
    let mut total = 0;
    let mut stored = 0;
    for (file, spec) in expected.as_object().expect("object") {
        for (line, want) in fixture_lines(file)
            .into_iter()
            .zip(spec["lines"].as_array().expect("lines"))
        {
            total += 1;
            let outcome = store.ingest(line, rx()).expect("ingest");
            let wanted = match want["kind"].as_str().expect("kind") {
                "record" => [IngestOutcome::Stored, IngestOutcome::Duplicate].as_slice(),
                "unknown" => [IngestOutcome::Unparsed].as_slice(),
                _ => [IngestOutcome::Skipped].as_slice(),
            };
            assert!(wanted.contains(&outcome), "{file}: {outcome:?}");
            stored += usize::from(outcome == IngestOutcome::Stored);
        }
    }
    assert_eq!(journal(&store, rx()).len(), total);
    assert_eq!(store.call_count().expect("count"), stored as u64);
    assert_eq!(store.unparsed_count().expect("count"), 1);
}

#[test]
fn parser_failure_still_lands_in_the_raw_journal() {
    let tmp = tempfile::tempdir().expect("tmp");
    let mut store = open(&tmp);
    let line = fixture_lines("malformed_short.txt").remove(0);
    let raw = line.raw().to_string();
    assert_eq!(
        store.ingest(line, rx()).expect("ingest"),
        IngestOutcome::Unparsed
    );
    let j = journal(&store, rx());
    assert_eq!(j.len(), 1);
    assert!(j[0].starts_with("2026-10-23T18:05:00.000Z\t"));
    assert!(j[0].ends_with(&raw));
    assert_eq!(store.call_count().expect("count"), 0);
}

#[test]
fn reprinted_record_is_deduped_but_journaled_twice() {
    let tmp = tempfile::tempdir().expect("tmp");
    let mut store = open(&tmp);
    let line = || fixture_lines("outgoing.txt").remove(0);
    assert_eq!(
        store.ingest(line(), rx()).expect("first"),
        IngestOutcome::Stored
    );
    let later = rx() + Duration::minutes(30);
    assert_eq!(
        store.ingest(line(), later).expect("reprint"),
        IngestOutcome::Duplicate
    );
    assert_eq!(store.call_count().expect("count"), 1);
    assert_eq!(journal(&store, rx()).len(), 2);
}

#[test]
fn records_with_blank_duration_still_dedupe() {
    let tmp = tempfile::tempdir().expect("tmp");
    let mut store = open(&tmp);
    let line = || fixture_lines("incoming_no_cid.txt").remove(0);
    assert_eq!(
        store.ingest(line(), rx()).expect("first"),
        IngestOutcome::Stored
    );
    assert_eq!(
        store.ingest(line(), rx()).expect("again"),
        IngestOutcome::Duplicate
    );
}

#[test]
fn prune_drops_rows_and_journals_past_retention() {
    let tmp = tempfile::tempdir().expect("tmp");
    let mut store = open(&tmp);
    let old = rx() - Duration::days(i64::from(DEFAULT_RETENTION_DAYS) + 1);
    store
        .ingest(fixture_lines("outgoing.txt").remove(0), old)
        .expect("old");
    store
        .ingest(fixture_lines("malformed_short.txt").remove(0), old)
        .expect("old bad");
    store
        .ingest(fixture_lines("incoming_cid.txt").remove(0), rx())
        .expect("new");
    let report = store.prune(rx(), DEFAULT_RETENTION_DAYS).expect("prune");
    assert_eq!((report.calls, report.unparsed, report.journals), (1, 1, 1));
    assert_eq!(store.call_count().expect("count"), 1);
    assert!(!store.journal_path(old.date_naive()).exists());
    assert!(store.journal_path(rx().date_naive()).exists());
    assert_eq!(
        store.prune(rx(), DEFAULT_RETENTION_DAYS).expect("again"),
        Default::default()
    );
}

#[test]
fn files_are_owner_only() {
    let tmp = tempfile::tempdir().expect("tmp");
    let mut store = open(&tmp);
    store
        .ingest(fixture_lines("outgoing.txt").remove(0), rx())
        .expect("ingest");
    assert_eq!(mode(store.dir()), 0o700);
    assert_eq!(mode(&store.dir().join(SMDR_DB_NAME)), 0o600);
    assert_eq!(mode(&store.journal_path(rx().date_naive())), 0o600);
}

#[test]
fn store_refuses_to_live_inside_a_backup_set() {
    let tmp = tempfile::tempdir().expect("tmp");
    let backups = tmp.path().join("data");
    let err = SmdrStore::open(&backups.join("backups"), &[&backups], DateOrder::Mdy);
    assert!(matches!(err, Err(SmdrStoreError::InsideBackupSet { .. })));
    let err = SmdrStore::open(tmp.path(), &[&tmp.path().join("smdr/x")], DateOrder::Mdy);
    assert!(matches!(err, Err(SmdrStoreError::InsideBackupSet { .. })));
}
