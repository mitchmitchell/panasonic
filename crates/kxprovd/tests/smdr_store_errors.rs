#![allow(
    clippy::unwrap_used,
    reason = "test setup failures should abort the test"
)]

use chrono::Utc;
use kxprov_api::{QueryLimit, SmdrApiError, SmdrQueryParams};
use kxprovd::port::journal::LeaseJournal;
use kxprovd::port::PortManager;
use kxprovd::smdr_api::{
    calls_after, count_after, db_path, lease_journal_path, max_call_id, query, store_counters,
};
use kxprovd::smdr_store::SmdrStore;
use kxtd1232::smdr::DateOrder;
use rusqlite::Connection;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

struct RestoreJournalMode {
    path: PathBuf,
    mode: u32,
}

impl Drop for RestoreJournalMode {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(
            &self.path,
            std::fs::Permissions::from_mode(self.mode),
        );
    }
}

fn params() -> SmdrQueryParams {
    SmdrQueryParams {
        limit: QueryLimit::new(50).unwrap(),
        ..SmdrQueryParams::with_defaults(None, None, Utc::now().timestamp_millis() + 60_000)
    }
}

fn run_query(dir: &Path) -> Result<kxprov_api::SmdrPage, SmdrApiError> {
    query(&db_path(dir), &lease_journal_path(dir), &params())
}

fn not_a_database(dir: &Path) {
    let db = db_path(dir);
    std::fs::create_dir_all(db.parent().unwrap()).unwrap();
    std::fs::write(&db, vec![0x5a; 8192]).unwrap();
}

#[test]
fn unreadable_lease_journal_is_store_failed_even_without_a_database() {
    let tmp = tempfile::tempdir().unwrap();
    let j = lease_journal_path(tmp.path());
    std::fs::write(
        &j,
        "{\"ts_utc\":\"2026-11-01T12:00:00.000Z\",\"event\":\"reader_paused\",\"job_id\":\"job-a\",\"gap_tracking\":\"gap\"}\n",
    )
    .unwrap();
    let mode = std::fs::metadata(&j).unwrap().permissions().mode() & 0o777;
    let _restore = RestoreJournalMode {
        path: j.clone(),
        mode,
    };
    std::fs::set_permissions(&j, std::fs::Permissions::from_mode(0o000)).unwrap();
    assert!(!db_path(tmp.path()).exists());
    assert_eq!(run_query(tmp.path()), Err(SmdrApiError::StoreFailed));
}

#[test]
fn missing_database_is_an_empty_page_that_still_carries_gaps() {
    let tmp = tempfile::tempdir().unwrap();
    let pm = PortManager::new((), LeaseJournal::new(lease_journal_path(tmp.path())), 4);
    let lease = pm
        .request_lease("job-a", Duration::from_millis(50))
        .unwrap();
    std::thread::sleep(Duration::from_millis(5));
    lease.release().unwrap();
    assert!(!db_path(tmp.path()).exists());
    let page = run_query(tmp.path()).unwrap();
    assert!(page.calls.is_empty());
    assert!(page.next.is_none());
    let jobs: Vec<_> = page.gaps.iter().map(|g| g.job_id.as_str()).collect();
    assert_eq!(jobs, ["job-a"]);
}

#[test]
fn missing_database_reads_as_empty_for_every_reader() {
    let tmp = tempfile::tempdir().unwrap();
    let db = db_path(tmp.path());
    assert_eq!(calls_after(&db, 0, 10), Ok(Vec::new()));
    assert_eq!(count_after(&db, 0), Ok(0));
    assert_eq!(max_call_id(&db), Ok(0));
    assert_eq!(
        store_counters(&db, "2026-11-01T00:00:00.000Z"),
        Ok((0, 0, None))
    );
}

#[test]
fn busy_or_locked_store_is_store_unavailable_for_every_reader() {
    let tmp = tempfile::tempdir().unwrap();
    drop(SmdrStore::open(tmp.path(), &[], DateOrder::Mdy).unwrap());
    let db = db_path(tmp.path());
    let writer = Connection::open(&db).unwrap();
    writer
        .execute_batch("PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE;")
        .unwrap();
    assert_eq!(run_query(tmp.path()), Err(SmdrApiError::StoreUnavailable));
    assert_eq!(calls_after(&db, 0, 10), Err(SmdrApiError::StoreUnavailable));
    assert_eq!(count_after(&db, 0), Err(SmdrApiError::StoreUnavailable));
    assert_eq!(max_call_id(&db), Err(SmdrApiError::StoreUnavailable));
    assert_eq!(
        store_counters(&db, "2026-11-01T00:00:00.000Z"),
        Err(SmdrApiError::StoreUnavailable)
    );
    writer.execute_batch("COMMIT;").unwrap();
}

#[test]
fn a_file_that_is_not_a_database_is_store_failed_never_empty() {
    let tmp = tempfile::tempdir().unwrap();
    not_a_database(tmp.path());
    let db = db_path(tmp.path());
    assert_eq!(run_query(tmp.path()), Err(SmdrApiError::StoreFailed));
    assert_eq!(calls_after(&db, 0, 10), Err(SmdrApiError::StoreFailed));
    assert_eq!(count_after(&db, 0), Err(SmdrApiError::StoreFailed));
    assert_eq!(max_call_id(&db), Err(SmdrApiError::StoreFailed));
    assert_eq!(
        store_counters(&db, "2026-11-01T00:00:00.000Z"),
        Err(SmdrApiError::StoreFailed)
    );
}

#[test]
fn a_database_path_that_cannot_be_opened_is_store_failed_never_empty() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(db_path(tmp.path())).unwrap();
    assert_eq!(run_query(tmp.path()), Err(SmdrApiError::StoreFailed));
    assert_eq!(
        calls_after(&db_path(tmp.path()), 0, 10),
        Err(SmdrApiError::StoreFailed)
    );
}

#[test]
fn a_store_without_the_call_table_is_store_failed_never_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let db = db_path(tmp.path());
    std::fs::create_dir_all(db.parent().unwrap()).unwrap();
    Connection::open(&db)
        .unwrap()
        .execute_batch("CREATE TABLE other (x INTEGER);")
        .unwrap();
    assert_eq!(run_query(tmp.path()), Err(SmdrApiError::StoreFailed));
    assert_eq!(max_call_id(&db), Err(SmdrApiError::StoreFailed));
}
