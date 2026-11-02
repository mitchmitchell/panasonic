#![allow(
    clippy::unwrap_used,
    reason = "test setup failures should abort the test"
)]

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use kxprov_api::{CallDirection, QueryLimit, SmdrApiError, SmdrCursor, SmdrQueryParams};
use kxprovd::smdr_api::{db_path, lease_journal_path, query};
use kxprovd::smdr_store::SmdrStore;
use kxtd1232::smdr::DateOrder;
use rusqlite::{params, Connection};
use std::path::Path;

fn base() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-11-01T12:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

fn setup(tmp: &tempfile::TempDir) -> Connection {
    drop(SmdrStore::open(tmp.path(), &[], DateOrder::Mdy).unwrap());
    Connection::open(db_path(tmp.path())).unwrap()
}

fn insert(db: &Connection, at: DateTime<Utc>, ext: &str, dir: &str, number: &str) {
    let ts = at.to_rfc3339_opts(SecondsFormat::Millis, true);
    db.execute(
        "INSERT INTO smdr_call (rx_ts_utc, pbx_local, ext, co, direction, number, cid_text,
          ring_s, duration_s, acc, cd, raw, parse_ok)
         VALUES (?1, ?1, ?2, '01', ?3, ?4, '', NULL, 30, '', '', 'RAW-SECRET', 1)",
        params![ts, ext, dir, number],
    )
    .unwrap();
}

fn params(limit: u16) -> SmdrQueryParams {
    SmdrQueryParams {
        limit: QueryLimit::new(limit).unwrap(),
        ..SmdrQueryParams::with_defaults(
            None,
            None,
            (base() + Duration::hours(1)).timestamp_millis(),
        )
    }
}

fn all_pages(dir: &Path, mut p: SmdrQueryParams, mut between: impl FnMut()) -> Vec<i64> {
    let mut ids = Vec::new();
    loop {
        let page = query(&db_path(dir), &lease_journal_path(dir), &p).unwrap();
        ids.extend(page.calls.iter().map(|c| c.id));
        between();
        match page.next {
            Some(c) => p.cursor = Some(c),
            None => return ids,
        }
    }
}

#[test]
fn filters_by_window_ext_and_direction() {
    let tmp = tempfile::tempdir().unwrap();
    let db = setup(&tmp);
    insert(&db, base() - Duration::hours(25), "101", "in", "1");
    insert(&db, base(), "101", "in", "2");
    insert(&db, base() + Duration::minutes(1), "102", "out", "3");
    insert(&db, base() + Duration::hours(1), "101", "in", "4");
    let all = query(
        &db_path(tmp.path()),
        &lease_journal_path(tmp.path()),
        &params(50),
    )
    .unwrap();
    let numbers: Vec<&str> = all.calls.iter().map(|c| c.number.as_str()).collect();
    assert_eq!(
        numbers,
        ["3", "2"],
        "half-open last-24h window, newest first"
    );

    let mut p = params(50);
    p.ext = Some("101".into());
    let page = query(&db_path(tmp.path()), &lease_journal_path(tmp.path()), &p).unwrap();
    assert_eq!(page.calls.len(), 1);
    assert_eq!(page.calls[0].number, "2");

    let mut p = params(50);
    p.direction = Some(CallDirection::Outgoing);
    let page = query(&db_path(tmp.path()), &lease_journal_path(tmp.path()), &p).unwrap();
    assert_eq!(page.calls.len(), 1);
    assert_eq!(page.calls[0].direction, CallDirection::Outgoing);
}

#[test]
fn empty_range_returns_no_calls_and_no_cursor() {
    let tmp = tempfile::tempdir().unwrap();
    let _db = setup(&tmp);
    let page = query(
        &db_path(tmp.path()),
        &lease_journal_path(tmp.path()),
        &params(50),
    )
    .unwrap();
    assert!(page.calls.is_empty());
    assert!(page.next.is_none());
}

#[test]
fn pages_cover_a_full_31_day_range_exactly_once() {
    let tmp = tempfile::tempdir().unwrap();
    let db = setup(&tmp);
    let until = base() + Duration::hours(1);
    let since = until - Duration::days(31);
    for i in 0..1203 {
        insert(
            &db,
            since + Duration::minutes(i * 37),
            "101",
            "in",
            &i.to_string(),
        );
    }
    insert(&db, since, "101", "in", "same-ts-a");
    insert(&db, since, "101", "in", "same-ts-b");
    let p = SmdrQueryParams {
        since_ms: since.timestamp_millis(),
        until_ms: until.timestamp_millis(),
        limit: QueryLimit::new(500).unwrap(),
        ..params(1)
    };
    let ids = all_pages(tmp.path(), p, || {});
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), ids.len(), "no row repeats across pages");
    assert_eq!(ids.len(), 1205);
}

#[test]
fn paging_is_stable_while_new_calls_arrive() {
    let tmp = tempfile::tempdir().unwrap();
    let db = setup(&tmp);
    for i in 0..10 {
        insert(
            &db,
            base() - Duration::minutes(i),
            "101",
            "in",
            &i.to_string(),
        );
    }
    let before: Vec<i64> = all_pages(tmp.path(), params(3), || {});
    let mut n = 0;
    let during = all_pages(tmp.path(), params(3), || {
        n += 1;
        insert(
            &db,
            base() + Duration::seconds(n),
            "101",
            "in",
            &format!("new{n}"),
        );
    });
    assert_eq!(before, during);
}

#[test]
fn oversize_and_bad_inputs_are_typed_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let _db = setup(&tmp);
    let mut p = params(50);
    p.since_ms = p.until_ms - Duration::days(32).num_milliseconds();
    assert_eq!(
        query(&db_path(tmp.path()), &lease_journal_path(tmp.path()), &p),
        Err(SmdrApiError::RangeTooLarge { max_days: 31 })
    );
    assert_eq!(SmdrCursor::decode("not-hex"), Err(SmdrApiError::BadCursor));
    let bad: Result<SmdrQueryParams, _> =
        serde_json::from_str(r#"{"since_ms":0,"until_ms":1,"cursor":"zz"}"#);
    assert!(bad.is_err());
}

#[test]
fn locked_writer_reports_store_unavailable() {
    let tmp = tempfile::tempdir().unwrap();
    let db = setup(&tmp);
    db.execute_batch("PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE;")
        .unwrap();
    insert(&db, base(), "101", "in", "1");
    assert_eq!(
        query(
            &db_path(tmp.path()),
            &lease_journal_path(tmp.path()),
            &params(50)
        ),
        Err(SmdrApiError::StoreUnavailable)
    );
    db.execute_batch("COMMIT;").unwrap();
}

#[test]
fn rows_never_carry_the_raw_line() {
    let tmp = tempfile::tempdir().unwrap();
    let db = setup(&tmp);
    insert(&db, base(), "101", "in", "1");
    let page = query(
        &db_path(tmp.path()),
        &lease_journal_path(tmp.path()),
        &params(50),
    )
    .unwrap();
    let json = serde_json::to_string(&page).unwrap();
    assert!(!json.contains("RAW-SECRET"), "{json}");
}
