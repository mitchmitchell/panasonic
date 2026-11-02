//! Read-only call-log queries (S6). Reads SQLite only; this module never reaches the port.

use crate::lease_journal::{LeaseEvent, LeaseRecord, LEASE_JOURNAL_NAME};
use crate::smdr_store::{SMDR_DB_NAME, SMDR_DIR_NAME};
use chrono::{DateTime, SecondsFormat, Utc};
use kxprov_api::{
    CallDirection, GapWindow, SmdrApiError, SmdrCallView, SmdrCursor, SmdrPage, SmdrQueryParams,
};
use rusqlite::{params, Connection, ErrorCode, OpenFlags};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long a read waits on the ingest writer before reporting [`SmdrApiError::StoreUnavailable`].
pub const READ_BUSY_TIMEOUT: Duration = Duration::from_millis(250);

/// Path of the call-log database under a profile data directory.
pub fn db_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SMDR_DIR_NAME).join(SMDR_DB_NAME)
}

/// Path of the port lease journal that gap windows are read from.
pub fn lease_journal_path(data_dir: &Path) -> PathBuf {
    data_dir.join(LEASE_JOURNAL_NAME)
}

/// Reader gap windows from the lease journal that overlap `[since, until)`, oldest first.
///
/// One window per lease: a repeated `reader_paused` for the same job extends nothing, and a
/// pause for a different job closes any window still open, because the port has one holder.
/// A missing journal means no lease was ever taken. A line that does not parse is skipped,
/// because a crash can leave a torn final line and the rest of the journal is still valid.
pub fn gap_windows(
    journal: &Path,
    since: &str,
    until: &str,
) -> Result<Vec<GapWindow>, SmdrApiError> {
    let text = match std::fs::read_to_string(journal) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            tracing::warn!(%e, "lease journal unreadable");
            return Err(SmdrApiError::StoreUnavailable);
        }
    };
    let mut done: Vec<GapWindow> = Vec::new();
    let mut open: Option<GapWindow> = None;
    for line in text.lines() {
        let rec: LeaseRecord = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(%e, "lease journal: skipping unparsable line");
                continue;
            }
        };
        match rec.event {
            LeaseEvent::ReaderPaused => {
                if open.as_ref().is_some_and(|g| g.job_id == rec.job_id) {
                    continue;
                }
                if let Some(mut prev) = open.take() {
                    prev.to_utc = Some(rec.ts_utc.clone());
                    done.push(prev);
                }
                open = Some(GapWindow {
                    from_utc: rec.ts_utc,
                    to_utc: None,
                    job_id: rec.job_id,
                    tracking: kxprov_api::GAP_TRACKING.to_string(),
                });
            }
            LeaseEvent::ReaderResumed => {
                if open.as_ref().is_some_and(|g| g.job_id == rec.job_id) {
                    if let Some(mut g) = open.take() {
                        g.to_utc = Some(rec.ts_utc);
                        done.push(g);
                    }
                }
            }
            LeaseEvent::Requested
            | LeaseEvent::Granted
            | LeaseEvent::Refused
            | LeaseEvent::TimedOut
            | LeaseEvent::Released => {}
        }
    }
    done.extend(open);
    done.retain(|g| {
        g.from_utc.as_str() < until && g.to_utc.as_deref().is_none_or(|to| to >= since)
    });
    Ok(done)
}

/// Opens a connection that SQLite itself refuses to write through; separate from the ingest writer.
pub fn open_read_only(db: &Path) -> Result<Connection, SmdrApiError> {
    let conn = Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(store_err)?;
    conn.busy_timeout(READ_BUSY_TIMEOUT).map_err(store_err)?;
    Ok(conn)
}

fn store_err(e: rusqlite::Error) -> SmdrApiError {
    match e.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => {
            tracing::debug!("smdr read busy");
        }
        other => tracing::warn!(?other, "smdr read failed"),
    }
    SmdrApiError::StoreUnavailable
}

fn ts(ms: i64) -> Result<String, SmdrApiError> {
    let dt = DateTime::<Utc>::from_timestamp_millis(ms).ok_or(SmdrApiError::BadRange)?;
    let s = dt.to_rfc3339_opts(SecondsFormat::Millis, true);
    if s.len() == 24 {
        Ok(s)
    } else {
        Err(SmdrApiError::BadRange)
    }
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn direction_wire(d: CallDirection) -> &'static str {
    match d {
        CallDirection::Incoming => "in",
        CallDirection::Outgoing => "out",
    }
}

/// One page of stored calls in `[since, until)`, newest first, keyset-paged by `(rx_ts_utc, id)`.
pub fn query(db: &Path, journal: &Path, p: &SmdrQueryParams) -> Result<SmdrPage, SmdrApiError> {
    p.validate()?;
    let since = ts(p.since_ms)?;
    let until = ts(p.until_ms)?;
    let conn = open_read_only(db)?;
    let limit = usize::from(p.limit.get());
    let (cur_ts, cur_id) = match &p.cursor {
        Some(c) => (Some(c.rx_ts_utc().to_string()), Some(c.id())),
        None => (None, None),
    };
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, rx_ts_utc, pbx_local, ext, co, direction, number, cid_text,
                    ring_s, duration_s, acc
             FROM smdr_call
             WHERE parse_ok = 1
               AND rx_ts_utc >= ?1 AND rx_ts_utc < ?2
               AND (?3 IS NULL OR ext = ?3)
               AND (?4 IS NULL OR direction = ?4)
               AND (?5 IS NULL OR rx_ts_utc < ?5 OR (rx_ts_utc = ?5 AND id < ?6))
             ORDER BY rx_ts_utc DESC, id DESC
             LIMIT ?7",
        )
        .map_err(store_err)?;
    let rows = stmt
        .query_map(
            params![
                since,
                until,
                p.ext.as_deref().map(str::trim),
                p.direction.map(direction_wire),
                cur_ts,
                cur_id,
                i64::from(p.limit.get()) + 1
            ],
            |r| {
                let dir: String = r.get(5)?;
                Ok((
                    dir,
                    SmdrCallView {
                        id: r.get(0)?,
                        rx_ts_utc: r.get(1)?,
                        pbx_local: r.get(2)?,
                        ext: r.get(3)?,
                        co: r.get(4)?,
                        direction: CallDirection::Incoming,
                        number: r.get(6)?,
                        cid_text: non_empty(r.get(7)?),
                        ring_s: r.get(8)?,
                        duration_s: r.get(9)?,
                        acc: non_empty(r.get(10)?),
                    },
                ))
            },
        )
        .map_err(store_err)?;
    let mut calls = Vec::with_capacity(limit + 1);
    for row in rows {
        let (dir, mut view) = row.map_err(store_err)?;
        view.direction = match dir.as_str() {
            "out" => CallDirection::Outgoing,
            "in" => CallDirection::Incoming,
            other => {
                tracing::warn!(
                    id = view.id,
                    direction = other,
                    "smdr row has unknown direction"
                );
                return Err(SmdrApiError::CorruptRow { id: view.id });
            }
        };
        calls.push(view);
    }
    let next = if calls.len() > limit {
        calls.truncate(limit);
        calls
            .last()
            .map(|c| SmdrCursor::new(c.rx_ts_utc.clone(), c.id))
    } else {
        None
    };
    let gaps = gap_windows(journal, &since, &until)?;
    Ok(SmdrPage { calls, next, gaps })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test setup failures should abort the test"
    )]
    use super::*;
    use crate::smdr_store::SmdrStore;
    use kxprov_api::QueryLimit;
    use kxtd1232::smdr::{DateOrder, SmdrLine};

    fn rx(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn source_never_names_the_port_or_a_transport() {
        let src = include_str!("smdr_api.rs");
        let body = src.split("#[cfg(test)]").next().unwrap();
        for word in [
            "port::",
            "transport",
            "DeviceArbiter",
            "PortManager",
            "serial",
            "tty",
        ] {
            assert!(!body.contains(word), "smdr_api must not reference {word}");
        }
    }

    #[test]
    fn read_only_connection_refuses_writes() {
        let tmp = tempfile::tempdir().unwrap();
        drop(SmdrStore::open(tmp.path(), &[], DateOrder::default()).unwrap());
        let conn = open_read_only(&db_path(tmp.path())).unwrap();
        let err = conn
            .execute("DELETE FROM smdr_call", [])
            .unwrap_err()
            .sqlite_error_code();
        assert_eq!(err, Some(ErrorCode::ReadOnly));
    }

    #[test]
    fn missing_database_is_store_unavailable() {
        let tmp = tempfile::tempdir().unwrap();
        let p = SmdrQueryParams::with_defaults(None, None, 1_800_000_000_000);
        assert_eq!(
            query(&db_path(tmp.path()), &lease_journal_path(tmp.path()), &p),
            Err(SmdrApiError::StoreUnavailable)
        );
    }

    #[test]
    fn stored_record_is_returned_with_its_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = SmdrStore::open(tmp.path(), &[], DateOrder::Mdy).unwrap();
        let raw = include_str!("../../kxtd1232/tests/fixtures/smdr-v1/outgoing.txt")
            .lines()
            .next()
            .unwrap()
            .to_string();
        store
            .ingest(SmdrLine::new(raw), rx("2026-11-01T12:00:00Z"))
            .expect("fixture record ingests");
        store
            .ingest(
                SmdrLine::new("not a call".into()),
                rx("2026-11-01T12:00:01Z"),
            )
            .expect("unparsed line is journaled");
        let p = SmdrQueryParams {
            limit: QueryLimit::new(10).unwrap(),
            ..SmdrQueryParams::with_defaults(
                None,
                None,
                rx("2026-11-01T13:00:00Z").timestamp_millis(),
            )
        };
        let page = query(&db_path(tmp.path()), &lease_journal_path(tmp.path()), &p).unwrap();
        assert_eq!(page.calls.len(), 1, "only the parsed record is a call");
        let c = &page.calls[0];
        assert_eq!(c.rx_ts_utc, "2026-11-01T12:00:00.000Z");
        assert_eq!(c.ext, "101");
        assert_eq!(c.co, "01");
        assert_eq!(c.direction, CallDirection::Outgoing);
        assert_eq!(c.number, "5551230000");
        assert!(page.next.is_none());
    }

    #[test]
    fn unknown_direction_is_a_typed_corrupt_row() {
        let tmp = tempfile::tempdir().unwrap();
        drop(SmdrStore::open(tmp.path(), &[], DateOrder::Mdy).unwrap());
        let db = Connection::open(db_path(tmp.path())).unwrap();
        db.execute(
            "INSERT INTO smdr_call (rx_ts_utc, pbx_local, ext, co, direction, number, cid_text,
              ring_s, duration_s, acc, cd, raw, parse_ok)
             VALUES ('2026-11-01T12:00:00.000Z', '', '101', '01', 'sideways', '1', '',
              NULL, NULL, '', '', 'x', 1)",
            [],
        )
        .unwrap();
        let id = db.last_insert_rowid();
        let p = SmdrQueryParams::with_defaults(
            None,
            None,
            rx("2026-11-01T13:00:00Z").timestamp_millis(),
        );
        assert_eq!(
            query(&db_path(tmp.path()), &lease_journal_path(tmp.path()), &p),
            Err(SmdrApiError::CorruptRow { id })
        );
    }
}
