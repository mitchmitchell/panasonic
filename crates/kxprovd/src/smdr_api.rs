//! Read-only call-log queries (S6). Reads SQLite only; this module never reaches the port.

use crate::smdr_store::{SMDR_DB_NAME, SMDR_DIR_NAME};
use chrono::{DateTime, SecondsFormat, Utc};
use kxprov_api::{
    CallDirection, SmdrApiError, SmdrCallView, SmdrCursor, SmdrPage, SmdrQueryParams,
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
pub fn query(db: &Path, p: &SmdrQueryParams) -> Result<SmdrPage, SmdrApiError> {
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
                    ring_s, duration_s, acc, cd
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
                        cd: non_empty(r.get(11)?),
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
                tracing::warn!(direction = other, "smdr row has unknown direction");
                return Err(SmdrApiError::StoreUnavailable);
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
    Ok(SmdrPage { calls, next })
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
            query(&db_path(tmp.path()), &p),
            Err(SmdrApiError::StoreUnavailable)
        );
    }

    #[test]
    fn store_line_is_queryable() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = SmdrStore::open(tmp.path(), &[], DateOrder::default()).unwrap();
        let _ = store.ingest(
            SmdrLine::new("not a call".into()),
            rx("2026-11-01T12:00:00Z"),
        );
        let p = SmdrQueryParams {
            limit: QueryLimit::new(10).unwrap(),
            ..SmdrQueryParams::with_defaults(
                None,
                None,
                rx("2026-11-01T13:00:00Z").timestamp_millis(),
            )
        };
        let page = query(&db_path(tmp.path()), &p).unwrap();
        assert!(page.calls.is_empty());
        assert!(page.next.is_none());
    }
}
