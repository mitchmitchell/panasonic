use chrono::{DateTime, Duration, NaiveDate, Utc};
use kxtd1232::smdr::{parse_line, DateOrder, Direction, ParsedLine, SmdrLine, SmdrRecord};
use rusqlite::{params, Connection};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const SMDR_DIR_NAME: &str = "smdr";
pub const SMDR_DB_NAME: &str = "smdr.db";
pub const RAW_JOURNAL_PREFIX: &str = "smdr-raw-";
pub const RAW_JOURNAL_SUFFIX: &str = ".log";
pub const DEFAULT_RETENTION_DAYS: u32 = 365;
const FILE_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS smdr_call (
    id INTEGER PRIMARY KEY,
    rx_ts_utc TEXT NOT NULL,
    pbx_local TEXT NOT NULL,
    ext TEXT NOT NULL,
    co TEXT NOT NULL,
    direction TEXT NOT NULL,
    number TEXT NOT NULL,
    cid_text TEXT NOT NULL,
    ring_s INTEGER,
    duration_s INTEGER,
    acc TEXT NOT NULL,
    cd TEXT NOT NULL,
    raw TEXT NOT NULL,
    parse_ok INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS smdr_call_dedup
    ON smdr_call (pbx_local, ext, co, number, ifnull(duration_s, -1));
CREATE INDEX IF NOT EXISTS smdr_call_rx ON smdr_call (rx_ts_utc);
CREATE TABLE IF NOT EXISTS smdr_unparsed (
    id INTEGER PRIMARY KEY,
    rx_ts_utc TEXT NOT NULL,
    raw TEXT NOT NULL,
    error TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS smdr_unparsed_rx ON smdr_unparsed (rx_ts_utc);
";

#[derive(Debug, Error)]
pub enum SmdrStoreError {
    #[error("smdr io: {0}")]
    Io(#[from] std::io::Error),
    #[error("smdr db: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("smdr dir {store} is inside backup set {backup}")]
    InsideBackupSet { store: PathBuf, backup: PathBuf },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    Stored,
    Duplicate,
    Unparsed,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PruneReport {
    pub calls: usize,
    pub unparsed: usize,
    pub journals: usize,
}

pub struct SmdrStore {
    dir: PathBuf,
    db: Connection,
    order: DateOrder,
}

impl SmdrStore {
    pub fn open(
        data_dir: &Path,
        backup_sets: &[&Path],
        order: DateOrder,
    ) -> Result<Self, SmdrStoreError> {
        let dir = data_dir.join(SMDR_DIR_NAME);
        for backup in backup_sets {
            if dir.starts_with(backup) || backup.starts_with(&dir) {
                return Err(SmdrStoreError::InsideBackupSet {
                    store: dir,
                    backup: backup.to_path_buf(),
                });
            }
        }
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(DIR_MODE))?;
        let db_path = dir.join(SMDR_DB_NAME);
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(FILE_MODE)
            .open(&db_path)?;
        fs::set_permissions(&db_path, fs::Permissions::from_mode(FILE_MODE))?;
        let db = Connection::open(&db_path)?;
        db.execute_batch(SCHEMA)?;
        Ok(Self { dir, db, order })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn journal_path(&self, day: NaiveDate) -> PathBuf {
        self.dir.join(format!(
            "{RAW_JOURNAL_PREFIX}{}{RAW_JOURNAL_SUFFIX}",
            day.format("%Y%m%d")
        ))
    }

    pub fn ingest(
        &mut self,
        line: SmdrLine,
        rx: DateTime<Utc>,
    ) -> Result<IngestOutcome, SmdrStoreError> {
        let rx_ts = rx.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.append_raw(rx, &rx_ts, line.raw())?;
        match parse_line(line, self.order) {
            ParsedLine::Record { line, record } => self.insert_call(&rx_ts, line.raw(), &record),
            ParsedLine::Unparsed { line, error } => {
                self.db.execute(
                    "INSERT INTO smdr_unparsed (rx_ts_utc, raw, error) VALUES (?1, ?2, ?3)",
                    params![rx_ts, line.raw(), error.to_string()],
                )?;
                Ok(IngestOutcome::Unparsed)
            }
            ParsedLine::PageHeader(_) | ParsedLine::ModemInit(_) => Ok(IngestOutcome::Skipped),
        }
    }

    fn append_raw(&self, rx: DateTime<Utc>, rx_ts: &str, raw: &str) -> Result<(), SmdrStoreError> {
        let path = self.journal_path(rx.date_naive());
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(FILE_MODE)
            .open(&path)?;
        file.set_permissions(fs::Permissions::from_mode(FILE_MODE))?;
        let escaped = raw.replace('\\', "\\\\").replace('\t', "\\t");
        writeln!(file, "{rx_ts}\t{escaped}")?;
        file.sync_data()?;
        Ok(())
    }

    fn insert_call(
        &self,
        rx_ts: &str,
        raw: &str,
        r: &SmdrRecord,
    ) -> Result<IngestOutcome, SmdrStoreError> {
        let pbx_local = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}",
            r.date.year, r.date.month, r.date.day, r.time.hour, r.time.minute
        );
        let direction = match r.direction {
            Direction::Incoming => "in",
            Direction::Outgoing => "out",
        };
        let n = self.db.execute(
            "INSERT OR IGNORE INTO smdr_call
             (rx_ts_utc, pbx_local, ext, co, direction, number, cid_text,
              ring_s, duration_s, acc, cd, raw, parse_ok)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1)",
            params![
                rx_ts,
                pbx_local,
                r.ext,
                r.co,
                direction,
                r.number,
                r.cid_name,
                r.ring_s,
                r.duration_s,
                r.acc_code,
                r.cd,
                raw
            ],
        )?;
        Ok(if n == 0 {
            IngestOutcome::Duplicate
        } else {
            IngestOutcome::Stored
        })
    }

    pub fn prune(
        &self,
        now: DateTime<Utc>,
        retention_days: u32,
    ) -> Result<PruneReport, SmdrStoreError> {
        let cutoff = now - Duration::days(i64::from(retention_days));
        let cutoff_ts = cutoff.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let calls = self.db.execute(
            "DELETE FROM smdr_call WHERE rx_ts_utc < ?1",
            params![cutoff_ts],
        )?;
        let unparsed = self.db.execute(
            "DELETE FROM smdr_unparsed WHERE rx_ts_utc < ?1",
            params![cutoff_ts],
        )?;
        let cutoff_day = cutoff.date_naive();
        let mut journals = 0;
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(day) = name
                .to_str()
                .and_then(|n| n.strip_prefix(RAW_JOURNAL_PREFIX))
                .and_then(|n| n.strip_suffix(RAW_JOURNAL_SUFFIX))
                .and_then(|d| NaiveDate::parse_from_str(d, "%Y%m%d").ok())
            else {
                continue;
            };
            if day < cutoff_day {
                fs::remove_file(entry.path())?;
                journals += 1;
            }
        }
        Ok(PruneReport {
            calls,
            unparsed,
            journals,
        })
    }

    pub fn call_count(&self) -> Result<u64, SmdrStoreError> {
        Ok(self
            .db
            .query_row("SELECT count(*) FROM smdr_call", [], |r| r.get(0))?)
    }

    pub fn unparsed_count(&self) -> Result<u64, SmdrStoreError> {
        Ok(self
            .db
            .query_row("SELECT count(*) FROM smdr_unparsed", [], |r| r.get(0))?)
    }
}

pub fn backup_sets(config: &crate::config::Config) -> [PathBuf; 2] {
    [
        config.data_dir.join("backups"),
        config.goliath_target.clone(),
    ]
}
