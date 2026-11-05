use chrono::Utc;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const GAP_TRACKING_ISSUE: &str = kxprov_api::GAP_TRACKING;
/// File name of the lease journal under a profile data directory.
pub const LEASE_JOURNAL_NAME: &str = "port-lease.jsonl";
const FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseEvent {
    Requested,
    Granted,
    Refused,
    TimedOut,
    ReaderPaused,
    Released,
    ReaderResumed,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LeaseRecord {
    pub ts_utc: String,
    pub event: LeaseEvent,
    pub job_id: String,
    pub gap_tracking: String,
}

pub trait LeaseLog: Send {
    fn append(&mut self, event: LeaseEvent, job_id: &str) -> std::io::Result<()>;
}

impl LeaseLog for LeaseJournal {
    fn append(&mut self, event: LeaseEvent, job_id: &str) -> std::io::Result<()> {
        LeaseJournal::append(self, event, job_id)
    }
}

pub struct LeaseJournal {
    path: PathBuf,
}

impl LeaseJournal {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&mut self, event: LeaseEvent, job_id: &str) -> std::io::Result<()> {
        let record = LeaseRecord {
            ts_utc: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            event,
            job_id: job_id.to_string(),
            gap_tracking: GAP_TRACKING_ISSUE.to_string(),
        };
        let line = serde_json::to_string(&record).map_err(std::io::Error::other)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(FILE_MODE)
            .open(&self.path)?;
        file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))?;
        writeln!(file, "{line}")?;
        file.sync_data()
    }

    pub fn read_all(&self) -> std::io::Result<Vec<LeaseRecord>> {
        std::fs::read_to_string(&self.path)?
            .lines()
            .map(|l| serde_json::from_str(l).map_err(std::io::Error::other))
            .collect()
    }
}
