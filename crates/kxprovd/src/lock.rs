//! Process lock (flock) and optional serial exclusivity.

use fs2::FileExt;
use std::fs::File;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LockError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("another kxprovd holds the lock")]
    Contended,
}

pub struct ProcessLock {
    _file: File,
    path: PathBuf,
}

impl ProcessLock {
    pub fn acquire(data_dir: &Path) -> Result<Self, LockError> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join("kxprovd.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)?;
        file.try_lock_exclusive().map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                LockError::Contended
            } else {
                LockError::Io(e)
            }
        })?;
        Ok(Self { _file: file, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
