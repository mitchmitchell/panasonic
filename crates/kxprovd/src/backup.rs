use crate::dbh::{self, parse_size, HEADER_TAIL_LEN};
use crate::goliath::GoliathQueue;
use crate::time::now_ms;
use kxprov_api::DEFAULT_BACKUP_KEEP;
use kxprov_api::GoliathCopyStatus;
use kxtd1232::tables::TABLES;
use kxtd1232::{Client, Transport};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("protocol: {0}")]
    Protocol(#[from] kxtd1232::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("dbh: {0}")]
    Dbh(#[from] dbh::DbhError),
    #[error("verify failed")]
    Verify,
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("no verified backup; header tail unavailable for writes")]
    NoBackupForWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupMeta {
    pub id: String,
    pub created_at_ms: u64,
    pub bytes: u64,
    pub sha256: String,
    pub path: PathBuf,
}

pub struct BackupStore {
    dir: PathBuf,
}

impl BackupStore {
    pub fn new(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn list(&self) -> Result<Vec<BackupMeta>, std::io::Error> {
        let mut out = Vec::new();
        for ent in std::fs::read_dir(&self.dir)? {
            let ent = ent?;
            let path = ent.path();
            if path.extension().is_some_and(|e| e == "meta") {
                let data = std::fs::read(&path)?;
                if let Ok(m) = serde_json::from_slice::<BackupMeta>(&data) {
                    out.push(m);
                }
            }
        }
        out.sort_by_key(|b| std::cmp::Reverse(b.created_at_ms));
        Ok(out)
    }

    /// Header bytes 0x1E–0xFF for the next assembly: from latest backup, or spec on first backup.
    pub fn header_tail_for_assembly(&self) -> Result<[u8; HEADER_TAIL_LEN], BackupError> {
        let list = self.list()?;
        if let Some(latest) = list.first() {
            let data = std::fs::read(&latest.path)?;
            return Ok(dbh::copy_header_tail_from_dbh(&data)?);
        }
        Ok(dbh::spec_header_tail())
    }

    /// Apply and other writes require at least one verified backup on disk.
    pub fn require_backup_for_write(&self) -> Result<(), BackupError> {
        if self.list()?.is_empty() {
            Err(BackupError::NoBackupForWrite)
        } else {
            Ok(())
        }
    }

    pub fn read_full_backup<T: Transport>(
        client: &mut Client<T>,
        password: &str,
    ) -> Result<std::collections::HashMap<u8, Vec<u8>>, BackupError> {
        client.login(password)?;
        let mut wire = std::collections::HashMap::new();
        for spec in TABLES.iter() {
            wire.insert(spec.id, client.read_table(spec.id)?);
        }
        let _ = client.end_binary();
        Ok(wire)
    }

    pub fn save_verified(
        &self,
        data: &[u8],
        goliath: &GoliathQueue,
    ) -> Result<BackupMeta, BackupError> {
        parse_size(data)?;
        let hash = hex::encode(Sha256::digest(data));
        let id = hash[..16].to_string();
        let created_at_ms = now_ms();
        let dbh_path = self.dir.join(format!("{id}.dbh"));
        std::fs::write(&dbh_path, data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dbh_path, std::fs::Permissions::from_mode(0o600))?;
        }
        let meta = BackupMeta {
            id: id.clone(),
            created_at_ms,
            bytes: data.len() as u64,
            sha256: hash.clone(),
            path: dbh_path.clone(),
        };
        let meta_path = self.dir.join(format!("{id}.meta"));
        std::fs::write(&meta_path, serde_json::to_vec_pretty(&meta)?)?;
        goliath.enqueue_copy(&meta);
        self.prune_to_keep(DEFAULT_BACKUP_KEEP)?;
        Ok(meta)
    }

    fn prune_to_keep(&self, keep: usize) -> Result<(), BackupError> {
        let mut list = self.list()?;
        while list.len() > keep {
            let Some(old) = list.pop() else {
                break;
            };
            let _ = std::fs::remove_file(&old.path);
            let meta_path = self.dir.join(format!("{}.meta", old.id));
            let _ = std::fs::remove_file(meta_path);
        }
        Ok(())
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

pub fn wire_to_dbh(
    store: &BackupStore,
    wire: &std::collections::HashMap<u8, Vec<u8>>,
) -> Result<Vec<u8>, BackupError> {
    let tail = store.header_tail_for_assembly()?;
    Ok(dbh::assemble_with_tail(wire, &tail)?)
}

pub fn goliath_status(meta: &BackupMeta, goliath: &GoliathQueue) -> GoliathCopyStatus {
    goliath.status(&meta.id)
}
