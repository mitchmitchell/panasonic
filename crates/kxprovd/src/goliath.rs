//! Off-box backup copy queue (A3: local directory target; SSH/age in later phases).

use crate::backup::BackupMeta;
use kxprov_api::GoliathCopyStatus;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct GoliathQueue {
    target: PathBuf,
    state: Arc<Mutex<HashMap<String, GoliathCopyStatus>>>,
}

impl GoliathQueue {
    pub fn new(target: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&target)?;
        Ok(Self {
            target,
            state: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn enqueue_copy(&self, meta: &BackupMeta) {
        let mut st = self.state.lock().expect("goliath lock");
        st.insert(meta.id.clone(), GoliathCopyStatus::Pending);
        drop(st);
        let target = self.target.clone();
        let id = meta.id.clone();
        let src = meta.path.clone();
        let sha = meta.sha256.clone();
        let state = Arc::clone(&self.state);
        std::thread::spawn(move || {
            let result = copy_one(&target, &id, &src, &sha);
            let mut st = state.lock().expect("goliath lock");
            st.insert(
                id,
                if result {
                    GoliathCopyStatus::Ok
                } else {
                    GoliathCopyStatus::Failed
                },
            );
        });
    }

    pub fn status(&self, backup_id: &str) -> GoliathCopyStatus {
        self.state
            .lock()
            .expect("goliath lock")
            .get(backup_id)
            .cloned()
            .unwrap_or(GoliathCopyStatus::Pending)
    }

    pub fn target(&self) -> &PathBuf {
        &self.target
    }
}

fn copy_one(target: &std::path::Path, id: &str, src: &std::path::Path, sha256: &str) -> bool {
    let dst_dbh = target.join(format!("{id}.dbh"));
    let dst_meta = target.join(format!("{id}.meta.json"));
    if std::fs::copy(src, &dst_dbh).is_err() {
        return false;
    }
    let meta = serde_json::json!({
        "backup_id": id,
        "sha256": sha256,
        "profile": "sim",
    });
    std::fs::write(dst_meta, meta.to_string()).is_ok()
}
