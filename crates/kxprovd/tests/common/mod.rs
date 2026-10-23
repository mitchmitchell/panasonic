#![allow(dead_code, unused_imports, clippy::unwrap_used)]

use kxprov_api::{OperationalMode, Profile, RequestAuth};
use kxprovd::test_util::write_integration_tokens;
use std::path::Path;

pub use kxprovd::test_util::{APPROVER_SECRET, COMM_SECRET, READER_SECRET, WRITER_SECRET};

pub fn kxprov_binary() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_kxprov") {
        return std::path::PathBuf::from(p);
    }
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target")
        });
    let bin = target.join("debug/kxprov");
    assert!(
        bin.is_file(),
        "kxprov not at {}; run via cargo test",
        bin.display()
    );
    bin
}

pub fn bearer_auth(secret: &str) -> RequestAuth {
    RequestAuth {
        bearer: secret.to_string(),
    }
}

pub fn init_test_daemon(
    tmp: &tempfile::TempDir,
    uid: u32,
    profile: Profile,
) -> (kxprovd::Daemon, std::path::PathBuf) {
    write_integration_tokens(&tmp.path().join("tokens.json"));
    kxprovd::Daemon::sim_for_tests_profile(tmp.path(), uid, profile)
}

/// Daemon where `local_uid` connects as read-only (not admin/gateway).
pub fn init_test_daemon_local_readonly(
    tmp: &tempfile::TempDir,
    local_uid: u32,
    profile: Profile,
) -> (kxprovd::Daemon, std::path::PathBuf) {
    kxprovd::Daemon::sim_for_tests_profile_peers(
        tmp.path(),
        local_uid,
        profile,
        local_uid.wrapping_add(9002),
        local_uid.wrapping_add(9001),
    )
}

pub fn write_testing_mode_backup_meta(backups_dir: &Path, digest: &str) {
    use kxprovd::backup::BackupMeta;
    let id = "testingmodebackup";
    let meta = BackupMeta {
        id: id.into(),
        created_at_ms: 9_000_000,
        bytes: 100,
        sha256: "aa".repeat(32),
        path: backups_dir.join(format!("{id}.dbh")),
        caller_id_digest: Some(digest.into()),
        operational_mode: Some(OperationalMode::Testing),
    };
    std::fs::write(
        backups_dir.join(format!("{id}.meta")),
        serde_json::to_vec_pretty(&meta).unwrap(),
    )
    .unwrap();
    let _ = std::fs::write(&meta.path, vec![0u8; 100]);
}

pub fn write_prod_mode_backup_meta(backups_dir: &Path, digest: &str) {
    use kxprovd::backup::BackupMeta;
    let id = "prodmodebackup";
    let meta = BackupMeta {
        id: id.into(),
        created_at_ms: 10_000_000,
        bytes: 100,
        sha256: "bb".repeat(32),
        path: backups_dir.join(format!("{id}.dbh")),
        caller_id_digest: Some(digest.into()),
        operational_mode: Some(OperationalMode::Production),
    };
    std::fs::write(
        backups_dir.join(format!("{id}.meta")),
        serde_json::to_vec_pretty(&meta).unwrap(),
    )
    .unwrap();
    let _ = std::fs::write(&meta.path, vec![0u8; 100]);
}
