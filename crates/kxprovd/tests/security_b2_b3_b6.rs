#![allow(clippy::unwrap_used)]

//! Security Analyst cases B2, B3, B6 (draft).

mod support;

use kxprov_api::{ApiClient, OperationalMode, Profile, RequestBody, ResponseResult, SetModeParams};
use kxprovd::mode::ModeFileBody;
use kxprovd::transition::TransitionBlockStore;
use std::time::Duration;
use support::{bearer_auth, init_test_daemon, write_testing_mode_backup_meta, READER_SECRET};

/// B2: stale backup from another mode — only latest **Production** backup counts.
#[tokio::test]
async fn b2_stale_testing_mode_backup_ignored_for_prod_transition() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("mode.json"),
        serde_json::to_vec_pretty(&ModeFileBody {
            mode: OperationalMode::Testing,
        })
        .unwrap(),
    )
    .unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = init_test_daemon(&tmp, uid, Profile::Test);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let live_digest = {
        let cfg = kxprovd::config::Config::sim_test(
            tmp.path().to_path_buf(),
            tmp.path().join("kxprovd.sock"),
            uid,
        );
        kxprovd::transition::live_caller_id_digest(&cfg).unwrap()
    };
    write_testing_mode_backup_meta(&tmp.path().join("backups"), &live_digest);

    let mut admin = ApiClient::connect(&sock).await.unwrap();
    let err = admin
        .call(RequestBody::SetMode {
            params: SetModeParams {
                mode: OperationalMode::Production,
                profile: Profile::Test,
            },
        })
        .await
        .expect_err("no prod backup");
    assert!(
        err.to_string().contains("backup") || err.to_string().contains("transition"),
        "{err}"
    );
    assert!(TransitionBlockStore::new(tmp.path()).writes_blocked());
}

/// B3: BackupNow with read scope only is denied.
#[tokio::test]
async fn b3_backup_now_requires_write_scope_not_read() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = init_test_daemon(&tmp, uid, Profile::Sim);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut c = ApiClient::connect(&sock).await.unwrap();
    let err = c
        .call_auth(RequestBody::BackupNow, Some(bearer_auth(READER_SECRET)))
        .await
        .expect_err("read scope");
    assert!(
        err.to_string().contains("forbidden") || err.to_string().contains("scope"),
        "{err}"
    );
}

/// B6: missing production backup fails closed on switch to Production.
#[tokio::test]
async fn b6_missing_prod_backup_blocks_transition() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = init_test_daemon(&tmp, uid, Profile::Sim);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut admin = ApiClient::connect(&sock).await.unwrap();
    let err = admin
        .call(RequestBody::SetMode {
            params: SetModeParams {
                mode: OperationalMode::Production,
                profile: Profile::Sim,
            },
        })
        .await
        .expect_err("missing backup");
    assert!(err.to_string().contains("backup") || err.to_string().contains("transition"));
    assert!(TransitionBlockStore::new(tmp.path()).writes_blocked());
}
