#![allow(clippy::unwrap_used, unused_imports)]

//! Security Analyst cases B2, B3, B6–B8 (draft).

mod common;

use common::{
    bearer_auth, init_test_daemon, write_testing_mode_backup_meta, READER_SECRET, WRITER_SECRET,
};
use kxprov_api::{
    ApiClient, OperationalMode, PlanChangeParams, Profile, RequestBody, ResponseResult,
    SetModeParams, TokensFile,
};
use kxprovd::config::{Config, ConfigError};
use kxprovd::mode::ModeFileBody;
use kxprovd::transition::TransitionBlockStore;
use std::time::Duration;

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

/// B7: revoking a token on disk is enforced on the next request without restarting the daemon.
#[tokio::test]
async fn b7_revocation_takes_effect_without_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = init_test_daemon(&tmp, uid, Profile::Sim);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let path = tmp.path().join("tokens.json");
    let mut file: TokensFile =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).expect("tokens file");
    for t in &mut file.tokens {
        if t.id.as_str() == "writer" {
            t.revoked = true;
        }
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();

    let mut c = ApiClient::connect(&sock).await.unwrap();
    let err = c
        .call_auth(
            RequestBody::PlanChange {
                params: PlanChangeParams {
                    kind: kxprov_api::FieldKindWire::CidName,
                    index: 0,
                    value: "REVOKED".into(),
                },
            },
            Some(bearer_auth(WRITER_SECRET)),
        )
        .await
        .expect_err("revoked writer");
    assert!(
        err.to_string().contains("unauthorized") || err.to_string().contains("invalid bearer"),
        "{err}"
    );
}

/// B8: gateway and admin Unix identities must differ at startup.
#[test]
fn b8_gateway_and_admin_uid_must_differ() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let mut cfg = Config::sim_test(tmp.path().to_path_buf(), tmp.path().join("sock"), uid);
    cfg.gateway_uid = uid;
    cfg.admin_uid = uid;
    assert!(matches!(cfg.validate(), Err(ConfigError::UidsMustDiffer)));
}
