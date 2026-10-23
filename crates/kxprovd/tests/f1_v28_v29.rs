#![allow(clippy::unwrap_used, unused_imports)]

mod common;

use kxprov_api::{http_dispatch, mcp_invoke, HttpMethod, HttpStatus};
use kxprov_api::{
    ApiClient, FieldKindWire, OperationalMode, Profile, RequestAuth, RequestBody, ResponseResult,
    SetModeParams, TokenId,
};
use kxprovd::audit::AuditKind;
use kxprovd::mode::{ModeFileBody, ModeStore};
use kxprovd::sim_mark::SimMarkStore;
use kxprovd::transition::TransitionBlockStore;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

#[test]
fn route_table_no_mode_profile_over_http_or_mcp() {
    assert_eq!(
        http_dispatch(HttpMethod::Post, "/api/mode"),
        HttpStatus::NotFound
    );
    assert_eq!(mcp_invoke("set_mode"), HttpStatus::NotFound);
}

#[tokio::test]
async fn test_apply_without_backup_when_not_prod() {
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
    let (_d, sock) = common::init_test_daemon(&tmp, uid, Profile::Sim);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut gw = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::PlanChange(plan) = gw
        .call_auth(
            RequestBody::PlanChange {
                params: kxprov_api::PlanChangeParams {
                    kind: FieldKindWire::CidName,
                    index: 1,
                    value: "T".into(),
                },
            },
            Some(common::bearer_auth(common::WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("plan");
    };
    let ResponseResult::Job(job) = gw
        .call_auth(
            RequestBody::ApplyPlan {
                params: kxprov_api::ApplyPlanParams {
                    plan_id: plan.plan_id,
                    diff_hash: plan.diff_hash,
                },
            },
            Some(common::bearer_auth(common::WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("apply without prior backup on sim");
    };
    assert!(job.job_id.starts_with('j'));
}

#[tokio::test]
async fn testing_to_production_mismatch_blocks_writes() {
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
    let (_d, sock) = common::init_test_daemon(&tmp, uid, Profile::Sim);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut gw = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::BackupNow(first) = gw
        .call_auth(
            RequestBody::BackupNow,
            Some(common::bearer_auth(common::WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("backup");
    };
    let digest = {
        let meta_path = tmp
            .path()
            .join("backups")
            .join(format!("{}.meta", first.backup.id));
        let meta: kxprovd::backup::BackupMeta =
            serde_json::from_slice(&std::fs::read(meta_path).unwrap()).unwrap();
        meta.caller_id_digest.unwrap()
    };
    common::write_prod_mode_backup_meta(&tmp.path().join("backups"), &digest);
    let ResponseResult::PlanChange(plan) = gw
        .call_auth(
            RequestBody::PlanChange {
                params: kxprov_api::PlanChangeParams {
                    kind: FieldKindWire::CidName,
                    index: 2,
                    value: "CHANGED".into(),
                },
            },
            Some(common::bearer_auth(common::WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("plan");
    };
    let ResponseResult::Job(_) = gw
        .call_auth(
            RequestBody::ApplyPlan {
                params: kxprov_api::ApplyPlanParams {
                    plan_id: plan.plan_id.clone(),
                    diff_hash: plan.diff_hash.clone(),
                },
            },
            Some(common::bearer_auth(common::WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("apply testing");
    };
    let mut admin = ApiClient::connect(&sock).await.unwrap();
    let err = admin
        .call(RequestBody::SetMode {
            params: SetModeParams {
                mode: OperationalMode::Production,
                profile: Profile::Test,
            },
        })
        .await
        .expect_err("tables differ from first backup digest");
    assert!(err.to_string().contains("transition") || err.to_string().contains("verify"));

    assert!(TransitionBlockStore::new(tmp.path()).writes_blocked());
    let audit = ModeStore::new(tmp.path(), Profile::Sim)
        .audit()
        .load()
        .unwrap();
    assert!(audit
        .iter()
        .any(|e| e.kind == AuditKind::ModeTransitionMismatch));
}

#[test]
fn sim_mark_file_mode_0600() {
    let tmp = tempfile::tempdir().unwrap();
    let store = SimMarkStore::new(tmp.path());
    store.write(1).unwrap();
    let mode = std::fs::metadata(tmp.path().join("sim-passed.json"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}
