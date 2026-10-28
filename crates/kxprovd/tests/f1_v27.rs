#![allow(clippy::unwrap_used)]

mod common;

use kxprov_api::{
    resolve_profile_data_dir, ApiClient, FieldKindWire, OperationalMode, Profile, RequestBody,
    ResponseResult, SetModeParams,
};
use kxprovd::audit::AuditKind;
use kxprovd::mode::{ModeFileBody, ModeStore, ProfileFileBody};
use kxprovd::sim_mark::SimMarkStore;
use std::time::Duration;

fn write_mode(dir: &std::path::Path, mode: OperationalMode) {
    std::fs::write(
        dir.join("mode.json"),
        serde_json::to_vec_pretty(&ModeFileBody { mode, counter: 0 }).unwrap(),
    )
    .unwrap();
}

fn write_profile(dir: &std::path::Path, profile: Profile) {
    std::fs::write(
        dir.join("profile.json"),
        serde_json::to_vec_pretty(&ProfileFileBody {
            profile,
            counter: 0,
        })
        .unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn mode_missing_fail_closed_with_audit() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = common::init_test_daemon(&tmp, uid, Profile::Sim);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut c = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::Status(st) = c.call(RequestBody::Status).await.unwrap() else {
        panic!("status");
    };
    assert_eq!(st.operational_mode, OperationalMode::Production);
    let audit = ModeStore::new(tmp.path(), Profile::Sim)
        .audit()
        .load()
        .unwrap();
    assert!(audit.iter().any(|e| e.kind == AuditKind::ModeMissing));
}

#[tokio::test]
async fn mode_set_via_root_socket_increments_counter() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = common::init_test_daemon(&tmp, uid, Profile::Sim);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut admin = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::SetMode(r) = admin
        .call(RequestBody::SetMode {
            params: SetModeParams {
                mode: OperationalMode::Testing,
                profile: Profile::Test,
            },
        })
        .await
        .unwrap()
    else {
        panic!("set_mode");
    };
    assert_eq!(r.counter, 1);
    assert_eq!(r.mode, OperationalMode::Testing);
    assert_eq!(r.profile, Profile::Test);
    assert!(kxprovd::config::profile_epoch_counter_path(tmp.path(), Profile::Test).exists());
    let sim_root = resolve_profile_data_dir(tmp.path(), Profile::Sim);
    let raw = std::fs::read_to_string(sim_root.join("mode.json")).unwrap();
    assert!(raw.contains("counter"));
}

#[test]
fn mode_set_rejected_when_not_idle() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ModeStore::new(tmp.path(), Profile::Sim);
    let err = store
        .set_operational(OperationalMode::Production, Profile::Sim, false)
        .unwrap_err();
    assert!(err.to_string().contains("idle"));
}

#[tokio::test]
async fn sim_profile_skips_approval() {
    let tmp = tempfile::tempdir().unwrap();
    let sim_root = resolve_profile_data_dir(tmp.path(), Profile::Sim);
    std::fs::create_dir_all(&sim_root).unwrap();
    write_mode(&sim_root, OperationalMode::Production);
    write_profile(&sim_root, Profile::Sim);
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = common::init_test_daemon(&tmp, uid, Profile::Sim);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut gw = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::PlanChange(plan) = gw
        .call_auth(
            RequestBody::PlanChange {
                params: kxprov_api::PlanChangeParams {
                    kind: FieldKindWire::CidName,
                    index: 2,
                    value: "Z".into(),
                },
            },
            Some(common::bearer_auth(common::WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("plan");
    };
    let ResponseResult::BackupNow(_) = gw
        .call_auth(
            RequestBody::BackupNow,
            Some(common::bearer_auth(common::WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("backup");
    };
    let ResponseResult::Job(job) = gw
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
        panic!("apply job");
    };
    assert!(job.job_id.starts_with('j'));
}

#[tokio::test]
async fn submit_approval_accepts_eight_hex_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let sim_root = resolve_profile_data_dir(tmp.path(), Profile::Sim);
    std::fs::create_dir_all(&sim_root).unwrap();
    write_mode(&sim_root, OperationalMode::Production);
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = common::init_test_daemon(&tmp, uid, Profile::Sim);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut gw = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::PlanChange(plan) = gw
        .call_auth(
            RequestBody::PlanChange {
                params: kxprov_api::PlanChangeParams {
                    kind: FieldKindWire::CidName,
                    index: 3,
                    value: "P".into(),
                },
            },
            Some(common::bearer_auth(common::WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("plan");
    };
    let prefix = plan.plan_id.as_str()[..8].to_string();
    let mut approver = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::SubmitApproval(_) = approver
        .call_auth(
            RequestBody::SubmitApproval {
                params: kxprov_api::SubmitApprovalParams {
                    plan_id: prefix,
                    diff_hash: plan.diff_hash.clone(),
                    profile: Profile::Sim,
                },
            },
            Some(common::bearer_auth(common::APPROVER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("submit");
    };
}

#[test]
fn sim_mark_cleared_on_build_change() {
    let tmp = tempfile::tempdir().unwrap();
    let store = SimMarkStore::new(tmp.path());
    let stale = serde_json::json!({"build_hash":"old-build","marked_at_ms":1});
    std::fs::write(tmp.path().join("sim-passed.json"), stale.to_string()).unwrap();
    assert!(store.load_valid().unwrap().is_none());
}
