#![allow(
    clippy::unwrap_used,
    reason = "integration test: a panic on unexpected daemon output is the failure signal"
)]

//! #74: every enter-Production check and apply preflight leases the port under its own holder id.

mod common;

use kxprov_api::{
    resolve_profile_data_dir, ApiClient, FieldKindWire, OperationalMode, Profile, RequestBody,
    ResponseResult, SetModeParams,
};
use kxprovd::mode::ModeFileBody;
use std::collections::HashSet;
use std::time::Duration;

const SET_MODE_PREFIX: &str = "set-mode-production-verify";
const APPLY_PREFLIGHT_PREFIX: &str = "apply-preflight-diff-verify";

/// Holder ids the sim transport was opened under that start with `prefix`.
fn opened_holders(prefix: &str) -> Vec<String> {
    kxprovd::test_util::sim_open_holders()
        .into_iter()
        .filter(|h| h.starts_with(prefix))
        .collect()
}

/// Asserts at least two holders were seen and none repeats.
fn assert_distinct(holders: &[String], what: &str) {
    assert!(
        holders.len() >= 2,
        "{what}: expected two leases, got {holders:?}"
    );
    let unique: HashSet<&String> = holders.iter().collect();
    assert_eq!(
        unique.len(),
        holders.len(),
        "{what}: holder id reused: {holders:?}"
    );
}

/// Sets the operational mode as the local admin.
async fn set_mode(sock: &std::path::Path, mode: OperationalMode) {
    let mut admin = ApiClient::connect(sock).await.unwrap();
    admin
        .call(RequestBody::SetMode {
            params: SetModeParams {
                mode,
                profile: Profile::Test,
            },
        })
        .await
        .unwrap();
}

/// Plans one caller-id name change and applies it, returning once the apply is queued.
async fn plan_and_apply(gw: &mut ApiClient, index: u16, value: &str) {
    let ResponseResult::PlanChange(plan) = gw
        .call_auth(
            RequestBody::PlanChange {
                params: kxprov_api::PlanChangeParams {
                    kind: FieldKindWire::CidName,
                    index,
                    value: value.into(),
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
                    plan_id: plan.plan_id,
                    diff_hash: plan.diff_hash,
                },
            },
            Some(common::bearer_auth(common::WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("apply");
    };
}

#[tokio::test]
async fn repeated_enter_production_and_apply_preflight_use_distinct_lease_holders() {
    let tmp = tempfile::tempdir().unwrap();
    let sim_root = resolve_profile_data_dir(tmp.path(), Profile::Sim);
    std::fs::create_dir_all(&sim_root).unwrap();
    std::fs::write(
        sim_root.join("mode.json"),
        serde_json::to_vec_pretty(&ModeFileBody {
            mode: OperationalMode::Testing,
            counter: 0,
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
    let meta: kxprovd::backup::BackupMeta = serde_json::from_slice(
        &std::fs::read(
            sim_root
                .join("backups")
                .join(format!("{}.meta", first.backup.id)),
        )
        .unwrap(),
    )
    .unwrap();
    common::write_prod_mode_backup_meta(&sim_root.join("backups"), &meta.caller_id_digest.unwrap());

    for _ in 0..2 {
        set_mode(&sock, OperationalMode::Production).await;
        set_mode(&sock, OperationalMode::Testing).await;
    }
    plan_and_apply(&mut gw, 2, "FIRST").await;
    plan_and_apply(&mut gw, 3, "SECOND").await;

    assert_distinct(&opened_holders(SET_MODE_PREFIX), "enter-Production");
    assert_distinct(&opened_holders(APPLY_PREFLIGHT_PREFIX), "apply preflight");
}
