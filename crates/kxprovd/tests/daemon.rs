#![allow(clippy::unwrap_used)]

mod common;

use common::{bearer_auth, init_test_daemon, APPROVER_SECRET, COMM_SECRET, WRITER_SECRET};
use kxprov_api::{
    ApiClient, ApplyPlanAwaitingStatus, FieldKindWire, OperationalMode, Profile, RequestBody,
    ResponseResult,
};
use kxprovd::locked::LockedStore;
use kxprovd::mode::{ModeFileBody, ProfileFileBody};
use std::time::Duration;

#[tokio::test]
async fn plan_immutable_and_token_bound() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = init_test_daemon(&tmp, uid, Profile::Sim);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut c = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::PlanChange(p) = c
        .call_auth(
            RequestBody::PlanChange {
                params: kxprov_api::PlanChangeParams {
                    kind: FieldKindWire::CidName,
                    index: 1,
                    value: "SYNTH".into(),
                },
            },
            Some(bearer_auth(WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("plan");
    };
    assert_eq!(p.plan_id.0.len(), 32);
    let ResponseResult::PlanChange(p2) = c
        .call_auth(
            RequestBody::PlanChange {
                params: kxprov_api::PlanChangeParams {
                    kind: FieldKindWire::CidName,
                    index: 1,
                    value: "SYNTH".into(),
                },
            },
            Some(bearer_auth(WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("plan2");
    };
    assert_ne!(p.plan_id, p2.plan_id, "each plan gets a fresh PlanId");
    assert_eq!(p.diff_hash, p2.diff_hash);
}

#[tokio::test]
async fn apply_requires_approval_on_prod() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("mode.json"),
        serde_json::to_vec_pretty(&ModeFileBody {
            mode: OperationalMode::Production,
            counter: 0,
        })
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("profile.json"),
        serde_json::to_vec_pretty(&ProfileFileBody {
            profile: Profile::Prod,
            counter: 0,
        })
        .unwrap(),
    )
    .unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = init_test_daemon(&tmp, uid, Profile::Prod);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut c = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::PlanChange(plan) = c
        .call_auth(
            RequestBody::PlanChange {
                params: kxprov_api::PlanChangeParams {
                    kind: FieldKindWire::CidNumber,
                    index: 2,
                    value: "456".into(),
                },
            },
            Some(bearer_auth(WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("plan");
    };

    let ResponseResult::ApplyApprovalRequired(r) = c
        .call_auth(
            RequestBody::ApplyPlan {
                params: kxprov_api::ApplyPlanParams {
                    plan_id: plan.plan_id.clone(),
                    diff_hash: plan.diff_hash.clone(),
                },
            },
            Some(bearer_auth(WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("approval_required result");
    };
    assert_eq!(r.plan_id, plan.plan_id);
    assert_eq!(r.status, ApplyPlanAwaitingStatus::ApprovalRequired);
}

#[tokio::test]
async fn sim_apply_without_approval() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = init_test_daemon(&tmp, uid, Profile::Sim);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut gw = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::PlanChange(plan) = gw
        .call_auth(
            RequestBody::PlanChange {
                params: kxprov_api::PlanChangeParams {
                    kind: FieldKindWire::CidName,
                    index: 3,
                    value: "OK".into(),
                },
            },
            Some(bearer_auth(WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("plan");
    };

    let ResponseResult::BackupNow(_) = gw
        .call_auth(RequestBody::BackupNow, Some(bearer_auth(WRITER_SECRET)))
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
            Some(bearer_auth(WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("apply job");
    };
    assert!(job.job_id.starts_with('j'));
    tokio::time::sleep(Duration::from_millis(150)).await;
}

/// Prod profile: approval consumed once; second apply returns approval_required again.
#[tokio::test]
async fn prod_apply_single_use_approval() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("mode.json"),
        serde_json::to_vec_pretty(&ModeFileBody {
            mode: OperationalMode::Production,
            counter: 0,
        })
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("profile.json"),
        serde_json::to_vec_pretty(&ProfileFileBody {
            profile: Profile::Prod,
            counter: 0,
        })
        .unwrap(),
    )
    .unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = init_test_daemon(&tmp, uid, Profile::Prod);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut gw = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::PlanChange(plan) = gw
        .call_auth(
            RequestBody::PlanChange {
                params: kxprov_api::PlanChangeParams {
                    kind: FieldKindWire::CidName,
                    index: 4,
                    value: "P".into(),
                },
            },
            Some(bearer_auth(WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("plan");
    };

    let mut approver = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::SubmitApproval(_) = approver
        .call_auth(
            RequestBody::SubmitApproval {
                params: kxprov_api::SubmitApprovalParams {
                    plan_id: plan.plan_id.as_str().to_string(),
                    diff_hash: plan.diff_hash.clone(),
                    profile: Profile::Prod,
                },
            },
            Some(bearer_auth(APPROVER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("submit");
    };

    let ResponseResult::BackupNow(_) = gw
        .call_auth(RequestBody::BackupNow, Some(bearer_auth(WRITER_SECRET)))
        .await
        .unwrap()
    else {
        panic!("backup");
    };

    let ResponseResult::Job(_) = gw
        .call_auth(
            RequestBody::ApplyPlan {
                params: kxprov_api::ApplyPlanParams {
                    plan_id: plan.plan_id.clone(),
                    diff_hash: plan.diff_hash.clone(),
                },
            },
            Some(bearer_auth(WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("apply job");
    };
    tokio::time::sleep(Duration::from_millis(150)).await;

    let ResponseResult::PlanChange(plan2) = gw
        .call_auth(
            RequestBody::PlanChange {
                params: kxprov_api::PlanChangeParams {
                    kind: FieldKindWire::CidName,
                    index: 4,
                    value: "P2".into(),
                },
            },
            Some(bearer_auth(WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("plan2");
    };

    let ResponseResult::ApplyApprovalRequired(_) = gw
        .call_auth(
            RequestBody::ApplyPlan {
                params: kxprov_api::ApplyPlanParams {
                    plan_id: plan2.plan_id,
                    diff_hash: plan2.diff_hash,
                },
            },
            Some(bearer_auth(WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("second apply needs fresh approval");
    };
}

#[tokio::test]
async fn token_b_cannot_apply_token_a_plan() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = init_test_daemon(&tmp, uid, Profile::Sim);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut a = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::PlanChange(plan) = a
        .call_auth(
            RequestBody::PlanChange {
                params: kxprov_api::PlanChangeParams {
                    kind: FieldKindWire::CidName,
                    index: 5,
                    value: "X".into(),
                },
            },
            Some(bearer_auth(WRITER_SECRET)),
        )
        .await
        .unwrap()
    else {
        panic!("plan");
    };

    let mut approver = ApiClient::connect(&sock).await.unwrap();
    let _ = approver
        .call_auth(
            RequestBody::SubmitApproval {
                params: kxprov_api::SubmitApprovalParams {
                    plan_id: plan.plan_id.as_str().to_string(),
                    diff_hash: plan.diff_hash.clone(),
                    profile: Profile::Sim,
                },
            },
            Some(bearer_auth(APPROVER_SECRET)),
        )
        .await
        .unwrap();

    let err = ApiClient::connect(&sock)
        .await
        .unwrap()
        .call_auth(
            RequestBody::ApplyPlan {
                params: kxprov_api::ApplyPlanParams {
                    plan_id: plan.plan_id,
                    diff_hash: plan.diff_hash,
                },
            },
            Some(bearer_auth(COMM_SECRET)),
        )
        .await
        .expect_err("wrong token owner");
    assert!(err.to_string().contains("token") || err.to_string().contains("plan"));
}

#[tokio::test]
async fn locked_persists_until_unlock() {
    let tmp = tempfile::tempdir().unwrap();
    let store = LockedStore::new(tmp.path());
    store.set_locked("test", Some("j1"), 1).expect("set locked");
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = init_test_daemon(&tmp, uid, Profile::Sim);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut c = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::Status(st) = c.call(RequestBody::Status).await.unwrap() else {
        panic!("status");
    };
    assert!(st.gates.locked);

    let ResponseResult::Unlock(u) = c
        .call_auth(
            RequestBody::Unlock {
                params: kxprov_api::UnlockParams {
                    job_id: "j1".into(),
                    reason: "verified backup".into(),
                },
            },
            None,
        )
        .await
        .unwrap()
    else {
        panic!("unlock");
    };
    assert!(u.unlocked);
    let ResponseResult::Status(st2) = c.call(RequestBody::Status).await.unwrap() else {
        panic!("status2");
    };
    assert!(!st2.gates.locked);
}
