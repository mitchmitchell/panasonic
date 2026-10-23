#![allow(clippy::unwrap_used)]

use kxprov_api::{
    ApiClient, DiffHash, FieldKindWire, Profile, RequestAuth, RequestBody, ResponseResult, TokenId,
};
use kxprovd::locked::LockedStore;
use kxprovd::Daemon;
use nix::unistd::getuid;
use std::time::Duration;

fn gateway_auth(id: &str) -> RequestAuth {
    RequestAuth {
        token_id: TokenId(id.into()),
    }
}

#[tokio::test]
async fn plan_immutable_and_token_bound() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests(tmp.path(), uid);
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
            Some(gateway_auth("writer")),
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
            Some(gateway_auth("writer")),
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
async fn apply_requires_approval() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests(tmp.path(), uid);
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
            Some(gateway_auth("writer")),
        )
        .await
        .unwrap()
    else {
        panic!("plan");
    };

    let err = c
        .call_auth(
            RequestBody::ApplyPlan {
                params: kxprov_api::ApplyPlanParams {
                    plan_id: plan.plan_id.clone(),
                    diff_hash: plan.diff_hash.clone(),
                },
            },
            Some(gateway_auth("writer")),
        )
        .await
        .expect_err("no approval");
    assert!(err.to_string().contains("approval_required"));

    let err = ApiClient::connect(&sock)
        .await
        .unwrap()
        .call_auth(
            RequestBody::ApplyPlan {
                params: kxprov_api::ApplyPlanParams {
                    plan_id: plan.plan_id,
                    diff_hash: DiffHash("bad".into()),
                },
            },
            Some(gateway_auth("writer")),
        )
        .await
        .expect_err("bad hash");
    assert!(err.to_string().contains("plan") || err.to_string().contains("approval"));
}

#[tokio::test]
async fn approval_single_use() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests(tmp.path(), uid);
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
            Some(gateway_auth("writer")),
        )
        .await
        .unwrap()
    else {
        panic!("plan");
    };

    let mut admin = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::MintApproval(_) = admin
        .call(RequestBody::MintApproval {
            params: kxprov_api::MintApprovalParams {
                plan_id: plan.plan_id.clone(),
                diff_hash: plan.diff_hash.clone(),
                profile: Profile::Sim,
                admin_reauth_proof: "ok".into(),
            },
        })
        .await
        .unwrap()
    else {
        panic!("mint");
    };

    let ResponseResult::ApplyDeferred(_) = gw
        .call_auth(
            RequestBody::ApplyPlan {
                params: kxprov_api::ApplyPlanParams {
                    plan_id: plan.plan_id.clone(),
                    diff_hash: plan.diff_hash.clone(),
                },
            },
            Some(gateway_auth("writer")),
        )
        .await
        .unwrap()
    else {
        panic!("apply");
    };

    let err = gw
        .call_auth(
            RequestBody::ApplyPlan {
                params: kxprov_api::ApplyPlanParams {
                    plan_id: plan.plan_id,
                    diff_hash: plan.diff_hash,
                },
            },
            Some(gateway_auth("writer")),
        )
        .await
        .expect_err("reuse approval");
    assert!(err.to_string().contains("approval"));
}

#[tokio::test]
async fn token_b_cannot_apply_token_a_plan() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests(tmp.path(), uid);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut a = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::PlanChange(plan) = a
        .call_auth(
            RequestBody::PlanChange {
                params: kxprov_api::PlanChangeParams {
                    kind: FieldKindWire::CidName,
                    index: 4,
                    value: "X".into(),
                },
            },
            Some(gateway_auth("writer")),
        )
        .await
        .unwrap()
    else {
        panic!("plan");
    };

    let mut admin = ApiClient::connect(&sock).await.unwrap();
    let _ = admin
        .call(RequestBody::MintApproval {
            params: kxprov_api::MintApprovalParams {
                plan_id: plan.plan_id.clone(),
                diff_hash: plan.diff_hash.clone(),
                profile: Profile::Sim,
                admin_reauth_proof: "ok".into(),
            },
        })
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
            Some(gateway_auth("comm")),
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
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests(tmp.path(), uid);
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
