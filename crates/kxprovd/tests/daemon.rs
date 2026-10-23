#![allow(clippy::unwrap_used)]

use kxprov_api::{
    ApiClient, FieldKindWire, OperationalMode, Profile, RequestAuth, RequestBody, ResponseResult,
    TokenId, MODE_SSH_NAMESPACE,
};
use kxprovd::locked::LockedStore;
use kxprovd::mode::ModeFileBody;
use kxprovd::Daemon;
use nix::unistd::getuid;
use std::process::Command;
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
async fn apply_requires_approval_on_prod() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests_profile(tmp.path(), uid, Profile::Prod);
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
}

#[tokio::test]
async fn sim_apply_without_approval() {
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

    let ResponseResult::BackupNow(_) = gw
        .call_auth(RequestBody::BackupNow, Some(gateway_auth("writer")))
        .await
        .unwrap()
    else {
        panic!("backup");
    };

    let ResponseResult::ApplyPlan(applied) = gw
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
    assert!(applied.blocks_verified >= 1);
}

fn install_test_mode_signers(dir: &std::path::Path) -> std::path::PathBuf {
    let key = dir.join("mode-test-key");
    Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&key)
        .args(["-N", ""])
        .status()
        .unwrap();
    let pub_line = String::from_utf8(
        Command::new("ssh-keygen")
            .args(["-y", "-f"])
            .arg(&key)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let parts: Vec<_> = pub_line.split_whitespace().collect();
    std::fs::write(
        dir.join("mode-signers"),
        format!("{} {} {}\n", MODE_SSH_NAMESPACE, parts[0], parts[1]),
    )
    .unwrap();
    key
}

fn sign_mode_nonce(key_path: &std::path::Path, nonce: &[u8]) -> String {
    let dir = tempfile::tempdir().unwrap();
    let nonce_path = dir.path().join("nonce");
    let sig_path = dir.path().join("nonce.sig");
    std::fs::write(&nonce_path, nonce).unwrap();
    Command::new("ssh-keygen")
        .args([
            "-Y",
            "sign",
            "-f",
            key_path.to_str().unwrap(),
            "-n",
            MODE_SSH_NAMESPACE,
        ])
        .arg(&nonce_path)
        .status()
        .unwrap();
    std::fs::read_to_string(sig_path).unwrap()
}

/// Prod hardware cannot apply in the sim harness; Test + Production mode keeps approval gates.
#[tokio::test]
async fn prod_apply_single_use_approval() {
    let tmp = tempfile::tempdir().unwrap();
    let key = install_test_mode_signers(tmp.path());
    let counter = 1u64;
    let nonce = kxprov_api::mode_sign_message(OperationalMode::Production, counter);
    let body = ModeFileBody {
        mode: OperationalMode::Production,
        counter,
        signature: sign_mode_nonce(&key, &nonce),
    };
    std::fs::write(
        tmp.path().join("mode.json"),
        serde_json::to_vec_pretty(&body).unwrap(),
    )
    .unwrap();
    std::fs::write(tmp.path().join("mode.counter"), "0").unwrap();
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests_profile(tmp.path(), uid, Profile::Test);
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
            Some(gateway_auth("writer")),
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
                    plan_id: plan.plan_id.clone(),
                    diff_hash: plan.diff_hash.clone(),
                },
            },
            Some(gateway_auth("approver")),
        )
        .await
        .unwrap()
    else {
        panic!("submit");
    };

    let ResponseResult::BackupNow(_) = gw
        .call_auth(RequestBody::BackupNow, Some(gateway_auth("writer")))
        .await
        .unwrap()
    else {
        panic!("backup");
    };

    let ResponseResult::ApplyPlan(_) = gw
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
                    index: 5,
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

    let mut approver = ApiClient::connect(&sock).await.unwrap();
    let _ = approver
        .call_auth(
            RequestBody::SubmitApproval {
                params: kxprov_api::SubmitApprovalParams {
                    plan_id: plan.plan_id.clone(),
                    diff_hash: plan.diff_hash.clone(),
                },
            },
            Some(gateway_auth("approver")),
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
