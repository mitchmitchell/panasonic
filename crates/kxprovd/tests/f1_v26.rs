#![allow(clippy::unwrap_used)]

use ed25519_dalek::{Signer, SigningKey};
use kxprov_api::{
    mode_sign_message, ApiClient, FieldKindWire, OperationalMode, Profile, RequestAuth,
    RequestBody, ResponseResult, SetModeParams, TokenId,
};
use kxprovd::audit::AuditKind;
use kxprovd::mode::{ModeFileBody, ModeSigner, ModeSignersFile, ModeStore};
use kxprovd::Daemon;
use nix::unistd::getuid;
use std::path::Path;
use std::time::Duration;

fn gateway_auth(id: &str) -> RequestAuth {
    RequestAuth {
        token_id: TokenId(id.into()),
    }
}

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

pub fn install_mode_signers(dir: &Path, key: &SigningKey) {
    let vk = key.verifying_key();
    let signers = ModeSignersFile {
        signers: vec![ModeSigner {
            id: "test".into(),
            public_key_hex: hex::encode(vk.to_bytes()),
        }],
    };
    std::fs::write(
        dir.join("mode-signers.json"),
        serde_json::to_vec_pretty(&signers).unwrap(),
    )
    .unwrap();
}

fn signed_mode_body(mode: OperationalMode, counter: u64, key: &SigningKey) -> ModeFileBody {
    let msg = mode_sign_message(mode, counter);
    let sig = key.sign(&msg);
    ModeFileBody {
        mode,
        counter,
        signature: hex::encode(sig.to_bytes()),
    }
}

fn write_mode_file(dir: &Path, body: &ModeFileBody) {
    std::fs::write(
        dir.join("mode.json"),
        serde_json::to_vec_pretty(body).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn mode_missing_fail_closed_with_audit() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests(tmp.path(), uid);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut c = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::Status(st) = c.call(RequestBody::Status).await.unwrap() else {
        panic!("status");
    };
    assert_eq!(st.operational_mode, OperationalMode::Production);
    let audit = ModeStore::new(tmp.path()).audit().load().unwrap();
    assert!(audit.iter().any(|e| e.kind == AuditKind::ModeMissing));
}

#[tokio::test]
async fn mode_bad_signature_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    install_mode_signers(tmp.path(), &test_signing_key());
    write_mode_file(
        tmp.path(),
        &ModeFileBody {
            mode: OperationalMode::Testing,
            counter: 1,
            signature: "00".repeat(32),
        },
    );
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests(tmp.path(), uid);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut c = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::Status(st) = c.call(RequestBody::Status).await.unwrap() else {
        panic!("status");
    };
    assert_eq!(st.operational_mode, OperationalMode::Production);
    let audit = ModeStore::new(tmp.path()).audit().load().unwrap();
    assert!(audit.iter().any(|e| e.kind == AuditKind::ModeBadSignature));
}

#[tokio::test]
async fn mode_counter_rollback_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let key = test_signing_key();
    install_mode_signers(tmp.path(), &key);
    std::fs::write(tmp.path().join("mode.counter"), "5").unwrap();
    write_mode_file(
        tmp.path(),
        &signed_mode_body(OperationalMode::Testing, 3, &key),
    );
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests(tmp.path(), uid);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut c = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::Status(st) = c.call(RequestBody::Status).await.unwrap() else {
        panic!("status");
    };
    assert_eq!(st.operational_mode, OperationalMode::Production);
    let audit = ModeStore::new(tmp.path()).audit().load().unwrap();
    assert!(audit
        .iter()
        .any(|e| e.kind == AuditKind::ModeCounterRollback));
}

#[tokio::test]
async fn mode_set_via_root_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let key = test_signing_key();
    install_mode_signers(tmp.path(), &key);
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests(tmp.path(), uid);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let msg = mode_sign_message(OperationalMode::Production, 1);
    let sig = hex::encode(key.sign(&msg).to_bytes());
    let mut admin = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::SetMode(r) = admin
        .call(RequestBody::SetMode {
            params: SetModeParams {
                mode: OperationalMode::Production,
                counter: 1,
                signature: sig,
            },
        })
        .await
        .unwrap()
    else {
        panic!("set mode");
    };
    assert_eq!(r.counter, 1);
}

#[tokio::test]
async fn test_profile_testing_mode_skips_approval() {
    let tmp = tempfile::tempdir().unwrap();
    let key = test_signing_key();
    install_mode_signers(tmp.path(), &key);
    write_mode_file(
        tmp.path(),
        &signed_mode_body(OperationalMode::Testing, 1, &key),
    );
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
                    index: 1,
                    value: "T".into(),
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
    let ResponseResult::ApplyPlan(_) = gw
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
        .unwrap()
    else {
        panic!("apply without approval");
    };
}

#[tokio::test]
async fn prod_profile_requires_approval() {
    let tmp = tempfile::tempdir().unwrap();
    let key = test_signing_key();
    install_mode_signers(tmp.path(), &key);
    write_mode_file(
        tmp.path(),
        &signed_mode_body(OperationalMode::Testing, 1, &key),
    );
    std::fs::write(tmp.path().join("mode.counter"), "0").unwrap();
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests_profile(tmp.path(), uid, Profile::Prod);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut gw = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::PlanChange(plan) = gw
        .call_auth(
            RequestBody::PlanChange {
                params: kxprov_api::PlanChangeParams {
                    kind: FieldKindWire::CidNumber,
                    index: 1,
                    value: "9".into(),
                },
            },
            Some(gateway_auth("writer")),
        )
        .await
        .unwrap()
    else {
        panic!("plan");
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
        .expect_err("prod needs approval");
    assert!(err.to_string().contains("approval"));
}

#[tokio::test]
async fn submit_approval_rules() {
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
                    index: 2,
                    value: "A".into(),
                },
            },
            Some(gateway_auth("writer")),
        )
        .await
        .unwrap()
    else {
        panic!("plan");
    };
    let err = gw
        .call_auth(
            RequestBody::SubmitApproval {
                params: kxprov_api::SubmitApprovalParams {
                    plan_id: plan.plan_id.clone(),
                    diff_hash: plan.diff_hash.clone(),
                },
            },
            Some(gateway_auth("writer")),
        )
        .await
        .expect_err("writer cannot approve");
    assert!(err.to_string().contains("forbidden") || err.to_string().contains("scope"));

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

    let ResponseResult::SubmitApproval(_) = approver
        .call_auth(
            RequestBody::SubmitApproval {
                params: kxprov_api::SubmitApprovalParams {
                    plan_id: plan.plan_id,
                    diff_hash: plan.diff_hash,
                },
            },
            Some(gateway_auth("approver")),
        )
        .await
        .unwrap()
    else {
        panic!("second submit allowed");
    };
}

#[tokio::test]
async fn submit_approval_rate_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests(tmp.path(), uid);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut approver = ApiClient::connect(&sock).await.unwrap();
    for i in 0..5 {
        let mut gw = ApiClient::connect(&sock).await.unwrap();
        let ResponseResult::PlanChange(plan) = gw
            .call_auth(
                RequestBody::PlanChange {
                    params: kxprov_api::PlanChangeParams {
                        kind: FieldKindWire::CidName,
                        index: 5 + i,
                        value: format!("R{i}"),
                    },
                },
                Some(gateway_auth("writer")),
            )
            .await
            .unwrap()
        else {
            panic!("plan");
        };
        let ResponseResult::SubmitApproval(_) = approver
            .call_auth(
                RequestBody::SubmitApproval {
                    params: kxprov_api::SubmitApprovalParams {
                        plan_id: plan.plan_id,
                        diff_hash: plan.diff_hash,
                    },
                },
                Some(gateway_auth("approver")),
            )
            .await
            .unwrap()
        else {
            panic!("submit {i}");
        };
    }
    let mut gw = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::PlanChange(plan) = gw
        .call_auth(
            RequestBody::PlanChange {
                params: kxprov_api::PlanChangeParams {
                    kind: FieldKindWire::CidName,
                    index: 20,
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
    let err = approver
        .call_auth(
            RequestBody::SubmitApproval {
                params: kxprov_api::SubmitApprovalParams {
                    plan_id: plan.plan_id,
                    diff_hash: plan.diff_hash,
                },
            },
            Some(gateway_auth("approver")),
        )
        .await
        .expect_err("hour limit");
    assert!(err.to_string().contains("rate") || err.to_string().contains("Rate"));
}

#[tokio::test]
async fn mode_corrupt_json_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("mode.json"), b"{not-json").unwrap();
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests(tmp.path(), uid);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut c = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::Status(st) = c.call(RequestBody::Status).await.unwrap() else {
        panic!("status");
    };
    assert_eq!(st.operational_mode, OperationalMode::Production);
    let audit = ModeStore::new(tmp.path()).audit().load().unwrap();
    assert!(audit.iter().any(|e| e.kind == AuditKind::ModeCorrupt));
}

#[tokio::test]
async fn testing_mode_invalid_on_sim_profile() {
    let tmp = tempfile::tempdir().unwrap();
    let key = test_signing_key();
    install_mode_signers(tmp.path(), &key);
    write_mode_file(
        tmp.path(),
        &signed_mode_body(OperationalMode::Testing, 1, &key),
    );
    std::fs::write(tmp.path().join("mode.counter"), "0").unwrap();
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests(tmp.path(), uid);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut c = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::Status(st) = c.call(RequestBody::Status).await.unwrap() else {
        panic!("status");
    };
    assert_eq!(st.operational_mode, OperationalMode::Production);
    let audit = ModeStore::new(tmp.path()).audit().load().unwrap();
    assert!(audit
        .iter()
        .any(|e| e.kind == AuditKind::ModeTestingInvalidProfile));
}
