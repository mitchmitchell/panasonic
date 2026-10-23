#![allow(clippy::unwrap_used)]

use kxprov_api::{
    mode_sign_message, ApiClient, FieldKindWire, OperationalMode, Profile, RequestAuth,
    RequestBody, ResponseResult, SetModeParams, TokenId, MODE_SSH_NAMESPACE,
};
use kxprovd::audit::AuditKind;
use kxprovd::mode::{ModeFileBody, ModeStore};
use kxprovd::Daemon;
use nix::unistd::getuid;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

fn gateway_auth(id: &str) -> RequestAuth {
    RequestAuth {
        token_id: TokenId(id.into()),
    }
}

fn sign_mode_nonce(key_path: &Path, nonce: &[u8]) -> String {
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

pub fn install_mode_signers(dir: &Path, key_path: &Path) {
    let pub_line = String::from_utf8(
        Command::new("ssh-keygen")
            .args(["-y", "-f"])
            .arg(key_path)
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
}

fn test_key(dir: &Path) -> std::path::PathBuf {
    let key = dir.join("mode-test-key");
    Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&key)
        .args(["-N", ""])
        .status()
        .unwrap();
    key
}

fn signed_mode_body(mode: OperationalMode, counter: u64, key_path: &Path) -> ModeFileBody {
    let nonce = mode_sign_message(mode, counter);
    ModeFileBody {
        mode,
        counter,
        signature: sign_mode_nonce(key_path, &nonce),
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
    let audit = ModeStore::new(tmp.path(), tmp.path().join("mode-signers"))
        .audit()
        .load()
        .unwrap();
    assert!(audit.iter().any(|e| e.kind == AuditKind::ModeMissing));
}

#[tokio::test]
async fn mode_bad_signature_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let key = test_key(tmp.path());
    install_mode_signers(tmp.path(), &key);
    write_mode_file(
        tmp.path(),
        &ModeFileBody {
            mode: OperationalMode::Testing,
            counter: 1,
            signature: "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n".into(),
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
}

#[tokio::test]
async fn mode_counter_rollback_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let key = test_key(tmp.path());
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
}

#[tokio::test]
async fn mode_set_via_root_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let key = test_key(tmp.path());
    install_mode_signers(tmp.path(), &key);
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests(tmp.path(), uid);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let nonce = mode_sign_message(OperationalMode::Production, 1);
    let sig = sign_mode_nonce(&key, &nonce);
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
    let key = test_key(tmp.path());
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
async fn sim_profile_skips_approval() {
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
                    index: 6,
                    value: "SIM".into(),
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
        panic!("sim apply without approval");
    };
}

#[tokio::test]
async fn prod_profile_requires_approval() {
    let tmp = tempfile::tempdir().unwrap();
    let key = test_key(tmp.path());
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
}
