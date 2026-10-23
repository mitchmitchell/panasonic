#![allow(clippy::unwrap_used)]

mod common;

use common::{bearer_auth, init_test_daemon, WRITER_SECRET};
use kxprov_api::TokenId;
use kxprov_api::{
    ApiClient, FieldKindWire, PlanChangeParams, Profile, RequestBody, ResponseResult,
};
use kxprovd::mode::ModeStore;
use kxprovd::tokens::TokenStore;
use std::process::Command;
use std::time::Duration;

#[tokio::test]
async fn p4_r1_root_read_without_token_reaches_worker() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = init_test_daemon(&tmp, uid, Profile::Sim);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut c = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::ReadFields(rows) = c
        .call(RequestBody::ReadFields {
            params: kxprov_api::ReadFieldsParams {
                kind: FieldKindWire::CidName,
                first: 0,
                count: 1,
            },
        })
        .await
        .expect("admin root read without bearer")
    else {
        panic!("expected ReadFields");
    };
    assert!(!rows.rows.is_empty());
}

#[tokio::test]
async fn p4_r1_local_read_only_peer_reaches_worker() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, socket) = common::init_test_daemon_local_readonly(&tmp, uid, Profile::Sim);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut c = ApiClient::connect(&socket).await.unwrap();
    let ResponseResult::ReadFields(rows) = c
        .call(RequestBody::ReadFields {
            params: kxprov_api::ReadFieldsParams {
                kind: FieldKindWire::CidName,
                first: 0,
                count: 1,
            },
        })
        .await
        .expect("local read-only read")
    else {
        panic!("expected ReadFields");
    };
    assert!(!rows.rows.is_empty());
}

#[test]
fn p4_r1_deleted_token_id_is_revoked() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("tokens.json");
    kxprovd::test_util::write_integration_tokens(&path);
    let store = TokenStore::load_insecure(path).expect("load tokens");
    assert!(store
        .is_revoked(&TokenId("no-such-token".into()))
        .expect("lookup"));
}

#[test]
fn p4_r8_reserved_token_id_rejected_at_load() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("tokens.json");
    let mut file = kxprovd::test_util::default_tokens_file();
    file.tokens.push(kxprov_api::TokenEntry {
        id: TokenId("local:42".into()),
        secret_hash: kxprov_api::hash_bearer_secret("extra"),
        scopes: vec![kxprov_api::Scope::Read],
        expires_at_ms: u64::MAX / 2,
        revoked: false,
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    assert!(TokenStore::load_insecure(path).is_err());
}

#[test]
fn p4_r9_missing_mode_counter_with_stored_epoch_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("mode.json"),
        serde_json::to_vec_pretty(&kxprovd::mode::ModeFileBody {
            mode: kxprov_api::OperationalMode::Production,
            counter: 3,
        })
        .unwrap(),
    )
    .unwrap();
    let store = ModeStore::new(tmp.path(), Profile::Prod);
    assert_eq!(store.load_profile(), Profile::Prod);
}

#[test]
fn p4_r2_corrupt_mode_counter_fails_closed() {
    use kxprovd::config::profile_epoch_counter_path;
    let tmp = tempfile::tempdir().unwrap();
    let counter = profile_epoch_counter_path(tmp.path(), Profile::Sim);
    std::fs::create_dir_all(counter.parent().unwrap()).unwrap();
    std::fs::write(counter, "not-a-number\n").unwrap();
    let store = ModeStore::new(tmp.path(), Profile::Sim);
    assert_eq!(store.load_profile(), Profile::Prod);
    let eff = store.effective(Profile::Sim);
    assert_eq!(eff.operational, kxprov_api::OperationalMode::Production);
}

#[test]
fn p4_r2_missing_mode_counter_is_first_boot_epoch_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ModeStore::new(tmp.path(), Profile::Test);
    assert_eq!(store.load_profile(), Profile::Test);
}

#[test]
fn prod_data_dir_profile_json_sim_fails_closed_to_prod() {
    let tmp = tempfile::tempdir().unwrap();
    let prod_dir = tmp.path().join("prod");
    std::fs::create_dir_all(&prod_dir).unwrap();
    std::fs::write(
        prod_dir.join("profile.json"),
        serde_json::to_vec_pretty(&kxprovd::mode::ProfileFileBody {
            profile: Profile::Sim,
            counter: 0,
        })
        .unwrap(),
    )
    .unwrap();
    let store = ModeStore::new(&prod_dir, Profile::Prod);
    assert_eq!(store.load_profile(), Profile::Prod);
}

#[test]
fn p4_r3_missing_profile_after_epoch_fails_closed_to_prod() {
    use kxprovd::config::profile_epoch_counter_path;
    let tmp = tempfile::tempdir().unwrap();
    let counter = profile_epoch_counter_path(tmp.path(), Profile::Sim);
    std::fs::create_dir_all(counter.parent().unwrap()).unwrap();
    std::fs::write(counter, "2\n").unwrap();
    let store = ModeStore::new(tmp.path(), Profile::Sim);
    assert_eq!(store.load_profile(), Profile::Prod);
}

/// Jobs queued while revoked stay failed after rotate; only post-rotate submits succeed.
#[tokio::test]
async fn p4_r6_rotate_does_not_revive_queued_revoked_jobs() {
    use common::{bearer_auth, init_test_daemon};
    use kxprov_api::TokensFile;

    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = init_test_daemon(&tmp, uid, Profile::Sim);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let plan = |n: u16| PlanChangeParams {
        kind: FieldKindWire::CidName,
        index: n,
        value: format!("Q-{n}"),
    };

    let mut handles = Vec::new();
    for n in 0..4u16 {
        let sock = sock.clone();
        handles.push(tokio::spawn(async move {
            let mut c = ApiClient::connect(&sock).await.unwrap();
            c.call_auth(
                RequestBody::PlanChange { params: plan(n) },
                Some(bearer_auth(WRITER_SECRET)),
            )
            .await
        }));
    }

    let path = tmp.path().join("tokens.json");
    let mut file: TokensFile =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).expect("tokens");
    for t in &mut file.tokens {
        if t.id.as_str() == "writer" {
            t.revoked = true;
        }
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut probe = ApiClient::connect(&sock).await.unwrap();
    probe
        .call_auth(
            RequestBody::PlanChange { params: plan(99) },
            Some(bearer_auth(WRITER_SECRET)),
        )
        .await
        .expect_err("writer revoked before rotate");

    let kxprov = common::kxprov_binary();
    let out = Command::new(&kxprov)
        .args(["token", "rotate", "--id", "writer"])
        .arg("--tokens-path")
        .arg(&path)
        .output()
        .expect("rotate");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let new_bearer = stdout
        .lines()
        .map(str::trim)
        .find(|line| line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("bearer");

    let mut saw_revoked = false;
    for h in handles {
        match h.await.unwrap() {
            Err(e) if e.to_string().contains("token_revoked") => saw_revoked = true,
            Err(e)
                if e.to_string().contains("unauthorized")
                    || e.to_string().contains("invalid bearer") =>
            {
                saw_revoked = true;
            }
            Ok(_) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
    assert!(
        saw_revoked,
        "queued jobs during revoke should stay failed after rotate"
    );

    let mut c = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::PlanChange(_) = c
        .call_auth(
            RequestBody::PlanChange { params: plan(9) },
            Some(bearer_auth(new_bearer)),
        )
        .await
        .expect("new job after rotate")
    else {
        panic!("plan after rotate");
    };
}

#[tokio::test]
async fn synthetic_root_read_during_token_store_outage() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = init_test_daemon(&tmp, uid, Profile::Sim);
    let path = tmp.path().join("tokens.json");
    std::fs::write(&path, b"{ corrupt").unwrap();

    let mut admin = ApiClient::connect(&sock).await.unwrap();
    let _ = admin
        .call_auth(
            RequestBody::PlanChange {
                params: PlanChangeParams {
                    kind: FieldKindWire::CidName,
                    index: 0,
                    value: "Y".into(),
                },
            },
            Some(bearer_auth(WRITER_SECRET)),
        )
        .await
        .expect("bearer may use grace snapshot during reload window");

    let outage_deadline =
        tokio::time::Instant::now() + Duration::from_secs(2) + Duration::from_millis(500);
    loop {
        let err = admin
            .call_auth(
                RequestBody::PlanChange {
                    params: PlanChangeParams {
                        kind: FieldKindWire::CidName,
                        index: 0,
                        value: "Z".into(),
                    },
                },
                Some(bearer_auth(WRITER_SECRET)),
            )
            .await;
        if let Err(e) = err {
            if e.to_string().contains("token store unavailable") {
                break;
            }
        }
        assert!(
            tokio::time::Instant::now() < outage_deadline,
            "bearer auth did not fail closed after reload grace"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let err = admin
        .call_auth(
            RequestBody::PlanChange {
                params: PlanChangeParams {
                    kind: FieldKindWire::CidName,
                    index: 0,
                    value: "X".into(),
                },
            },
            Some(bearer_auth(WRITER_SECRET)),
        )
        .await
        .expect_err("bearer blocked during outage");
    assert!(err.to_string().contains("token store unavailable"), "{err}");

    let ResponseResult::ReadFields(rows) = admin
        .call(RequestBody::ReadFields {
            params: kxprov_api::ReadFieldsParams {
                kind: FieldKindWire::CidName,
                first: 0,
                count: 1,
            },
        })
        .await
        .expect("synthetic root read during outage")
    else {
        panic!("expected ReadFields");
    };
    assert!(!rows.rows.is_empty());
}
