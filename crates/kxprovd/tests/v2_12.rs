#![allow(clippy::unwrap_used)]

mod common;

use common::{bearer_auth, init_test_daemon, WRITER_SECRET};
use kxprov_api::{profile_data_dir, resolve_profile_data_dir};
use kxprov_api::{ApiClient, PlanChangeParams, RequestBody, Scope};
use kxprov_api::{OperationalMode, Profile, DAEMON_SOCKET, DATA_DIR, TOKENS_JSON};
use kxprovd::audit::AuditKind;
use kxprovd::mode::{ModeFileBody, ModeStore, ProfileFileBody};
use kxprovd::tokens::TokenStore;
use std::time::Duration;

#[test]
fn rolled_back_mode_json_fails_closed_to_production() {
    let tmp = tempfile::tempdir().unwrap();
    let profile_root = resolve_profile_data_dir(tmp.path(), Profile::Sim);
    std::fs::create_dir_all(&profile_root).unwrap();
    let store = ModeStore::new(tmp.path(), Profile::Sim);
    store
        .set_operational(OperationalMode::Testing, Profile::Test, true)
        .unwrap();
    store
        .set_operational(OperationalMode::Production, Profile::Sim, true)
        .unwrap();
    std::fs::write(
        profile_root.join("mode.json"),
        serde_json::to_vec_pretty(&ModeFileBody {
            mode: OperationalMode::Testing,
            counter: 1,
        })
        .unwrap(),
    )
    .unwrap();
    let eff = store.effective(Profile::Test);
    assert_eq!(eff.operational, OperationalMode::Production);
    let audit = store.audit().load().unwrap();
    assert!(audit
        .iter()
        .any(|e| e.kind == AuditKind::ModeCounterRollback));
}

#[test]
fn rolled_back_profile_json_fails_closed_to_prod_profile() {
    let tmp = tempfile::tempdir().unwrap();
    let profile_root = resolve_profile_data_dir(tmp.path(), Profile::Sim);
    std::fs::create_dir_all(&profile_root).unwrap();
    let store = ModeStore::new(tmp.path(), Profile::Sim);
    store
        .set_operational(OperationalMode::Production, Profile::Sim, true)
        .unwrap();
    std::fs::write(
        profile_root.join("profile.json"),
        serde_json::to_vec_pretty(&ProfileFileBody {
            profile: Profile::Test,
            counter: 0,
        })
        .unwrap(),
    )
    .unwrap();
    assert_eq!(store.load_profile(), Profile::Prod);
    let audit = store.audit().load().unwrap();
    assert!(audit
        .iter()
        .any(|e| e.kind == AuditKind::ModeCounterRollback));
}

#[test]
fn approver_with_plan_scope_rejected_at_load() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("tokens.json");
    let mut file = kxprovd::test_util::default_tokens_file();
    for t in &mut file.tokens {
        if t.id.as_str() == "approver" {
            t.scopes.push(Scope::Plan);
        }
    }
    TokenStore::write_test_file(&path, &file).unwrap();
    let err = match TokenStore::load_insecure(path) {
        Err(e) => e,
        Ok(_) => panic!("expected load to fail"),
    };
    assert!(
        err.to_string().contains("approver") || err.to_string().contains("Plan"),
        "{err}"
    );
}

#[test]
fn approver_with_plan_scope_rejected_at_mint() {
    let mut file = kxprovd::test_util::default_tokens_file();
    for t in &mut file.tokens {
        if t.id.as_str() == "approver" {
            t.scopes.push(Scope::Write);
        }
    }
    assert_eq!(
        kxprov_api::validate_tokens_file(&file),
        Err(kxprov_api::TokenValidationError::ApproverMustNotHoldPlanOrWrite)
    );
}

#[tokio::test]
async fn per_token_queue_depth_rate_limit_integration() {
    use kxprov_api::TOKEN_QUEUE_DEPTH_MAX;
    use std::sync::Arc;
    use tokio::sync::Barrier;

    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = init_test_daemon(&tmp, uid, Profile::Sim);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let plan = |n: u16| PlanChangeParams {
        kind: kxprov_api::FieldKindWire::CidName,
        index: n,
        value: format!("RL-{n}"),
    };

    let n = (TOKEN_QUEUE_DEPTH_MAX + 1) as usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::new();
    for i in 0..n {
        let sock = sock.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let mut c = ApiClient::connect(&sock).await.unwrap();
            c.call_auth(
                RequestBody::PlanChange {
                    params: plan(i as u16),
                },
                Some(bearer_auth(WRITER_SECRET)),
            )
            .await
        }));
    }

    let mut rate_limited = false;
    for h in handles {
        match h.await.unwrap() {
            Err(e) if e.to_string().contains("rate_limit") => rate_limited = true,
            Ok(_) | Err(_) => {}
        }
    }
    assert!(rate_limited, "expected queue depth rate limit");
}

#[test]
fn default_production_paths() {
    use kxprovd::config::{production_path_defaults, Config};
    let p = tempfile::tempdir().unwrap();
    let pass = p.path().join("password");
    std::fs::write(&pass, "0000").unwrap();
    let cfg_path = p.path().join("kxprovd.json");
    std::fs::write(
        &cfg_path,
        format!(r#"{{"password_path":"{}"}}"#, pass.display()),
    )
    .unwrap();
    let cfg = Config::load_from_etc(&cfg_path).unwrap();
    let defaults = production_path_defaults();
    assert_eq!(cfg.data_dir, defaults.data_dir);
    assert_eq!(cfg.data_dir, std::path::PathBuf::from(DATA_DIR));
    assert_eq!(cfg.socket_path, std::path::PathBuf::from(DAEMON_SOCKET));
    assert_eq!(cfg.tokens_path, std::path::PathBuf::from(TOKENS_JSON));
    assert_eq!(
        cfg.profile_data_dir(),
        std::path::PathBuf::from(profile_data_dir(Profile::Sim))
    );
}
