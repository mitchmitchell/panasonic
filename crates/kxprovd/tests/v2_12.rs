#![allow(clippy::unwrap_used)]

mod common;

use common::{bearer_auth, init_test_daemon, WRITER_SECRET};
use kxprov_api::{ApiClient, PlanChangeParams, RequestBody, Scope};
use kxprov_api::{OperationalMode, Profile};
use kxprovd::audit::AuditKind;
use kxprovd::mode::{ModeFileBody, ModeStore, ProfileFileBody};
use kxprovd::tokens::TokenStore;
use std::time::Duration;

#[test]
fn rolled_back_mode_json_fails_closed_to_production() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ModeStore::new(tmp.path(), Profile::Test);
    store
        .set_operational(OperationalMode::Testing, Profile::Test, true)
        .unwrap();
    std::fs::write(
        tmp.path().join("mode.json"),
        serde_json::to_vec_pretty(&ModeFileBody {
            mode: OperationalMode::Testing,
            counter: 0,
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
    let store = ModeStore::new(tmp.path(), Profile::Sim);
    store
        .set_operational(OperationalMode::Production, Profile::Sim, true)
        .unwrap();
    std::fs::write(
        tmp.path().join("profile.json"),
        serde_json::to_vec_pretty(&ProfileFileBody {
            profile: Profile::Sim,
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
    use kxprovd::config::Config;
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
    assert_eq!(
        cfg.provision_root,
        std::path::PathBuf::from(kxprovd::config::PROVISION_ROOT)
    );
    assert_eq!(
        cfg.data_dir,
        kxprovd::config::profile_data_dir(
            kxprovd::config::PROVISION_ROOT,
            kxprov_api::Profile::Sim,
        )
    );
    assert_eq!(
        cfg.socket_path,
        std::path::PathBuf::from(kxprovd::config::DEFAULT_SOCKET)
    );
    assert_eq!(
        cfg.tokens_path,
        std::path::PathBuf::from(kxprovd::config::PROVISION_ROOT).join("tokens.json")
    );
}

#[test]
fn profile_data_dir_honors_configured_provision_root() {
    use kxprovd::config::{profile_data_dir, profile_epoch_counter_path, Config};
    let p = tempfile::tempdir().unwrap();
    let root = p.path().join("custom-root");
    let pass = p.path().join("password");
    std::fs::write(&pass, "0000").unwrap();
    let cfg_path = p.path().join("kxprovd.json");
    std::fs::write(
        &cfg_path,
        format!(
            r#"{{"password_path":"{}","provision_root":"{}"}}"#,
            pass.display(),
            root.display()
        ),
    )
    .unwrap();
    let cfg = Config::load_from_etc(&cfg_path).unwrap();
    assert_eq!(cfg.provision_root, root);
    assert_eq!(
        cfg.data_dir,
        profile_data_dir(&root, kxprov_api::Profile::Sim)
    );
    assert_eq!(
        profile_data_dir(&root, kxprov_api::Profile::Prod),
        root.join("prod")
    );
    assert_eq!(
        profile_epoch_counter_path(&root, Profile::Sim),
        root.join(".epoch/sim.counter")
    );
}

#[test]
fn custom_data_dir_is_provision_root_with_profile_subdirs() {
    use kxprovd::config::{profile_data_dir, profile_epoch_counter_path, Config};
    let p = tempfile::tempdir().unwrap();
    let data_root = p.path().join("data-root");
    let pass = p.path().join("password");
    std::fs::write(&pass, "0000").unwrap();
    let cfg_path = p.path().join("kxprovd.json");
    std::fs::write(
        &cfg_path,
        format!(
            r#"{{"password_path":"{}","data_dir":"{}"}}"#,
            pass.display(),
            data_root.display()
        ),
    )
    .unwrap();
    let cfg = Config::load_from_etc(&cfg_path).unwrap();
    assert_eq!(cfg.provision_root, data_root);
    assert_eq!(cfg.data_dir, profile_data_dir(&data_root, Profile::Sim));
    assert_eq!(
        profile_epoch_counter_path(&data_root, Profile::Prod),
        data_root.join(".epoch/prod.counter")
    );
}

#[test]
fn mode_counter_is_per_profile_data_directory() {
    use kxprovd::config::profile_epoch_counter_path;
    use kxprovd::mode::ProfileFileBody;
    let root = tempfile::tempdir().unwrap();
    let sim_dir = root.path().join("sim");
    let prod_dir = root.path().join("prod");
    std::fs::create_dir_all(&sim_dir).unwrap();
    std::fs::create_dir_all(&prod_dir).unwrap();
    std::fs::create_dir_all(root.path().join(".epoch")).unwrap();
    std::fs::write(profile_epoch_counter_path(root.path(), Profile::Sim), "1\n").unwrap();
    std::fs::write(
        profile_epoch_counter_path(root.path(), Profile::Prod),
        "9\n",
    )
    .unwrap();
    std::fs::write(
        sim_dir.join("profile.json"),
        serde_json::to_vec_pretty(&ProfileFileBody {
            profile: Profile::Sim,
            counter: 1,
        })
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        prod_dir.join("profile.json"),
        serde_json::to_vec_pretty(&ProfileFileBody {
            profile: Profile::Prod,
            counter: 9,
        })
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        ModeStore::new_with_epoch_root(&sim_dir, root.path(), Profile::Sim).load_profile(),
        Profile::Sim
    );
    assert_eq!(
        ModeStore::new_with_epoch_root(&prod_dir, root.path(), Profile::Prod).load_profile(),
        Profile::Prod
    );
}

#[test]
fn profile_epoch_counter_lives_outside_profile_data_dir() {
    use kxprovd::config::profile_epoch_counter_path;
    let root = tempfile::tempdir().unwrap();
    let sim_dir = root.path().join("sim");
    std::fs::create_dir_all(&sim_dir).unwrap();
    let counter = profile_epoch_counter_path(root.path(), Profile::Sim);
    std::fs::create_dir_all(counter.parent().unwrap()).unwrap();
    std::fs::write(&counter, "4\n").unwrap();
    std::fs::write(
        sim_dir.join("profile.json"),
        serde_json::to_vec_pretty(&kxprovd::mode::ProfileFileBody {
            profile: Profile::Sim,
            counter: 4,
        })
        .unwrap(),
    )
    .unwrap();
    assert!(!counter.starts_with(&sim_dir));
    assert_eq!(
        ModeStore::new_with_epoch_root(&sim_dir, root.path(), Profile::Sim).load_profile(),
        Profile::Sim
    );
}
