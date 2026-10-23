#![allow(clippy::unwrap_used)]

use kxprov_api::{ApiClient, FieldKindWire, GoliathCopyStatus, RequestBody, ResponseResult, Scope};
use kxprovd::config::Config;
use kxprovd::peer::{peer_cred, PeerPolicy};
use kxprovd::plan_store::{diff_hash, PlanSnapshot, PlanStore};
use kxprovd::Daemon;
use nix::unistd::getuid;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

#[tokio::test]
async fn read_and_plan_sim() {
    let tmp = tempfile::tempdir().unwrap();
    let plan_dir = tmp.path().join("plans");
    let uid = getuid().as_raw();
    let (_daemon, sock) = Daemon::sim_for_tests(tmp.path(), uid);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut c = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::Status(st) = c.call(RequestBody::Status).await.unwrap() else {
        panic!("status");
    };
    assert_eq!(st.transport, "sim");

    let ResponseResult::ReadFields(r) = c
        .call(RequestBody::ReadFields {
            params: kxprov_api::ReadFieldsParams {
                kind: FieldKindWire::CidName,
                first: 0,
                count: 2,
            },
        })
        .await
        .unwrap()
    else {
        panic!("read");
    };
    assert_eq!(r.rows.len(), 2);

    let ResponseResult::PlanChange(p) = c
        .call(RequestBody::PlanChange {
            params: kxprov_api::PlanChangeParams {
                kind: FieldKindWire::CidName,
                index: 1,
                value: "SYNTH".into(),
            },
        })
        .await
        .unwrap()
    else {
        panic!("plan");
    };
    assert_eq!(p.plan_id.len(), 64);
    assert!(!p.diff.is_empty());
    assert_eq!(p.diff_hash, diff_hash(&p.diff));

    let plans_dir = std::fs::read_dir(plan_dir).unwrap().count();
    assert!(plans_dir >= 1);

    let ResponseResult::PlanChange(p2) = c
        .call(RequestBody::PlanChange {
            params: kxprov_api::PlanChangeParams {
                kind: FieldKindWire::CidName,
                index: 1,
                value: "SYNTH".into(),
            },
        })
        .await
        .unwrap()
    else {
        panic!("plan2");
    };
    assert_eq!(p.plan_id, p2.plan_id, "immutable plan id for same content");
}

#[tokio::test]
async fn arm_single_use_and_apply_gates() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests(tmp.path(), uid);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut c = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::PlanChange(plan) = c
        .call(RequestBody::PlanChange {
            params: kxprov_api::PlanChangeParams {
                kind: FieldKindWire::CidNumber,
                index: 2,
                value: "456".into(),
            },
        })
        .await
        .unwrap()
    else {
        panic!("plan");
    };

    let err = c
        .call(RequestBody::ApplyPlan {
            params: kxprov_api::ApplyPlanParams {
                plan_id: plan.plan_id.clone(),
                diff_hash: plan.diff_hash.clone(),
                confirm: true,
            },
        })
        .await
        .expect_err("apply without arm/live ok");
    assert!(err.to_string().contains("gate") || err.to_string().contains("arm"));

    let ResponseResult::ArmPlan(a) = c
        .call(RequestBody::ArmPlan {
            params: kxprov_api::ArmPlanParams {
                plan_id: plan.plan_id.clone(),
                diff_hash: plan.diff_hash.clone(),
                ttl_secs: 60,
            },
        })
        .await
        .unwrap()
    else {
        panic!("arm");
    };
    assert_eq!(a.arm.plan_id, plan.plan_id);

    let err = c
        .call(RequestBody::ApplyPlan {
            params: kxprov_api::ApplyPlanParams {
                plan_id: plan.plan_id,
                diff_hash: "bad".into(),
                confirm: true,
            },
        })
        .await
        .expect_err("wrong diff hash");
    assert!(err.to_string().contains("plan") || err.to_string().contains("arm"));
}

#[tokio::test]
async fn backup_and_goliath_local() {
    let tmp = tempfile::tempdir().unwrap();
    let goliath_path = tmp.path().join("goliath");
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests(tmp.path(), uid);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut c = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::BackupNow(b) = c.call(RequestBody::BackupNow).await.unwrap() else {
        panic!("backup");
    };
    assert_eq!(b.backup.bytes, 60_692);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let ResponseResult::ListBackups(list) = c.call(RequestBody::ListBackups).await.unwrap() else {
        panic!("list");
    };
    assert_eq!(list.backups.len(), 1);
    let goliath_dir = std::fs::read_dir(goliath_path).unwrap();
    assert!(goliath_dir.count() >= 1);
    assert!(matches!(
        list.backups[0].goliath,
        GoliathCopyStatus::Ok | GoliathCopyStatus::Pending
    ));
}

#[test]
fn process_lock_contended() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = getuid().as_raw();
    let cfg = Config::sim_test(tmp.path().to_path_buf(), tmp.path().join("a.sock"), uid);
    let _a = Daemon::start(cfg).unwrap();
    assert!(matches!(
        kxprovd::lock::ProcessLock::acquire(tmp.path()),
        Err(kxprovd::lock::LockError::Contended)
    ));
}

#[test]
fn peer_cred_on_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let sock = tmp.path().join("pc.sock");
    rt.block_on(async {
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let accept = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            peer_cred(&s).unwrap()
        });
        let mut client = UnixStream::connect(&sock).await.unwrap();
        let _ = client.write_all(b"hi").await;
        let cred = accept.await.unwrap();
        assert_eq!(cred.uid, getuid().as_raw());
    });
}

#[test]
fn immutable_plan_hash_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let store = PlanStore::new(tmp.path().to_path_buf()).unwrap();
    let snap = PlanSnapshot {
        table: 0x25,
        record_size: 16,
        writes: vec![],
        diff: vec!["line".into()],
    };
    let (id, _) = store.put(&snap).unwrap();
    assert!(store.verify_diff_hash(&id, "deadbeef").is_err());
}

#[test]
fn peer_policy_denies_scope() {
    let pol = PeerPolicy::new([(99, vec![Scope::Read])]);
    let cred = kxprovd::peer::PeerCred {
        uid: 99,
        gid: 0,
        pid: 0,
    };
    assert!(pol.require(cred, Scope::Plan).is_err());
}

#[tokio::test]
async fn journal_recovery_truncates_orphan() {
    use kxprovd::journal::{Journal, JournalEntry};
    let tmp = tempfile::tempdir().unwrap();
    let journal = Journal::new(tmp.path());
    journal
        .append(&JournalEntry::BackupStart {
            job_id: "j1".into(),
            temp_path: tmp.path().join("orphan.partial").display().to_string(),
        })
        .unwrap();
    std::fs::write(tmp.path().join("orphan.partial"), b"x").unwrap();
    journal.replay(tmp.path()).unwrap();
    assert!(!tmp.path().join("orphan.partial").exists());
}
