#![allow(clippy::unwrap_used)]

use kxprov_api::{
    ApiClient, FieldKindWire, OperationalMode, Profile, RequestAuth, RequestBody, ResponseResult,
    TokenId,
};
use kxprovd::config::Config;
use kxprovd::mode::{ModeFileBody, ProfileFileBody};
use kxprovd::Daemon;
use kxtd1232::{build_plan, field_patch, frame::Access, Client, Granularity};
use kxtd1232::{Timing, MAX_LINK_BAUD, MIN_REPLY_GUARD_MS};
use kxtd1232_sim::{Fault, SimPbx, SimTransport, PLACEHOLDER_PASSWORD};
use nix::unistd::getuid;
use std::time::Duration;

fn gateway_auth(id: &str) -> RequestAuth {
    RequestAuth {
        token_id: TokenId(id.into()),
    }
}

#[test]
fn timing_config_rejected_at_daemon_start() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = getuid().as_raw();
    let socket = tmp.path().join("kxprovd.sock");
    let mut cfg = Config::sim_test(tmp.path().to_path_buf(), socket, uid);
    cfg.timing.link_baud = MAX_LINK_BAUD + 1;
    assert!(cfg.validate().is_err());
    assert!(Daemon::start(cfg).is_err());
}

#[test]
fn timing_config_rejects_zero_guard_even_at_max_baud() {
    let mut t = Timing::default();
    t.link_baud = MAX_LINK_BAUD;
    t.reply_guard_ms = MIN_REPLY_GUARD_MS - 1;
    assert!(t.validate().is_err());
}

/// Same read-after-write sequence as `apply.rs` (`apply_one_write`), for every profile on sim transport.
#[test]
fn apply_style_readback_after_each_write_all_profiles() {
    for profile in [Profile::Sim, Profile::Test, Profile::Prod] {
        let mut client = Client::with(
            SimTransport::new(SimPbx::default()),
            Access::ReadWrite,
            Timing::default(),
        );
        client.login(PLACEHOLDER_PASSWORD).unwrap();
        let base = client.read_table(0x25).unwrap();
        let p = field_patch(kxtd1232::FieldKind::CidName, 6, &format!("RB-{profile:?}")).unwrap();
        let plan = build_plan(0x25, &base, &[p], Granularity::Chunk).unwrap();
        for w in &plan.writes {
            client.write(w.table, w.record, w.word, &w.new).unwrap();
            let got = client
                .read(w.table, w.record, w.word, (w.new.len() / 2) as u8)
                .unwrap();
            assert_eq!(got, w.new, "readback mismatch for profile {profile:?}");
        }
        let _ = client.end_binary();
    }
}

#[test]
fn apply_style_readback_detects_silent_write() {
    let mut client = Client::with(
        SimTransport::new(SimPbx::default()),
        Access::ReadWrite,
        Timing::default(),
    );
    client.login(PLACEHOLDER_PASSWORD).unwrap();
    let w = {
        let base = client.read_table(0x25).unwrap();
        let p = field_patch(kxtd1232::FieldKind::CidName, 1, "SILENT").unwrap();
        build_plan(0x25, &base, &[p], Granularity::Chunk)
            .unwrap()
            .writes
            .into_iter()
            .next()
            .unwrap()
    };
    client.transport_mut().sim_mut().inject(Fault::SilentWrite);
    client.write(w.table, w.record, w.word, &w.new).unwrap();
    let got = client
        .read(w.table, w.record, w.word, (w.new.len() / 2) as u8)
        .unwrap();
    assert_ne!(got, w.new);
}

#[tokio::test]
async fn daemon_apply_on_prod_profile_readback_via_read_fields() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("mode.json"),
        serde_json::to_vec_pretty(&ModeFileBody {
            mode: OperationalMode::Production,
        })
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("profile.json"),
        serde_json::to_vec_pretty(&ProfileFileBody {
            profile: Profile::Prod,
        })
        .unwrap(),
    )
    .unwrap();
    let uid = getuid().as_raw();
    let (_d, sock) = Daemon::sim_for_tests_profile(tmp.path(), uid, Profile::Prod);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut gw = ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::PlanChange(plan) = gw
        .call_auth(
            RequestBody::PlanChange {
                params: kxprov_api::PlanChangeParams {
                    kind: FieldKindWire::CidName,
                    index: 8,
                    value: "LIVE".into(),
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
                    plan_id: plan.plan_id.as_str().to_string(),
                    diff_hash: plan.diff_hash.clone(),
                    profile: Profile::Prod,
                },
            },
            Some(gateway_auth("approver")),
        )
        .await
        .unwrap();
    let ResponseResult::BackupNow(_) = gw
        .call_auth(RequestBody::BackupNow, Some(gateway_auth("writer")))
        .await
        .unwrap()
    else {
        panic!("backup");
    };
    let ResponseResult::Job(_) = gw
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
        panic!("apply");
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    let ResponseResult::ReadFields(rows) = gw
        .call_auth(
            RequestBody::ReadFields {
                params: kxprov_api::ReadFieldsParams {
                    kind: FieldKindWire::CidName,
                    first: 8,
                    count: 1,
                },
            },
            Some(gateway_auth("writer")),
        )
        .await
        .unwrap()
    else {
        panic!("read");
    };
    assert_eq!(rows.rows[0].value, "LIVE");
}
