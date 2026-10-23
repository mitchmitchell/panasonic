#![allow(clippy::unwrap_used)]

mod common;

use kxprov_api::{Profile, RequestAuth, RequestBody, ResponseResult};
use kxprovd::test_util::GATEWAY_SECRET;

#[tokio::test]
async fn sim_trigger_busy_and_goliath_fail_on_sim_profile() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = kxprovd::Daemon::sim_for_tests_profile(tmp.path(), uid, Profile::Sim);
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let mut client = kxprov_api::ApiClient::connect(&sock).await.unwrap();
    let auth = Some(RequestAuth {
        bearer: GATEWAY_SECRET.to_string(),
    });
    let busy = client
        .call_auth(
            RequestBody::SimTriggerBusy {
                params: kxprov_api::SimTriggerBusyParams { frames: 4 },
            },
            auth.clone(),
        )
        .await
        .expect("busy trigger");
    assert!(matches!(busy, ResponseResult::SimTrigger(r) if r.ok));
    let g = client
        .call_auth(RequestBody::SimTriggerGoliathCopyFail, auth)
        .await
        .expect("goliath trigger");
    assert!(matches!(g, ResponseResult::SimTrigger(r) if r.ok));
}
