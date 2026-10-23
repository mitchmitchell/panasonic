#![allow(clippy::unwrap_used)]

use kxprov_api::{ApiError, Profile, RequestAuth, RequestBody, ResponseResult};
use kxprovd::test_util::{GATEWAY_SECRET, WRITER_SECRET};

fn assert_forbidden(err: ApiError, expected_message: &str) {
    match err {
        ApiError::Remote { code, message } => {
            assert_eq!(code, "forbidden");
            assert!(
                message.contains(expected_message),
                "expected message containing {expected_message:?}, got {message:?}"
            );
        }
        other => panic!("expected forbidden, got {other:?}"),
    }
}

#[tokio::test]
async fn sim_trigger_busy_and_goliath_fail_with_write_scope_on_sim() {
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
        bearer: WRITER_SECRET.to_string(),
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

#[tokio::test]
async fn sim_triggers_forbidden_for_gateway_read_plan_token() {
    let tmp = tempfile::tempdir().unwrap();
    let gateway_uid = nix::unistd::getuid().as_raw();
    let (_d, sock) =
        kxprovd::Daemon::sim_for_tests_as_gateway_profile(tmp.path(), gateway_uid, Profile::Sim);
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
                params: kxprov_api::SimTriggerBusyParams { frames: 1 },
            },
            auth.clone(),
        )
        .await
        .expect_err("gateway token lacks write");
    assert_forbidden(busy, "token scope denied");
}

#[tokio::test]
async fn sim_triggers_forbidden_on_prod_profile() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, sock) = kxprovd::Daemon::sim_for_tests_profile(tmp.path(), uid, Profile::Prod);
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let mut client = kxprov_api::ApiClient::connect(&sock).await.unwrap();
    let auth = Some(RequestAuth {
        bearer: WRITER_SECRET.to_string(),
    });
    let busy = client
        .call_auth(
            RequestBody::SimTriggerBusy {
                params: kxprov_api::SimTriggerBusyParams { frames: 1 },
            },
            auth,
        )
        .await
        .expect_err("prod profile blocks sim triggers");
    assert_forbidden(busy, "sim/test profile only");
}

#[tokio::test]
async fn sim_triggers_forbidden_on_serial_transport() {
    let tmp = tempfile::tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_d, socket) =
        kxprovd::Daemon::sim_for_tests_serial_profile(tmp.path(), uid, Profile::Sim);
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let mut client = kxprov_api::ApiClient::connect(&socket).await.unwrap();
    let auth = Some(RequestAuth {
        bearer: WRITER_SECRET.to_string(),
    });
    let busy = client
        .call_auth(
            RequestBody::SimTriggerBusy {
                params: kxprov_api::SimTriggerBusyParams { frames: 1 },
            },
            auth,
        )
        .await
        .expect_err("serial transport blocks sim triggers");
    assert_forbidden(busy, "sim transport only");
}
