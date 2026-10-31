//! End-to-end: gateway `DaemonClient` speaks real `kxprovd` JSON envelopes with bearer auth.

use std::sync::Arc;
use std::time::Duration;

use kxprov_api::{
    ApiError, FieldKindWire, OperationalMode, Profile, RequestAuth, RequestBody, ResponseResult,
    Scope,
};
use kxprov_gw::daemon_client::DaemonClient;
use kxprov_gw::gateway_token::GatewayDaemonToken;
use kxprov_mock::{CallerIdentity, DaemonBackend, WebSessionIdentity};
use kxprovd::test_util::GATEWAY_SECRET;
use tempfile::TempDir;

fn gateway_auth() -> RequestAuth {
    RequestAuth {
        bearer: GATEWAY_SECRET.to_string(),
    }
}

#[tokio::test]
async fn daemon_client_status_uses_bearer_and_audit() {
    let tmp = TempDir::new().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_daemon, sock) =
        kxprovd::Daemon::sim_for_tests_as_gateway_profile(tmp.path(), uid, Profile::Sim);
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(sock.exists(), "daemon socket at {}", sock.display());
    let client = DaemonClient::connect(&sock, GATEWAY_SECRET.to_string())
        .await
        .expect("connect");
    let caller = CallerIdentity::Web(WebSessionIdentity {
        session_key: "sess-e2e".into(),
    });
    client.status(&caller).await.expect("status");

    let mut api = kxprov_api::ApiClient::connect(&sock).await.unwrap();
    let result = api
        .call_auth_audit(
            RequestBody::Status,
            Some(gateway_auth()),
            Some("web-session:test".into()),
        )
        .await
        .expect("daemon status");
    assert!(matches!(result, ResponseResult::Status(_)));
    let _ = Arc::new(client);
}

#[tokio::test]
async fn gateway_service_token_can_plan_not_apply_approve_or_set_mode() {
    let tmp = TempDir::new().unwrap();
    let gateway_uid = nix::unistd::getuid().as_raw();
    let (_daemon, sock) =
        kxprovd::Daemon::sim_for_tests_as_gateway_profile(tmp.path(), gateway_uid, Profile::Sim);
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let bearer_path = tmp.path().join("gateway.bearer");
    std::fs::write(&bearer_path, format!("{GATEWAY_SECRET}\n")).unwrap();
    std::env::set_var("KXPROV_SKIP_SECRET_FILE_CHECKS", "1");
    let loaded = GatewayDaemonToken::load(&bearer_path, &sock)
        .await
        .expect("whoami-backed gateway token load");
    assert_eq!(loaded.bearer(), GATEWAY_SECRET);

    let mut api = kxprov_api::ApiClient::connect(&sock).await.unwrap();
    let auth = Some(gateway_auth());

    let ResponseResult::PlanChange(plan) = api
        .call_auth(
            RequestBody::PlanChange {
                params: kxprov_api::PlanChangeParams {
                    kind: FieldKindWire::CidName,
                    index: 2,
                    value: "GW".into(),
                },
            },
            auth.clone(),
        )
        .await
        .expect("gateway token may plan")
    else {
        panic!("expected plan_change");
    };

    let apply = api
        .call_auth(
            RequestBody::ApplyPlan {
                params: kxprov_api::ApplyPlanParams {
                    plan_id: plan.plan_id.clone(),
                    diff_hash: plan.diff_hash.clone(),
                },
            },
            auth.clone(),
        )
        .await;
    assert!(matches!(
        apply,
        Err(ApiError::Remote {
            code,
            ..
        }) if code == "forbidden"
    ));

    let approve = api
        .call_auth(
            RequestBody::SubmitApproval {
                params: kxprov_api::SubmitApprovalParams {
                    plan_id: plan.plan_id.0.clone(),
                    diff_hash: plan.diff_hash.clone(),
                    profile: Profile::Sim,
                },
            },
            auth.clone(),
        )
        .await;
    assert!(matches!(
        approve,
        Err(ApiError::Remote {
            code,
            ..
        }) if code == "forbidden"
    ));

    let set_mode = api
        .call_auth(
            RequestBody::SetMode {
                params: kxprov_api::SetModeParams {
                    mode: OperationalMode::Testing,
                    profile: Profile::Sim,
                },
            },
            auth.clone(),
        )
        .await;
    assert!(matches!(
        set_mode,
        Err(ApiError::Remote {
            code,
            ..
        }) if code == "forbidden"
    ));

    let bad = api
        .call_auth(
            RequestBody::Whoami,
            Some(RequestAuth {
                bearer: "not-a-real-bearer".into(),
            }),
        )
        .await;
    assert!(matches!(
        bad,
        Err(ApiError::Remote {
            code,
            ..
        }) if code == "unauthorized"
    ));

    let whoami = api
        .call_auth(RequestBody::Whoami, auth)
        .await
        .expect("whoami");
    let ResponseResult::Whoami(w) = whoami else {
        panic!("whoami shape");
    };
    assert!(w.scopes.contains(&Scope::Read));
    assert!(w.scopes.contains(&Scope::Plan));
    assert!(!w
        .scopes
        .iter()
        .any(|s| *s == Scope::Write || *s == Scope::Approve));
}

#[tokio::test]
async fn daemon_client_plan_change_old_value_matches_daemon_read() {
    let tmp = TempDir::new().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (_daemon, sock) =
        kxprovd::Daemon::sim_for_tests_as_gateway_profile(tmp.path(), uid, Profile::Sim);
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let client = DaemonClient::connect(&sock, GATEWAY_SECRET.to_string())
        .await
        .expect("connect");
    let caller = CallerIdentity::Web(WebSessionIdentity {
        session_key: "sess-old-value".into(),
    });
    let kind = kxtd1232::FieldKind::CidName;

    let mut api = kxprov_api::ApiClient::connect(&sock).await.unwrap();
    let ResponseResult::ReadFields(read) = api
        .call_auth(
            RequestBody::ReadFields {
                params: kxprov_api::ReadFieldsParams {
                    kind: FieldKindWire::CidName,
                    first: 0,
                    count: 1,
                },
            },
            Some(gateway_auth()),
        )
        .await
        .expect("daemon read")
    else {
        panic!("expected read_fields");
    };
    let expected = read.rows[0].value.clone();
    assert!(!expected.is_empty(), "sim record 0 must be non-empty");

    let summary = client
        .plan_change(
            &caller,
            kxprov_mock::PlanChangeRequest {
                table: kind.table(),
                record: 0,
                field: kind.name().into(),
                new_value: "OLDVAL".into(),
                base_bytes: Vec::new(),
                new_bytes: Vec::new(),
            },
        )
        .await
        .expect("plan_change");
    assert_eq!(summary.old_value, expected);
    assert_eq!(summary.new_value, "OLDVAL");
}

#[tokio::test]
async fn daemon_client_plan_change_fails_closed_when_row_missing() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let tmp = TempDir::new().unwrap();
    let sock = tmp.path().join("fake.sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        let mut bodies = Vec::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap() == 0 {
                break;
            }
            let env: kxprov_api::RequestEnvelope = serde_json::from_str(line.trim()).unwrap();
            let is_read = matches!(env.body, RequestBody::ReadFields { .. });
            bodies.push(env.body);
            let reply = if is_read {
                serde_json::json!({"id": env.id, "ok": true, "result": {"rows": []}})
            } else {
                serde_json::json!({"id": env.id, "ok": false, "error": {"code": "internal", "message": "unexpected"}})
            };
            write
                .write_all(format!("{reply}\n").as_bytes())
                .await
                .unwrap();
        }
        bodies
    });

    let client = DaemonClient::connect(&sock, GATEWAY_SECRET.to_string())
        .await
        .expect("connect");
    let caller = CallerIdentity::Web(WebSessionIdentity {
        session_key: "sess-missing-row".into(),
    });
    let kind = kxtd1232::FieldKind::CidName;
    let err = client
        .plan_change(
            &caller,
            kxprov_mock::PlanChangeRequest {
                table: kind.table(),
                record: 7,
                field: kind.name().into(),
                new_value: "X".into(),
                base_bytes: Vec::new(),
                new_bytes: Vec::new(),
            },
        )
        .await
        .expect_err("missing row must fail closed");
    assert_eq!(
        err,
        kxprov_mock::BackendError::RecordNotFound {
            table: kind.table(),
            record: 7
        }
    );
    drop(client);
    let bodies = server.await.unwrap();
    assert_eq!(bodies.len(), 1, "no plan request after a missing row");
    assert!(matches!(bodies[0], RequestBody::ReadFields { .. }));
}
