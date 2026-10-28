#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use std::time::Duration;

use kxprov_api::{RequestAuth, RequestBody, ResponseResult};
use kxprovd::test_util::WRITER_SECRET;

/// Invoked by `scripts/run-a4.sh smoke` against a live sim stack in `KXPROV_RUN_DIR`.
#[tokio::test]
async fn a4_smoke_busy_trigger() {
    let Some(run) = std::env::var("KXPROV_RUN_DIR").ok() else {
        return;
    };
    let sock = PathBuf::from(&run).join("kxprovd.sock");
    for _ in 0..200 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(sock.exists(), "daemon socket at {}", sock.display());
    let mut client = kxprov_api::ApiClient::connect(&sock).await.unwrap();
    let auth = Some(RequestAuth {
        bearer: WRITER_SECRET.to_string(),
    });
    let busy = client
        .call_auth(
            RequestBody::SimTriggerBusy {
                params: kxprov_api::SimTriggerBusyParams { frames: 2 },
            },
            auth,
        )
        .await
        .expect("sim BUSY trigger");
    assert!(matches!(busy, ResponseResult::SimTrigger(r) if r.ok));
}
