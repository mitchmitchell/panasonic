//! Gateway secret checks and daemon bearer load as the current (non-root) uid against real kxprovd.

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use kxprov_api::Profile;
use kxprov_gw::gateway_token::GatewayDaemonToken;
use kxprovd::test_util::GATEWAY_SECRET;
use tempfile::TempDir;

fn write_owned_secret(path: &std::path::Path, body: &str) {
    std::fs::write(path, body).unwrap();
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms).unwrap();
}

#[tokio::test]
async fn gateway_bearer_loads_with_euid_owned_secret_against_real_daemon() {
    let prev_skip = std::env::var("KXPROV_SKIP_SECRET_FILE_CHECKS").ok();
    std::env::remove_var("KXPROV_SKIP_SECRET_FILE_CHECKS");
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
    assert!(sock.exists());

    let bearer_path = tmp.path().join("gateway.bearer");
    write_owned_secret(&bearer_path, &format!("{GATEWAY_SECRET}\n"));

    let loaded = GatewayDaemonToken::load(&bearer_path, &sock)
        .await
        .expect("non-root owned bearer should pass secret checks and whoami");
    assert_eq!(loaded.bearer(), GATEWAY_SECRET);
    match prev_skip {
        Some(v) => std::env::set_var("KXPROV_SKIP_SECRET_FILE_CHECKS", v),
        None => std::env::remove_var("KXPROV_SKIP_SECRET_FILE_CHECKS"),
    }
}
