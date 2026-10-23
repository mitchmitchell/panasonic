#[test]
fn gateway_server_wires_tailnet_serve_peer_from_config() {
    let server_rs = include_str!("../src/server.rs");
    assert!(
        server_rs.contains("tailnet_serve_trust"),
        "production startup must build ServeTrustConfig from gateway config"
    );
    assert!(
        server_rs.contains("install_tailnet_serve_trust") && server_rs.contains("TailnetConnect"),
        "tailnet listener must inject WebConnectInfo via SO_PEERCRED Connected type"
    );
}

#[test]
fn production_binary_uses_daemon_client_not_mock() {
    let main_rs = include_str!("../src/main.rs");
    assert!(
        main_rs.contains("DaemonClient"),
        "kxprov-gw main must connect via DaemonClient"
    );
    assert!(
        !main_rs.contains("MockDaemon"),
        "MockDaemon must not appear in production entrypoint"
    );
}

#[test]
fn run_a4_script_starts_real_kxprovd_and_gateway() {
    let script = include_str!("../../../scripts/run-a4.sh");
    assert!(script.contains("kxprovd"), "run-a4 must start kxprovd");
    assert!(script.contains("kxprov-gw"), "run-a4 must start kxprov-gw");
    assert!(
        !script.contains("MockDaemon"),
        "run-a4 must not use MockDaemon"
    );
    assert!(
        script.contains("[web_tailnet]") && script.contains("trust_x_forwarded_for = true"),
        "run-a4 must trust XFF only on Serve-fronted tailnet HTTP"
    );
    assert!(
        script.contains("serve_peer_uid"),
        "run-a4 must wire SO_PEERCRED serve peer uid for tailnet XFF trust"
    );
    assert!(
        !script.contains("[web_https]"),
        "run-a4 must not configure web_https XFF trust on direct TLS"
    );
    assert!(
        script.contains("rm -f \"$run_dir/kxprovd.pid\" \"$run_dir/kxprovd.sock\""),
        "run-a4 must drop stale pid/socket before starting kxprovd"
    );
}
