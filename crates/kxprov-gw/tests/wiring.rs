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
