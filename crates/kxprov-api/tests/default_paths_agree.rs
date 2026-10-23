//! Daemon, gateway, and CLI production defaults must match [`kxprov_api::paths`].

use std::path::PathBuf;

use kxprov_api::{DAEMON_SOCKET, DATA_DIR, GOLIATH_DIR, TOKENS_JSON};
use kxprov_gw::config::GatewayConfig;
use kxprovd::config::production_path_defaults;

#[test]
fn daemon_defaults_match_shared_paths() {
    let d = production_path_defaults();
    assert_eq!(d.socket_path, PathBuf::from(DAEMON_SOCKET));
    assert_eq!(d.data_dir, PathBuf::from(DATA_DIR));
    assert_eq!(d.tokens_path, PathBuf::from(TOKENS_JSON));
    assert_eq!(d.goliath_target, PathBuf::from(GOLIATH_DIR));
}

#[test]
fn gateway_defaults_match_shared_paths() {
    let gw = GatewayConfig::default();
    assert_eq!(gw.daemon_socket_path, PathBuf::from(DAEMON_SOCKET));
    assert_eq!(gw.daemon_tokens_path, PathBuf::from(TOKENS_JSON));
}

#[test]
fn cli_and_sim_mark_defaults_match_shared_paths() {
    assert_eq!(kxprov::cli_defaults::daemon_socket(), DAEMON_SOCKET);
    assert_eq!(kxprov::cli_defaults::tokens_json(), TOKENS_JSON);
    assert_eq!(kxprov::cli_defaults::sim_mark_data_dir(), DATA_DIR);
}
