//! Daemon, gateway, CLI, and sim-mark production defaults must match [`kxprov_api::paths`].

use std::path::{Path, PathBuf};

use kxprov_api::{
    goliath_dir, mode_counter_path, profile_data_dir, sim_passed_path, DAEMON_SOCKET, DATA_DIR,
    GATEWAY_WEB_SERVE_SOCKET, MODE_COUNTER, SIM_PASSED_JSON, TOKENS_JSON,
};
use kxprov_gw::config::GatewayConfig;
use kxprovd::config::production_path_defaults;
use kxprovd::sim_mark::SimMarkStore;

#[test]
fn daemon_defaults_match_shared_paths() {
    let d = production_path_defaults();
    assert_eq!(d.socket_path, PathBuf::from(DAEMON_SOCKET));
    assert_eq!(d.provision_root, PathBuf::from(DATA_DIR));
    assert_eq!(
        d.data_dir,
        PathBuf::from(profile_data_dir(kxprov_api::Profile::Sim))
    );
    assert_eq!(d.tokens_path, PathBuf::from(TOKENS_JSON));
    assert_eq!(
        d.goliath_target,
        PathBuf::from(goliath_dir(kxprov_api::Profile::Sim))
    );
}

#[test]
fn gateway_defaults_match_shared_paths() {
    let gw = GatewayConfig::default();
    assert_eq!(gw.daemon_socket_path, PathBuf::from(DAEMON_SOCKET));
    assert_eq!(gw.daemon_tokens_path, PathBuf::from(TOKENS_JSON));
    assert_eq!(gw.web_serve_socket, PathBuf::from(GATEWAY_WEB_SERVE_SOCKET));
}

#[test]
fn cli_and_sim_mark_defaults_match_shared_paths() {
    assert_eq!(
        kxprov::cli_defaults::daemon_socket(),
        PathBuf::from(DAEMON_SOCKET)
    );
    assert_eq!(
        kxprov::cli_defaults::tokens_json(),
        PathBuf::from(TOKENS_JSON)
    );
    assert_eq!(
        kxprov::cli_defaults::sim_mark_data_dir(),
        PathBuf::from(DATA_DIR)
    );
}

#[test]
fn root_markers_and_profile_trees_use_data_dir() {
    assert!(TOKENS_JSON.starts_with(DATA_DIR));
    assert!(MODE_COUNTER.starts_with(DATA_DIR));
    assert!(SIM_PASSED_JSON.starts_with(DATA_DIR));
    assert!(profile_data_dir(kxprov_api::Profile::Prod).starts_with(DATA_DIR));
    assert_ne!(DAEMON_SOCKET, DATA_DIR);
}

#[test]
fn daemon_and_sim_mark_resolve_identical_sim_passed_path() {
    let base = Path::new(DATA_DIR);
    let store = SimMarkStore::new(base);
    let cli = kxprov::cli_defaults::sim_passed_file();
    let shared = sim_passed_path(base);
    assert_eq!(store.path(), shared.as_path());
    assert_eq!(store.path(), cli.as_path());
    assert_eq!(store.path(), Path::new(SIM_PASSED_JSON));
}

#[test]
fn daemon_mode_counter_matches_shared_constant() {
    let base = Path::new(DATA_DIR);
    assert_eq!(
        mode_counter_path(base, kxprov_api::Profile::Sim),
        PathBuf::from(MODE_COUNTER)
    );
}
