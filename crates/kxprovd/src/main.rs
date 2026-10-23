use kxprov_api::{DaemonMode, Profile};
use kxprovd::config::{Config, TransportKind};
use kxprovd::Daemon;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let data = std::env::var("KXPROVD_DATA_DIR").unwrap_or_else(|_| "/tmp/kxprovd".into());
    let socket = std::env::var("KXPROVD_SOCKET").unwrap_or_else(|_| format!("{data}/kxprovd.sock"));
    let transport = match std::env::var("KXPROVD_TRANSPORT").as_deref() {
        Ok("serial") => TransportKind::Serial,
        _ => TransportKind::Sim,
    };
    let uid = nix::unistd::getuid().as_raw();
    let mut cfg = Config::sim_test(PathBuf::from(&data), PathBuf::from(socket), uid);
    cfg.transport = transport;
    cfg.profile = Profile::Sim;
    cfg.mode = DaemonMode::Simulator;

    let _daemon = Daemon::start(cfg)?;
    tracing::info!("kxprovd running (sim); ctrl-c to exit");
    loop {
        std::thread::park();
    }
}
