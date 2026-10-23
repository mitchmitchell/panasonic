use kxprovd::config::{Config, ETC_CONFIG};
use kxprovd::Daemon;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config_path = std::env::var("KXPROV_DAEMON_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(ETC_CONFIG));
    let cfg = Config::load_from_etc(&config_path)?;
    let _daemon = Daemon::start(cfg)?;
    tracing::info!("kxprovd running; ctrl-c to exit");
    loop {
        std::thread::park();
    }
}
