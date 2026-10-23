use kxprovd::config::{Config, ETC_CONFIG};
use kxprovd::Daemon;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = Config::load_from_etc(ETC_CONFIG)?;
    let _daemon = Daemon::start(cfg)?;
    tracing::info!("kxprovd running; ctrl-c to exit");
    loop {
        std::thread::park();
    }
}
