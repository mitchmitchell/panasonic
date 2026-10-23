use std::sync::Arc;

use kxprov_api::MockDaemon;
use kxprov_gw::config::GatewayConfig;
use kxprov_gw::server::serve;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = GatewayConfig::from_env_and_args();
    let backend = Arc::new(MockDaemon::new());
    let handles = serve(config, Some(backend)).await?;
    tracing::info!(
        web_tailnet = %handles.web_tailnet,
        web_lan = %handles.web_lan,
        mcp = %handles.mcp,
        "kxprov-gw listening"
    );
    tokio::signal::ctrl_c().await?;
    let _ = handles.shutdown.send(());
    Ok(())
}
