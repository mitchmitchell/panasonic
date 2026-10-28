use kxprov_gw::config::GatewayConfig;
use kxprov_gw::daemon_client::DaemonClient;
use kxprov_gw::gateway_token::GatewayDaemonToken;
use kxprov_gw::server::serve;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = GatewayConfig::from_env_and_args()?;
    let gateway_token =
        GatewayDaemonToken::load(&config.gateway_bearer_path, &config.daemon_socket_path).await?;
    let backend = DaemonClient::connect(
        &config.daemon_socket_path,
        gateway_token.bearer().to_string(),
    )
    .await
    .map_err(|e| {
        anyhow::anyhow!(
            "failed to connect to daemon at {}: {e}",
            config.daemon_socket_path.display()
        )
    })?;
    let handles = serve(config, backend).await?;
    tracing::info!(
        web_serve_socket = %handles.web_serve_socket.display(),
        web_lan = %handles.web_lan,
        mcp = %handles.mcp,
        "kxprov-gw listening"
    );
    tokio::signal::ctrl_c().await?;
    handles.shutdown.stop();
    Ok(())
}
