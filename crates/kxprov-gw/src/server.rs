use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use axum_csrf::CsrfConfig;
use axum_server::tls_rustls::RustlsConfig;
use kxprov_api::TokenId;
use kxprov_mcp::{KxMcpServer, MCP_CALLER};
use kxprov_mock::{CallerIdentity, DaemonBackend, McpTokenIdentity};
use kxprov_web::{LoginRateLimiter, PasswordVerifier, WebState};
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tower_service::Service;

use crate::auth::{AdminPassword, McpTokenStore};
use crate::config::GatewayConfig;
use crate::host_origin::HostOriginConfig;
use crate::ratelimit::RateLimiter;
use crate::web_stack::production_web_router;
pub struct GatewayHandles {
    pub web_tailnet: SocketAddr,
    pub web_lan: SocketAddr,
    pub mcp: SocketAddr,
    pub shutdown: GatewayShutdown,
}

struct AdminVerifier(Arc<AdminPassword>);

impl PasswordVerifier for AdminVerifier {
    fn verify(&self, password: &str) -> bool {
        self.0.verify(password)
    }
}

fn ensure_rustls_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

pub async fn serve(
    config: GatewayConfig,
    backend: Arc<dyn DaemonBackend>,
) -> anyhow::Result<GatewayHandles> {
    ensure_rustls_provider();
    config.validate_site_bind_settings()?;
    config.warn_if_lan_ip_unset();
    config.warn_if_insecure_bind();
    let admin = Arc::new(AdminPassword::from_file(&config.admin_password_path)?);
    let token_store = Arc::new(McpTokenStore::from_file(&config.mcp_tokens_path)?);

    let csrf_config = CsrfConfig::default();
    let web_state = WebState {
        backend: backend.clone(),
        admin: Arc::new(AdminVerifier(admin)),
        login_limiter: Arc::new(LoginRateLimiter::new(
            Duration::from_secs(1),
            Duration::from_secs(900),
        )),
        csrf_config: csrf_config.clone(),
    };

    let host_origin = HostOriginConfig {
        allowed_hosts: config.allowed_hosts.clone(),
        allowed_origins: config.allowed_origins.clone(),
    };

    let rate_limiter = RateLimiter::new(config.rate_limit_per_minute);
    let web_app = production_web_router(
        web_state,
        host_origin.clone(),
        csrf_config,
        config.session_ttl_secs,
        rate_limiter.clone(),
    );

    let mcp_backend = backend.clone();
    let mut mcp_http_config = StreamableHttpServerConfig::default();
    mcp_http_config.json_response = true;
    mcp_http_config.stateful_mode = true;
    mcp_http_config.allowed_hosts = config.allowed_hosts.clone();
    let mcp_service = StreamableHttpService::new(
        move || Ok(KxMcpServer::new(mcp_backend.clone())),
        Arc::new(LocalSessionManager::default()),
        mcp_http_config,
    );

    let mcp_router = Router::new().route(
        "/mcp",
        any({
            let tokens = token_store.clone();
            let limiter = rate_limiter.clone();
            move |req: Request| {
                let svc = mcp_service.clone();
                let tokens = tokens.clone();
                let limiter = limiter.clone();
                async move { handle_mcp(req, svc, tokens, limiter).await }
            }
        }),
    );

    let web_tailnet_addr: SocketAddr = config.web_tailnet_bind.parse()?;
    let mcp_addr: SocketAddr = config.mcp_public_bind.parse()?;
    let web_lan_addrs: Vec<SocketAddr> = config
        .web_lan_bind_addresses()
        .iter()
        .map(|s| s.parse())
        .collect::<Result<Vec<_>, _>>()?;

    warn_if_unspecified_bind(web_tailnet_addr);
    warn_if_unspecified_bind(mcp_addr);
    for addr in &web_lan_addrs {
        warn_if_unspecified_bind(*addr);
    }

    let web_tailnet_listener = TcpListener::bind(web_tailnet_addr).await?;
    let mcp_listener = TcpListener::bind(mcp_addr).await?;

    let bound_web_tailnet = web_tailnet_listener.local_addr()?;
    let bound_mcp = mcp_listener.local_addr()?;

    let tls = load_tls_config(&config.tls_cert_path, &config.tls_key_path).await?;
    let mut bound_web_lan: Option<SocketAddr> = None;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let (shutdown_tx_mcp, shutdown_rx_mcp) = oneshot::channel::<()>();

    let web_app_tailnet = web_app.clone();
    tokio::spawn(async move {
        axum::serve(
            web_tailnet_listener,
            web_app_tailnet.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        })
        .await
        .ok();
    });

    for lan_addr in web_lan_addrs {
        let listener = TcpListener::bind(lan_addr).await?;
        let local = listener.local_addr()?;
        if bound_web_lan.is_none() || local.ip().is_loopback() {
            bound_web_lan = Some(local);
        }
        let tls_cfg = tls.clone();
        let web_app_lan = web_app.clone();
        tokio::spawn(async move {
            let _ = axum_server::from_tcp_rustls(listener.into_std().expect("tcp"), tls_cfg)
                .serve(web_app_lan.into_make_service_with_connect_info::<SocketAddr>())
                .await;
        });
    }

    tokio::spawn(async move {
        axum::serve(mcp_listener, mcp_router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx_mcp.await;
            })
            .await
            .ok();
    });

    Ok(GatewayHandles {
        web_tailnet: bound_web_tailnet,
        web_lan: bound_web_lan.ok_or_else(|| anyhow::anyhow!("no web LAN HTTPS bind addresses"))?,
        mcp: bound_mcp,
        shutdown: GatewayShutdown {
            web_tailnet: shutdown_tx,
            mcp: shutdown_tx_mcp,
        },
    })
}

pub struct GatewayShutdown {
    web_tailnet: oneshot::Sender<()>,
    mcp: oneshot::Sender<()>,
}

impl GatewayShutdown {
    pub fn stop(self) {
        let _ = self.web_tailnet.send(());
        let _ = self.mcp.send(());
    }
}

async fn load_tls_config(cert: &Path, key: &Path) -> anyhow::Result<RustlsConfig> {
    if !cert.is_file() {
        anyhow::bail!(
            "TLS certificate not found at {} (set tls_cert_path in config)",
            cert.display()
        );
    }
    if !key.is_file() {
        anyhow::bail!(
            "TLS private key not found at {} (set tls_key_path in config)",
            key.display()
        );
    }
    RustlsConfig::from_pem_file(cert, key).await.map_err(|e| {
        anyhow::anyhow!(
            "failed to load TLS certificate from {} and key from {}: {e}",
            cert.display(),
            key.display()
        )
    })
}

async fn handle_mcp(
    req: Request<Body>,
    mut svc: StreamableHttpService<KxMcpServer, LocalSessionManager>,
    tokens: Arc<McpTokenStore>,
    limiter: RateLimiter,
) -> Response<Body> {
    let Some(bearer) = bearer_token(req.headers()) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(record) = tokens.verify_bearer(bearer) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let identity = CallerIdentity::Mcp(McpTokenIdentity {
        token_id: TokenId(record.token_id.clone()),
        agent_name: record.agent_name.clone(),
        scopes: record.scopes.clone(),
    });
    if !limiter.check(&identity.rate_limit_key()).await {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    MCP_CALLER
        .scope(identity, async {
            match Service::call(&mut svc, req).await {
                Ok(resp) => resp.map(Body::new),
                Err(e) => match e {},
            }
        })
        .await
}

fn warn_if_unspecified_bind(addr: SocketAddr) {
    if addr.ip().is_unspecified() {
        tracing::warn!(
            %addr,
            "SECURITY: gateway listening on all interfaces; prefer explicit site or loopback binds"
        );
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    auth.strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
}
