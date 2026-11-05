use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::from_fn;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
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
use crate::secret_file::open_validated_secret;
use crate::serve_peer;
use crate::web_stack::production_web_router;
pub struct GatewayHandles {
    pub web_serve_socket: std::path::PathBuf,
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
    config.validate_web_xff_trust()?;
    config.warn_if_lan_ip_unset();
    config.warn_if_insecure_bind();
    let admin = Arc::new(AdminPassword::from_file(&config.admin_password_path)?);
    let token_store = Arc::new(McpTokenStore::from_file(&config.mcp_tokens_path)?);

    let web_state = WebState {
        call_streams: Default::default(),
        backend: backend.clone(),
        admin: Arc::new(AdminVerifier(admin)),
        login_limiter: Arc::new(LoginRateLimiter::new(
            Duration::from_secs(1),
            Duration::from_secs(30),
            Duration::from_secs(300),
        )),
    };

    let rate_limiter = RateLimiter::new(config.rate_limit_per_minute);
    let web_app_tailnet = production_web_router(
        web_state.clone(),
        HostOriginConfig {
            allowed_hosts: config.effective_web_tailnet_hosts(),
            allowed_origins: config.effective_web_tailnet_origins(),
        },
        config.web_tailnet.trust_x_forwarded_for,
        config.session_ttl_secs,
        config.session_absolute_secs,
        rate_limiter.clone(),
    )
    .layer(from_fn(serve_peer::inject_web_connect));
    let web_app_https = production_web_router(
        web_state,
        HostOriginConfig {
            allowed_hosts: config.effective_web_https_hosts(),
            allowed_origins: config.effective_web_https_origins(),
        },
        config.web_https.trust_x_forwarded_for,
        config.session_ttl_secs,
        config.session_absolute_secs,
        rate_limiter.clone(),
    );

    let mcp_backend = backend.clone();
    let mut mcp_http_config = StreamableHttpServerConfig::default();
    mcp_http_config.json_response = true;
    mcp_http_config.stateful_mode = true;
    mcp_http_config.allowed_hosts = config.effective_allowed_hosts();
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
            let profile_source = backend.clone();
            move |req: Request| {
                let svc = mcp_service.clone();
                let tokens = tokens.clone();
                let limiter = limiter.clone();
                let profile_source = profile_source.clone();
                async move { handle_mcp(req, svc, tokens, limiter, profile_source).await }
            }
        }),
    );

    let mcp_addr: SocketAddr = config.mcp_tailnet_bind.parse()?;
    let web_lan_addrs: Vec<SocketAddr> = config
        .web_lan_bind_addresses()
        .iter()
        .map(|s| s.parse())
        .collect::<Result<Vec<_>, _>>()?;

    warn_if_unspecified_bind(mcp_addr);
    for addr in &web_lan_addrs {
        warn_if_unspecified_bind(*addr);
    }

    let web_serve_socket = config.web_serve_socket.clone();
    let web_serve_group = config.serve_socket_group.as_deref();
    let web_serve_listener =
        serve_peer::bind_web_serve_listener(&web_serve_socket, web_serve_group).await?;
    let mcp_listener = TcpListener::bind(mcp_addr).await?;

    let bound_mcp = mcp_listener.local_addr()?;

    let tls = load_tls_config(&config.tls_cert_path, &config.tls_key_path).await?;
    let mut bound_web_lan: Option<SocketAddr> = None;

    let tailnet_serve_trust = config.tailnet_serve_trust();
    tracing::info!(
        path = %web_serve_socket.display(),
        resolved_serve_peer_uid = tailnet_serve_trust.expected_peer_uid,
        trust_x_forwarded_for = tailnet_serve_trust.trust_x_forwarded_for,
        "web Serve Unix listener (SO_PEERCRED trust)"
    );

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let (shutdown_tx_mcp, shutdown_rx_mcp) = oneshot::channel::<()>();

    serve_peer::install_tailnet_serve_trust(tailnet_serve_trust);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(
            web_serve_listener,
            web_app_tailnet.into_make_service_with_connect_info::<serve_peer::TailnetConnect>(),
        )
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        })
        .await
        {
            tracing::error!(%e, "web tailnet serve exited with error");
        }
    });

    for lan_addr in web_lan_addrs {
        let listener = TcpListener::bind(lan_addr).await?;
        let local = listener.local_addr()?;
        if bound_web_lan.is_none() || local.ip().is_loopback() {
            bound_web_lan = Some(local);
        }
        let std = listener
            .into_std()
            .map_err(|e| anyhow::anyhow!("lan listener into_std: {e}"))?;
        std.set_nonblocking(true)
            .map_err(|e| anyhow::anyhow!("lan listener set_nonblocking: {e}"))?;
        let tls_cfg = tls.clone();
        let web_app_lan = web_app_https.clone();
        tokio::spawn(async move {
            let server = axum_server::from_tcp_rustls(std, tls_cfg);
            if let Err(e) = server
                .serve(web_app_lan.into_make_service_with_connect_info::<SocketAddr>())
                .await
            {
                tracing::error!(%e, "web lan https serve exited with error");
            }
        });
    }

    tokio::spawn(async move {
        if let Err(e) = axum::serve(mcp_listener, mcp_router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx_mcp.await;
            })
            .await
        {
            tracing::error!(%e, "mcp serve exited with error");
        }
    });

    Ok(GatewayHandles {
        web_serve_socket,
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
    let key_path = crate::secret_file::resolve_secret_path(key);
    let mut key_file = open_validated_secret(key, "TLS private key")?;
    let cert_pem = tokio::fs::read(cert).await?;
    let mut key_pem = Vec::new();
    std::io::Read::read_to_end(&mut key_file, &mut key_pem)?;
    RustlsConfig::from_pem(cert_pem, key_pem)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to load TLS certificate from {} and key from {}: {e}",
                cert.display(),
                key_path.display()
            )
        })
}

async fn handle_mcp(
    req: Request<Body>,
    mut svc: StreamableHttpService<KxMcpServer, LocalSessionManager>,
    tokens: Arc<McpTokenStore>,
    limiter: RateLimiter,
    profile_source: Arc<dyn DaemonBackend>,
) -> Response<Body> {
    let Some(bearer) = bearer_token(req.headers()) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(record) = tokens.verify_bearer(bearer) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let scopes = crate::auth::effective_scopes(&record, profile_source.as_ref()).await;
    let identity = CallerIdentity::Mcp(McpTokenIdentity {
        token_id: TokenId(record.token_id.clone()),
        agent_name: record.agent_name.clone(),
        scopes,
        bearer: bearer.to_string(),
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
