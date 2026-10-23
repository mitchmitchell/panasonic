use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use axum_csrf::{CsrfConfig, CsrfLayer};
use axum_server::tls_rustls::RustlsConfig;
use kxprov_api::{CallerIdentity, DaemonBackend, McpTokenIdentity, MockDaemon, TokenId};
use kxprov_mcp::{KxMcpServer, MCP_CALLER};
use kxprov_web::WebState;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_service::Service;
use tower_sessions::cookie::time::Duration as CookieDuration;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

use crate::auth::McpTokenStore;
use crate::config::GatewayConfig;
use crate::host_origin::{host_origin_middleware, security_headers, HostOriginConfig};
use crate::ratelimit::{rate_limit_middleware, RateLimitState, RateLimiter};

pub struct GatewayHandles {
    pub web_tailnet: SocketAddr,
    pub web_lan: SocketAddr,
    pub mcp: SocketAddr,
    pub shutdown: oneshot::Sender<()>,
}

pub async fn serve(
    config: GatewayConfig,
    backend: Option<Arc<dyn DaemonBackend>>,
) -> anyhow::Result<GatewayHandles> {
    let backend = backend.unwrap_or_else(|| Arc::new(MockDaemon::new()) as Arc<dyn DaemonBackend>);
    let token_store = Arc::new(McpTokenStore::from_file(&config.mcp_tokens_path)?);

    let web_state = WebState {
        backend: backend.clone(),
        session_id: Arc::from("admin-session"),
    };

    let host_origin = HostOriginConfig {
        allowed_hosts: config.allowed_hosts.clone(),
        allowed_origins: config.allowed_origins.clone(),
    };

    let rate_limiter = RateLimiter::new(config.rate_limit_per_minute);
    let web_rate = RateLimitState {
        limiter: rate_limiter.clone(),
        key_from_request: Arc::new(|req: &Request<Body>| {
            req.extensions()
                .get::<String>()
                .cloned()
                .or_else(|| Some("web-anonymous".into()))
        }),
    };

    let web_app = kxprov_web::router(web_state)
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            security_headers(),
        ))
        .layer(CsrfLayer::new(CsrfConfig::default()))
        .layer(
            SessionManagerLayer::new(MemoryStore::default())
                .with_secure(false)
                .with_expiry(Expiry::OnInactivity(CookieDuration::seconds(
                    config.session_ttl_secs as i64,
                ))),
        )
        .layer(from_fn_with_state(web_rate.clone(), web_identity_rate_limit))
        .layer(from_fn_with_state(host_origin.clone(), host_origin_layer));

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
    let web_lan_addr: SocketAddr = config.web_lan_bind.parse()?;
    let mcp_addr: SocketAddr = config.mcp_public_bind.parse()?;

    let web_tailnet_listener = TcpListener::bind(web_tailnet_addr).await?;
    let web_lan_listener = TcpListener::bind(web_lan_addr).await?;
    let mcp_listener = TcpListener::bind(mcp_addr).await?;

    let bound_web_tailnet = web_tailnet_listener.local_addr()?;
    let bound_web_lan = web_lan_listener.local_addr()?;
    let bound_mcp = mcp_listener.local_addr()?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let web_app_tailnet = web_app.clone();
    tokio::spawn(async move {
        axum::serve(web_tailnet_listener, web_app_tailnet)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .ok();
    });

    let web_app_lan = web_app;
    let tls_cert = config.tls_cert_path.clone();
    let tls_key = config.tls_key_path.clone();
    tokio::spawn(async move {
        if let Ok(tls) = RustlsConfig::from_pem_file(tls_cert, tls_key).await {
            let _ = axum_server::from_tcp_rustls(web_lan_listener.into_std().expect("tcp"), tls)
                .serve(web_app_lan.into_make_service())
                .await;
        }
    });

    tokio::spawn(async move {
        axum::serve(mcp_listener, mcp_router).await.ok();
    });

    Ok(GatewayHandles {
        web_tailnet: bound_web_tailnet,
        web_lan: bound_web_lan,
        mcp: bound_mcp,
        shutdown: shutdown_tx,
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

async fn web_identity_rate_limit(
    State(rate): State<RateLimitState>,
    mut req: Request<Body>,
    next: axum::middleware::Next,
) -> Result<Response, StatusCode> {
    req.extensions_mut()
        .insert("web-admin:admin-session".to_string());
    rate_limit_middleware(State(rate), req, next).await
}

async fn host_origin_layer(
    State(cfg): State<HostOriginConfig>,
    req: Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    host_origin_middleware(cfg, req, next).await
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    auth.strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
}
