use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub web_tailnet_bind: String,
    pub mcp_tailnet_bind: String,
    pub web_lan_bind: String,
    pub mcp_public_bind: String,
    pub mcp_tokens_path: PathBuf,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub session_ttl_secs: u64,
    pub rate_limit_per_minute: u32,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            web_tailnet_bind: "127.0.0.1:8080".into(),
            mcp_tailnet_bind: "127.0.0.1:8081".into(),
            web_lan_bind: "0.0.0.0:443".into(),
            mcp_public_bind: "127.0.0.1:8443".into(),
            mcp_tokens_path: "/etc/kx-provision/secrets/mcp-tokens.toml".into(),
            tls_cert_path: "/etc/kx-provision/tls/lan.crt".into(),
            tls_key_path: "/etc/kx-provision/tls/lan.key".into(),
            session_ttl_secs: 900,
            rate_limit_per_minute: 120,
            allowed_hosts: vec!["localhost".into(), "127.0.0.1".into()],
            allowed_origins: vec!["http://localhost".into(), "http://127.0.0.1".into()],
        }
    }
}
