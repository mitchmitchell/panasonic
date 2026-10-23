use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Primary HTTPS listen address (config key `bind`, CLI `--bind`).
    pub bind: String,
    pub web_tailnet_bind: String,
    pub mcp_tailnet_bind: String,
    pub mcp_public_bind: String,
    pub mcp_tokens_path: PathBuf,
    pub admin_password_path: PathBuf,
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
            bind: "0.0.0.0:8443".into(),
            web_tailnet_bind: "127.0.0.1:8080".into(),
            mcp_tailnet_bind: "127.0.0.1:8081".into(),
            mcp_public_bind: "127.0.0.1:8444".into(),
            mcp_tokens_path: "/etc/kx-provision/secrets/mcp-tokens.toml".into(),
            admin_password_path: "/etc/kx-provision/secrets/admin-password.hash".into(),
            tls_cert_path: "/etc/kx-provision/tls/lan.crt".into(),
            tls_key_path: "/etc/kx-provision/tls/lan.key".into(),
            session_ttl_secs: 900,
            rate_limit_per_minute: 120,
            allowed_hosts: vec!["localhost".into(), "127.0.0.1".into()],
            allowed_origins: vec!["http://localhost".into(), "http://127.0.0.1".into()],
        }
    }
}

impl GatewayConfig {
    pub fn web_lan_bind(&self) -> &str {
        &self.bind
    }

    pub fn from_env_and_args() -> Self {
        let mut config = Self::default();
        if let Ok(path) = std::env::var("KXPROV_CONFIG") {
            if let Err(e) = config.merge_file(Path::new(&path)) {
                tracing::warn!(path = %path, error = %e, "config file not loaded");
            }
        }
        if let Ok(bind) = std::env::var("KXPROV_BIND") {
            config.bind = bind;
        }
        if let Ok(path) = std::env::var("KXPROV_MCP_TOKENS") {
            config.mcp_tokens_path = path.into();
        }
        config.apply_cli(std::env::args().skip(1));
        config
    }

    fn merge_file(&mut self, path: &Path) -> anyhow::Result<()> {
        let text = std::fs::read_to_string(path)?;
        let file: FileConfig = toml::from_str(&text)?;
        if let Some(bind) = file.bind {
            self.bind = bind;
        }
        if let Some(v) = file.web_tailnet_bind {
            self.web_tailnet_bind = v;
        }
        if let Some(v) = file.mcp_public_bind {
            self.mcp_public_bind = v;
        }
        if let Some(v) = file.mcp_tokens_path {
            self.mcp_tokens_path = v.into();
        }
        if let Some(v) = file.mcp_tailnet_bind {
            self.mcp_tailnet_bind = v;
        }
        if let Some(v) = file.tls_cert_path {
            self.tls_cert_path = v.into();
        }
        if let Some(v) = file.tls_key_path {
            self.tls_key_path = v.into();
        }
        if let Some(v) = file.admin_password_path {
            self.admin_password_path = v.into();
        }
        Ok(())
    }

    fn apply_cli(&mut self, args: impl IntoIterator<Item = String>) {
        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--bind" => {
                    if let Some(v) = iter.next() {
                        self.bind = v;
                    }
                }
                "--config" => {
                    if let Some(path) = iter.next() {
                        let _ = self.merge_file(Path::new(&path));
                    }
                }
                _ => {}
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    bind: Option<String>,
    web_tailnet_bind: Option<String>,
    mcp_tailnet_bind: Option<String>,
    mcp_public_bind: Option<String>,
    mcp_tokens_path: Option<String>,
    tls_cert_path: Option<String>,
    tls_key_path: Option<String>,
    admin_password_path: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_web_and_mcp_ports_are_distinct() {
        let cfg = GatewayConfig::default();
        assert_eq!(cfg.bind, "0.0.0.0:8443");
        assert_eq!(cfg.web_lan_bind(), "0.0.0.0:8443");
        assert_eq!(cfg.mcp_public_bind, "127.0.0.1:8444");
        let web_port = cfg.bind.rsplit(':').next().unwrap();
        let mcp_port = cfg.mcp_public_bind.rsplit(':').next().unwrap();
        assert_ne!(web_port, mcp_port);
    }

    #[test]
    fn cli_bind_overrides_default() {
        let mut cfg = GatewayConfig::default();
        cfg.apply_cli(["--bind".into(), "127.0.0.1:8443".into()]);
        assert_eq!(cfg.bind, "127.0.0.1:8443");
    }

    #[test]
    fn file_bind_key_is_applied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gw.toml");
        std::fs::write(&path, "bind = \"127.0.0.1:9443\"\n").unwrap();
        let mut cfg = GatewayConfig::default();
        cfg.merge_file(&path).unwrap();
        assert_eq!(cfg.bind, "127.0.0.1:9443");
    }
}
