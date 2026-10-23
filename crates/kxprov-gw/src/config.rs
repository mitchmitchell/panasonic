use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Default site LAN address (§5a); override in config. Loopback is always included.
pub const DEFAULT_LAN_IP: &str = "192.168.50.1";

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// When set (CLI `--bind` or config `bind`), replaces the §5a LAN+loopback bind list.
    pub bind: Option<String>,
    pub lan_ip: IpAddr,
    pub web_https_port: u16,
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
            bind: None,
            lan_ip: DEFAULT_LAN_IP.parse().expect("default lan ip"),
            web_https_port: 443,
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
    /// HTTPS listen addresses: site LAN plus loopback (§5a), unless `bind` overrides.
    pub fn web_lan_bind_addresses(&self) -> Vec<String> {
        if let Some(ref single) = self.bind {
            return vec![single.clone()];
        }
        let port = self.web_https_port;
        let loopback = format!("127.0.0.1:{port}");
        let lan = format!("{}:{port}", self.lan_ip);
        if self.lan_ip.is_loopback() {
            vec![loopback]
        } else {
            vec![loopback, lan]
        }
    }

    pub fn from_env_and_args() -> anyhow::Result<Self> {
        let mut config = Self::default();
        if let Ok(path) = std::env::var("KXPROV_CONFIG") {
            config
                .merge_file(Path::new(&path))
                .map_err(|e| anyhow::anyhow!("failed to load KXPROV_CONFIG from {}: {e}", path))?;
        }
        if let Ok(bind) = std::env::var("KXPROV_BIND") {
            config.bind = Some(bind);
        }
        if let Ok(lan) = std::env::var("KXPROV_LAN_IP") {
            config.lan_ip = lan
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid KXPROV_LAN_IP: {lan}"))?;
        }
        if let Ok(path) = std::env::var("KXPROV_MCP_TOKENS") {
            config.mcp_tokens_path = path.into();
        }
        config.apply_cli(std::env::args().skip(1))?;
        Ok(config)
    }

    fn merge_file(&mut self, path: &Path) -> anyhow::Result<()> {
        let text = std::fs::read_to_string(path)?;
        let file: FileConfig = toml::from_str(&text)?;
        if let Some(bind) = file.bind {
            self.bind = Some(bind);
        }
        if let Some(v) = file.lan_ip {
            self.lan_ip = v
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid lan_ip in config"))?;
        }
        if let Some(v) = file.web_https_port {
            self.web_https_port = v;
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

    fn apply_cli(&mut self, args: impl IntoIterator<Item = String>) -> anyhow::Result<()> {
        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--bind" => {
                    if let Some(v) = iter.next() {
                        self.bind = Some(v);
                    }
                }
                "--config" => {
                    if let Some(path) = iter.next() {
                        self.merge_file(Path::new(&path))?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    bind: Option<String>,
    lan_ip: Option<String>,
    web_https_port: Option<u16>,
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
    fn default_web_lan_is_loopback_plus_site_lan_not_wildcard() {
        let cfg = GatewayConfig::default();
        let addrs = cfg.web_lan_bind_addresses();
        assert!(!addrs.iter().any(|a| a.starts_with("0.0.0.0:")));
        assert!(addrs.iter().any(|a| a.starts_with("127.0.0.1:")));
        assert!(addrs.iter().any(|a| a.starts_with("192.168.50.1:")));
        assert_eq!(cfg.mcp_public_bind, "127.0.0.1:8444");
    }

    #[test]
    fn cli_bind_overrides_lan_list() {
        let mut cfg = GatewayConfig::default();
        cfg.apply_cli(["--bind".into(), "127.0.0.1:8443".into()])
            .unwrap();
        assert_eq!(
            cfg.web_lan_bind_addresses(),
            vec!["127.0.0.1:8443".to_string()]
        );
    }

    #[test]
    fn file_bind_key_is_applied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gw.toml");
        std::fs::write(&path, "bind = \"127.0.0.1:9443\"\n").unwrap();
        let mut cfg = GatewayConfig::default();
        cfg.merge_file(&path).unwrap();
        assert_eq!(
            cfg.web_lan_bind_addresses(),
            vec!["127.0.0.1:9443".to_string()]
        );
    }
}
