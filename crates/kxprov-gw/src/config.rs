use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// When set (CLI `--bind` or config `bind`), replaces the §5a LAN+loopback bind list.
    pub bind: Option<String>,
    /// Site LAN address from config `lan_ip` or `KXPROV_LAN_IP`. When unset, HTTPS listens on loopback only.
    pub lan_ip: Option<IpAddr>,
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
            lan_ip: None,
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
    /// HTTPS listen addresses (§5a): loopback always; site LAN only when `lan_ip` is configured.
    pub fn web_lan_bind_addresses(&self) -> Vec<String> {
        if let Some(ref single) = self.bind {
            return vec![single.clone()];
        }
        let port = self.web_https_port;
        let loopback = format!("127.0.0.1:{port}");
        match self.lan_ip {
            None => vec![loopback],
            Some(ip) if ip.is_loopback() => vec![loopback],
            Some(ip) => vec![loopback, format!("{ip}:{port}")],
        }
    }

    pub fn warn_if_lan_ip_unset(&self) {
        if self.bind.is_some() || self.lan_ip.is_some() {
            return;
        }
        tracing::warn!(
            "lan_ip is not set (use config lan_ip or KXPROV_LAN_IP); \
             web HTTPS will listen on loopback ({}) only",
            self.web_lan_bind_addresses()
                .first()
                .map(String::as_str)
                .unwrap_or("127.0.0.1:443")
        );
    }

    pub fn from_env_and_args() -> anyhow::Result<Self> {
        let mut config = Self::default();
        if let Ok(path) = std::env::var("KXPROV_CONFIG") {
            config
                .merge_file(Path::new(&path))
                .map_err(|e| anyhow::anyhow!("failed to load KXPROV_CONFIG from {path}: {e}"))?;
        }
        if let Ok(bind) = std::env::var("KXPROV_BIND") {
            config.bind = Some(bind);
        }
        if let Ok(lan) = std::env::var("KXPROV_LAN_IP") {
            let trimmed = lan.trim();
            if !trimmed.is_empty() {
                config.lan_ip = Some(
                    trimmed
                        .parse()
                        .map_err(|_| anyhow::anyhow!("invalid KXPROV_LAN_IP: {lan}"))?,
                );
            }
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
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                self.lan_ip = Some(
                    trimmed
                        .parse()
                        .map_err(|_| anyhow::anyhow!("invalid lan_ip in config"))?,
                );
            }
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
    fn without_lan_ip_https_is_loopback_only_not_wildcard() {
        let cfg = GatewayConfig::default();
        let addrs = cfg.web_lan_bind_addresses();
        assert_eq!(addrs, vec!["127.0.0.1:443".to_string()]);
        assert!(!addrs.iter().any(|a| a.starts_with("0.0.0.0:")));
    }

    #[test]
    fn configured_lan_ip_adds_loopback_and_site_address() {
        let cfg = GatewayConfig {
            lan_ip: Some("10.20.30.40".parse().unwrap()),
            ..Default::default()
        };
        let addrs = cfg.web_lan_bind_addresses();
        assert_eq!(
            addrs,
            vec!["127.0.0.1:443".to_string(), "10.20.30.40:443".to_string()]
        );
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
    fn file_lan_ip_is_applied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gw.toml");
        std::fs::write(&path, "lan_ip = \"10.0.0.5\"\n").unwrap();
        let mut cfg = GatewayConfig::default();
        cfg.merge_file(&path).unwrap();
        assert_eq!(cfg.lan_ip, Some("10.0.0.5".parse().unwrap()));
        assert!(cfg
            .web_lan_bind_addresses()
            .contains(&"10.0.0.5:443".to_string()));
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
