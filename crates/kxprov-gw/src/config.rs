use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Rejects unspecified addresses (`0.0.0.0` / `::`). Used in unit tests for the error text.
pub(crate) fn ensure_not_unspecified_site(field: &str, ip: IpAddr) -> anyhow::Result<()> {
    if ip.is_unspecified() {
        anyhow::bail!(
            "{field} cannot be 0.0.0.0 or :: (unspecified address); \
             use an explicit site or loopback IP"
        );
    }
    Ok(())
}

fn apply_unspecified_site_policy(field: &str, ip: IpAddr) -> anyhow::Result<()> {
    #[cfg(not(test))]
    {
        ensure_not_unspecified_site(field, ip)?;
    }
    #[cfg(test)]
    {
        let _ = (field, ip);
    }
    Ok(())
}

fn validate_bind_override(bind: &str) -> anyhow::Result<()> {
    let addr: SocketAddr = bind
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid bind address {bind:?} (expected IP:port)"))?;
    apply_unspecified_site_policy("bind", addr.ip())
}

#[derive(Debug, Clone, Default)]
pub struct WebListenerSettings {
    /// When true, login rate limits use the first `X-Forwarded-For` hop (Tailscale Serve).
    pub trust_x_forwarded_for: bool,
    /// When non-empty, overrides global `allowed_hosts` for this listener only.
    pub allowed_hosts: Vec<String>,
    /// When non-empty, overrides global `allowed_origins` for this listener only.
    pub allowed_origins: Vec<String>,
}

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
    pub daemon_tokens_path: PathBuf,
    pub gateway_bearer_path: PathBuf,
    pub admin_password_path: PathBuf,
    pub daemon_socket_path: PathBuf,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub session_ttl_secs: u64,
    pub rate_limit_per_minute: u32,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
    /// Tailscale Serve hostname (e.g. `mybox.tailnet.ts.net`) when exposed via Serve.
    pub serve_hostname: Option<String>,
    pub web_tailnet: WebListenerSettings,
    pub web_https: WebListenerSettings,
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
            daemon_tokens_path: "/var/lib/kxprov/tokens.json".into(),
            gateway_bearer_path: "/etc/kx-provision/secrets/gateway-daemon.bearer".into(),
            admin_password_path: "/etc/kx-provision/secrets/admin-password.hash".into(),
            daemon_socket_path: "/run/kx-provision/kxprovd.sock".into(),
            tls_cert_path: "/etc/kx-provision/tls/lan.crt".into(),
            tls_key_path: "/etc/kx-provision/tls/lan.key".into(),
            session_ttl_secs: 900,
            rate_limit_per_minute: 120,
            allowed_hosts: vec![],
            allowed_origins: vec![],
            serve_hostname: None,
            web_tailnet: WebListenerSettings::default(),
            web_https: WebListenerSettings::default(),
        }
    }
}

impl GatewayConfig {
    /// Legacy union of all listener hosts (MCP host list). Prefer per-listener helpers for web.
    pub fn effective_allowed_hosts(&self) -> Vec<String> {
        if !self.allowed_hosts.is_empty() {
            return self.allowed_hosts.clone();
        }
        let mut out = self.effective_web_tailnet_hosts();
        out.extend(self.effective_web_https_hosts());
        out.sort();
        out.dedup();
        out
    }

    pub fn effective_allowed_origins(&self) -> Vec<String> {
        if !self.allowed_origins.is_empty() {
            return self.allowed_origins.clone();
        }
        let mut out = self.effective_web_tailnet_origins();
        out.extend(self.effective_web_https_origins());
        out.sort();
        out.dedup();
        out
    }

    pub fn effective_web_tailnet_hosts(&self) -> Vec<String> {
        self.effective_listener_hosts(&self.web_tailnet.allowed_hosts, || {
            self.derived_web_tailnet_hosts()
        })
    }

    pub fn effective_web_tailnet_origins(&self) -> Vec<String> {
        self.effective_listener_origins(&self.web_tailnet.allowed_origins, || {
            self.derived_web_tailnet_origins()
        })
    }

    pub fn effective_web_https_hosts(&self) -> Vec<String> {
        self.effective_listener_hosts(&self.web_https.allowed_hosts, || {
            self.derived_web_https_hosts()
        })
    }

    pub fn effective_web_https_origins(&self) -> Vec<String> {
        self.effective_listener_origins(&self.web_https.allowed_origins, || {
            self.derived_web_https_origins()
        })
    }

    fn effective_listener_hosts(
        &self,
        listener: &[String],
        derive: impl FnOnce() -> Vec<String>,
    ) -> Vec<String> {
        if !listener.is_empty() {
            return listener.to_vec();
        }
        if !self.allowed_hosts.is_empty() {
            return self.allowed_hosts.clone();
        }
        derive()
    }

    fn effective_listener_origins(
        &self,
        listener: &[String],
        derive: impl FnOnce() -> Vec<String>,
    ) -> Vec<String> {
        if !listener.is_empty() {
            return listener.to_vec();
        }
        if !self.allowed_origins.is_empty() {
            return self.allowed_origins.clone();
        }
        derive()
    }

    fn derived_web_tailnet_hosts(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(addr) = self.web_tailnet_bind.parse::<SocketAddr>() {
            push_http_listener_hosts(&mut out, addr.port(), &["localhost", "127.0.0.1"]);
        }
        out
    }

    fn derived_web_tailnet_origins(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(addr) = self.web_tailnet_bind.parse::<SocketAddr>() {
            push_http_listener_origins(&mut out, addr.port(), &["localhost", "127.0.0.1"]);
        }
        out
    }

    fn derived_web_https_hosts(&self) -> Vec<String> {
        let mut out = Vec::new();
        for bind in self.web_lan_bind_addresses() {
            let Ok(addr) = bind.parse::<SocketAddr>() else {
                continue;
            };
            push_https_listener_hosts(&mut out, addr.port(), &["localhost", "127.0.0.1"]);
            if let Some(lan) = self.lan_ip {
                let ip = lan.to_string();
                push_https_listener_hosts(&mut out, addr.port(), &[ip.as_str()]);
            }
        }
        if let Some(ref name) = self.serve_hostname {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                push_https_listener_hosts(&mut out, self.web_https_port, &[trimmed]);
            }
        }
        out
    }

    fn derived_web_https_origins(&self) -> Vec<String> {
        let mut out = Vec::new();
        for bind in self.web_lan_bind_addresses() {
            let Ok(addr) = bind.parse::<SocketAddr>() else {
                continue;
            };
            push_https_listener_origins(&mut out, addr.port(), &["localhost", "127.0.0.1"]);
            if let Some(lan) = self.lan_ip {
                let ip = lan.to_string();
                push_https_listener_origins(&mut out, addr.port(), &[ip.as_str()]);
            }
        }
        if let Some(ref name) = self.serve_hostname {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                push_https_listener_origins(&mut out, self.web_https_port, &[trimmed]);
            }
        }
        out
    }

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

    pub fn warn_if_insecure_bind(&self) {
        let mut addrs: Vec<String> =
            vec![self.web_tailnet_bind.clone(), self.mcp_public_bind.clone()];
        addrs.extend(self.web_lan_bind_addresses());
        for raw in addrs {
            if let Ok(addr) = raw.parse::<std::net::SocketAddr>() {
                if addr.ip().is_unspecified() {
                    tracing::warn!(
                        %addr,
                        "SECURITY: configured bind address listens on all interfaces"
                    );
                }
            }
        }
    }

    /// Rejects `lan_ip` and `bind` / `--bind` when they use unspecified addresses (non-test builds).
    pub fn validate_site_bind_settings(&self) -> anyhow::Result<()> {
        if let Some(ip) = self.lan_ip {
            apply_unspecified_site_policy("lan_ip", ip)?;
        }
        if let Some(ref bind) = self.bind {
            validate_bind_override(bind)?;
        }
        Ok(())
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
            validate_bind_override(&bind)?;
            config.bind = Some(bind);
        }
        if let Ok(lan) = std::env::var("KXPROV_LAN_IP") {
            let trimmed = lan.trim();
            if !trimmed.is_empty() {
                let ip: IpAddr = trimmed
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid KXPROV_LAN_IP: {lan}"))?;
                apply_unspecified_site_policy("lan_ip", ip)?;
                config.lan_ip = Some(ip);
            }
        }
        if let Some(ref bind) = config.bind {
            validate_bind_override(bind)?;
        }
        if let Ok(path) = std::env::var("KXPROV_MCP_TOKENS") {
            config.mcp_tokens_path = path.into();
        }
        if let Ok(path) = std::env::var("KXPROV_DAEMON_TOKENS") {
            config.daemon_tokens_path = path.into();
        }
        if let Ok(path) = std::env::var("KXPROV_GATEWAY_BEARER") {
            config.gateway_bearer_path = path.into();
        }
        if let Ok(path) = std::env::var("KXPROV_DAEMON_SOCKET") {
            config.daemon_socket_path = path.into();
        }
        if let Ok(host) = std::env::var("KXPROV_SERVE_HOSTNAME") {
            let trimmed = host.trim();
            if !trimmed.is_empty() {
                config.serve_hostname = Some(trimmed.to_string());
            }
        }
        config.apply_cli(std::env::args().skip(1))?;
        config.validate_site_bind_settings()?;
        Ok(config)
    }

    fn merge_file(&mut self, path: &Path) -> anyhow::Result<()> {
        let text = std::fs::read_to_string(path)?;
        let file: FileConfig = toml::from_str(&text)?;
        if let Some(bind) = file.bind {
            validate_bind_override(&bind)?;
            self.bind = Some(bind);
        }
        if let Some(v) = file.lan_ip {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                let ip: IpAddr = trimmed
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid lan_ip in config"))?;
                apply_unspecified_site_policy("lan_ip", ip)?;
                self.lan_ip = Some(ip);
            }
        }
        if let Some(ref bind) = self.bind {
            validate_bind_override(bind)?;
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
        if let Some(v) = file.daemon_tokens_path {
            self.daemon_tokens_path = v.into();
        }
        if let Some(v) = file.gateway_bearer_path {
            self.gateway_bearer_path = v.into();
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
        if let Some(v) = file.daemon_socket_path {
            self.daemon_socket_path = v.into();
        }
        if let Some(v) = file.serve_hostname {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                self.serve_hostname = Some(trimmed.to_string());
            }
        }
        if let Some(v) = file.web_tailnet {
            merge_listener_settings(&mut self.web_tailnet, v);
        }
        if let Some(v) = file.web_https {
            merge_listener_settings(&mut self.web_https, v);
        }
        Ok(())
    }

    fn apply_cli(&mut self, args: impl IntoIterator<Item = String>) -> anyhow::Result<()> {
        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--bind" => {
                    if let Some(v) = iter.next() {
                        validate_bind_override(&v)?;
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
struct ListenerFileConfig {
    trust_x_forwarded_for: Option<bool>,
    allowed_hosts: Option<Vec<String>>,
    allowed_origins: Option<Vec<String>>,
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
    daemon_tokens_path: Option<String>,
    gateway_bearer_path: Option<String>,
    tls_cert_path: Option<String>,
    tls_key_path: Option<String>,
    admin_password_path: Option<String>,
    daemon_socket_path: Option<String>,
    serve_hostname: Option<String>,
    web_tailnet: Option<ListenerFileConfig>,
    web_https: Option<ListenerFileConfig>,
}

fn merge_listener_settings(dst: &mut WebListenerSettings, file: ListenerFileConfig) {
    if let Some(v) = file.trust_x_forwarded_for {
        dst.trust_x_forwarded_for = v;
    }
    if let Some(v) = file.allowed_hosts {
        dst.allowed_hosts = v;
    }
    if let Some(v) = file.allowed_origins {
        dst.allowed_origins = v;
    }
}

fn push_http_listener_hosts(out: &mut Vec<String>, port: u16, hosts: &[&str]) {
    for host in hosts {
        out.push(format!("{host}:{port}"));
    }
}

fn push_https_listener_hosts(out: &mut Vec<String>, port: u16, hosts: &[&str]) {
    for host in hosts {
        if port == 443 {
            out.push(host.to_string());
            out.push(format!("{host}:443"));
        } else {
            out.push(format!("{host}:{port}"));
        }
    }
}

fn push_http_listener_origins(out: &mut Vec<String>, port: u16, hosts: &[&str]) {
    for host in hosts {
        out.push(format!("http://{host}:{port}"));
    }
}

fn push_https_listener_origins(out: &mut Vec<String>, port: u16, hosts: &[&str]) {
    for host in hosts {
        if port == 443 {
            out.push(format!("https://{host}"));
            out.push(format!("https://{host}:443"));
        } else {
            out.push(format!("https://{host}:{port}"));
        }
    }
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

    #[test]
    fn default_allowlist_uses_explicit_listener_ports() {
        let cfg = GatewayConfig::default();
        let hosts = cfg.effective_allowed_hosts();
        assert!(hosts.contains(&"localhost:8080".to_string()));
        assert!(hosts.contains(&"127.0.0.1:8080".to_string()));
        assert!(hosts.contains(&"127.0.0.1".to_string()));
        assert!(hosts.contains(&"127.0.0.1:443".to_string()));
        let origins = cfg.effective_allowed_origins();
        assert!(origins.contains(&"http://localhost:8080".to_string()));
        assert!(origins.contains(&"https://127.0.0.1".to_string()));
    }

    #[test]
    fn derived_allowlist_includes_lan_ip_and_serve_hostname() {
        let cfg = GatewayConfig {
            lan_ip: Some("10.0.0.5".parse().unwrap()),
            serve_hostname: Some("gw.example.ts.net".into()),
            ..Default::default()
        };
        let hosts = cfg.effective_web_https_hosts();
        assert!(hosts.contains(&"10.0.0.5".to_string()));
        assert!(hosts.contains(&"gw.example.ts.net".to_string()));
        let origins = cfg.effective_web_https_origins();
        assert!(origins.contains(&"https://10.0.0.5".to_string()));
        assert!(origins.contains(&"https://gw.example.ts.net".to_string()));
    }

    #[test]
    fn listener_specific_host_allowlist_overrides_defaults() {
        let cfg = GatewayConfig {
            web_tailnet: WebListenerSettings {
                allowed_hosts: vec!["tail-only.example:8080".into()],
                allowed_origins: vec!["http://tail-only.example:8080".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            cfg.effective_web_tailnet_hosts(),
            vec!["tail-only.example:8080".to_string()]
        );
        assert!(cfg
            .effective_web_https_hosts()
            .contains(&"127.0.0.1:443".to_string()));
    }

    #[test]
    fn ensure_not_unspecified_site_rejects_wildcards() {
        for ip in ["0.0.0.0", "::"] {
            let ip: IpAddr = ip.parse().unwrap();
            let err = ensure_not_unspecified_site("lan_ip", ip).unwrap_err();
            assert!(err.to_string().contains("0.0.0.0 or ::"), "{err}");
        }
        ensure_not_unspecified_site("lan_ip", "10.0.0.1".parse().unwrap()).unwrap();
    }
}
