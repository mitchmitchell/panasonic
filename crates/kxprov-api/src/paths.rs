//! Production filesystem layout (daemon, gateway, CLI, sim-mark).

/// Unix socket for admin and gateway API clients.
pub const DAEMON_SOCKET: &str = "/run/kx-provision/kxprovd.sock";

/// Persistent daemon state (plans, backups, tokens, sim-mark, …).
pub const DATA_DIR: &str = "/var/lib/kx-provision";

/// Daemon bearer token store (root-owned, mode 0600).
pub const TOKENS_JSON: &str = "/var/lib/kx-provision/tokens.json";

/// Goliath copy target directory under [`DATA_DIR`].
pub const GOLIATH_DIR: &str = "/var/lib/kx-provision/goliath";

/// Production daemon JSON config (systemd / package layout).
pub const DAEMON_ETC_CONFIG: &str = "/etc/kx-provision/kxprovd.json";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_paths_sit_under_data_dir() {
        assert!(TOKENS_JSON.starts_with(DATA_DIR));
        assert!(GOLIATH_DIR.starts_with(DATA_DIR));
        assert!(TOKENS_JSON.ends_with("tokens.json"));
        assert!(GOLIATH_DIR.ends_with("goliath"));
    }
}
