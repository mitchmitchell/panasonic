//! Production filesystem layout (daemon, gateway, CLI, sim-mark).
//!
//! Layout (v2.12): repository root [`DATA_DIR`]; per-profile trees under
//! `{DATA_DIR}/<profile>/`; [`MODE_COUNTER`] and [`SIM_PASSED_JSON`] at the root only.

use std::path::{Path, PathBuf};

use crate::Profile;

/// Unix socket for admin and gateway API clients.
pub const DAEMON_SOCKET: &str = "/run/kx-provision/kxprovd.sock";

/// Repository root for daemon state (not per-profile payload dirs).
pub const DATA_DIR: &str = "/var/lib/kx-provision";

/// Daemon bearer token store (root-owned, mode 0600).
pub const TOKENS_JSON: &str = "/var/lib/kx-provision/tokens.json";

/// Monotonic mode-set counter (global, not per-profile).
pub const MODE_COUNTER: &str = "/var/lib/kx-provision/mode.counter";

/// Simulator pass marker for the current build (global, root-owned in production).
pub const SIM_PASSED_JSON: &str = "/var/lib/kx-provision/sim-passed.json";

/// Production daemon JSON config (systemd / package layout).
pub const DAEMON_ETC_CONFIG: &str = "/etc/kx-provision/kxprovd.json";

/// Directory name segment for a profile under [`DATA_DIR`].
pub fn profile_dir_name(profile: Profile) -> &'static str {
    match profile {
        Profile::Sim => "sim",
        Profile::Test => "test",
        Profile::Prod => "prod",
    }
}

/// Per-profile data root: `/var/lib/kx-provision/<profile>/`.
pub fn profile_data_dir(profile: Profile) -> String {
    format!("{}/{}", DATA_DIR, profile_dir_name(profile))
}

/// Goliath copy target for a profile.
pub fn goliath_dir(profile: Profile) -> String {
    format!("{}/goliath", profile_data_dir(profile))
}

/// Whether `base` uses the production v2.12 layout (profile subdirs under [`DATA_DIR`]).
pub fn production_layout(base: &Path) -> bool {
    base == Path::new(DATA_DIR)
}

/// Profile-scoped data directory (plans, backups, mode.json, …).
pub fn resolve_profile_data_dir(base: &Path, profile: Profile) -> PathBuf {
    if production_layout(base) {
        PathBuf::from(profile_data_dir(profile))
    } else {
        base.to_path_buf()
    }
}

/// Path to [`SIM_PASSED_JSON`] (or `{base}/sim-passed.json` in isolated test trees).
pub fn sim_passed_path(base: &Path) -> PathBuf {
    if production_layout(base) {
        PathBuf::from(SIM_PASSED_JSON)
    } else {
        base.join("sim-passed.json")
    }
}

/// Path to [`MODE_COUNTER`] (or `{base}/mode.counter` in isolated test trees).
pub fn mode_counter_path(base: &Path) -> PathBuf {
    if production_layout(base) {
        PathBuf::from(MODE_COUNTER)
    } else {
        base.join("mode.counter")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_markers_sit_under_data_dir() {
        assert!(TOKENS_JSON.starts_with(DATA_DIR));
        assert!(MODE_COUNTER.starts_with(DATA_DIR));
        assert!(SIM_PASSED_JSON.starts_with(DATA_DIR));
        assert!(profile_data_dir(Profile::Sim).starts_with(DATA_DIR));
    }

    #[test]
    fn profile_dirs_are_siblings_under_root() {
        assert_eq!(profile_data_dir(Profile::Sim), "/var/lib/kx-provision/sim");
        assert_eq!(
            profile_data_dir(Profile::Test),
            "/var/lib/kx-provision/test"
        );
        assert_eq!(
            profile_data_dir(Profile::Prod),
            "/var/lib/kx-provision/prod"
        );
    }
}
