//! Production filesystem layout (daemon, gateway, CLI, sim-mark).
//!
//! Layout (v2.12): repository root [`DATA_DIR`]; per-profile trees under
//! `{DATA_DIR}/<profile>/`; profile epoch counters under [`EPOCH_DIR_NAME`]; [`SIM_PASSED_JSON`] at the root.

use std::path::{Path, PathBuf};

use crate::Profile;

/// Unix socket for admin and gateway API clients.
pub const DAEMON_SOCKET: &str = "/run/kx-provision/kxprovd.sock";

/// Repository root for daemon state (not per-profile payload dirs).
pub const DATA_DIR: &str = "/var/lib/kx-provision";

/// Daemon bearer token store (root-owned, mode 0600).
pub const TOKENS_JSON: &str = "/var/lib/kx-provision/tokens.json";

/// Subdirectory under [`DATA_DIR`] for monotonic profile epoch counters (P4-R10).
pub const EPOCH_DIR_NAME: &str = ".epoch";

/// Production Sim profile epoch counter (`{DATA_DIR}/.epoch/sim.counter`).
pub const MODE_COUNTER: &str = "/var/lib/kx-provision/.epoch/sim.counter";

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

/// Profile-scoped data directory (plans, backups, mode.json, …): `{base}/<profile>/`.
pub fn resolve_profile_data_dir(base: &Path, profile: Profile) -> PathBuf {
    base.join(profile_dir_name(profile))
}

/// Path to [`SIM_PASSED_JSON`] (or `{base}/sim-passed.json` in isolated test trees).
pub fn sim_passed_path(base: &Path) -> PathBuf {
    if production_layout(base) {
        PathBuf::from(SIM_PASSED_JSON)
    } else {
        base.join("sim-passed.json")
    }
}

/// Per-profile epoch counter: `{base}/.epoch/<profile>.counter`.
pub fn profile_epoch_counter_path(base: &Path, profile: Profile) -> PathBuf {
    base.join(EPOCH_DIR_NAME)
        .join(format!("{}.counter", profile_dir_name(profile)))
}

/// Alias for [`profile_epoch_counter_path`] (daemon mode / v2.12 tests).
pub fn mode_counter_path(base: &Path, profile: Profile) -> PathBuf {
    profile_epoch_counter_path(base, profile)
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

    #[test]
    fn custom_data_dir_gives_distinct_profile_trees_and_epoch_counters() {
        let base = Path::new("/opt/kx-data");
        assert_eq!(
            resolve_profile_data_dir(base, Profile::Sim),
            PathBuf::from("/opt/kx-data/sim")
        );
        assert_eq!(
            resolve_profile_data_dir(base, Profile::Test),
            PathBuf::from("/opt/kx-data/test")
        );
        assert_eq!(
            resolve_profile_data_dir(base, Profile::Prod),
            PathBuf::from("/opt/kx-data/prod")
        );
        assert_ne!(
            resolve_profile_data_dir(base, Profile::Sim),
            resolve_profile_data_dir(base, Profile::Prod)
        );
        assert_eq!(
            profile_epoch_counter_path(base, Profile::Sim),
            PathBuf::from("/opt/kx-data/.epoch/sim.counter")
        );
        assert_eq!(
            profile_epoch_counter_path(base, Profile::Prod),
            PathBuf::from("/opt/kx-data/.epoch/prod.counter")
        );
    }
}
