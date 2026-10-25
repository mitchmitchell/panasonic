//! Operational mode + runtime profile (v2.7 F1, unsigned, fail-closed Production).

use crate::audit::{alert_mode_failure, AuditEntry, AuditKind, AuditLog};
use crate::epoch_store;
use crate::time::now_ms;
use kxprov_api::{OperationalMode, Profile};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("epoch storage: {0}")]
    Epoch(#[from] epoch_store::EpochError),
    #[error("counter rollback")]
    CounterRollback,
    #[error("mode.counter corrupt or unreadable")]
    CounterCorrupt,
    #[error("testing mode requires Test profile")]
    TestingProfile,
    #[error("daemon not idle")]
    NotIdle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeFileBody {
    pub mode: OperationalMode,
    /// Monotonic revision; must match per-profile `mode.counter` and `profile.json` (v2.12 rollback guard).
    #[serde(default)]
    pub counter: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileFileBody {
    pub profile: Profile,
    #[serde(default)]
    pub counter: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveMode {
    pub operational: OperationalMode,
}

pub struct ModeStore {
    mode_path: PathBuf,
    profile_path: PathBuf,
    provision_root: PathBuf,
    audit: AuditLog,
    boot_profile: Profile,
}

impl ModeStore {
    pub fn new(data_dir: &Path, boot_profile: Profile) -> Self {
        Self::new_with_epoch_root(data_dir, data_dir, boot_profile)
    }

    pub fn new_with_epoch_root(
        data_dir: &Path,
        provision_root: &Path,
        boot_profile: Profile,
    ) -> Self {
        Self {
            mode_path: data_dir.join("mode.json"),
            profile_path: data_dir.join("profile.json"),
            provision_root: provision_root.to_path_buf(),
            audit: AuditLog::new(data_dir),
            boot_profile,
        }
    }

    pub fn read_stored_mode(&self) -> Option<OperationalMode> {
        let raw = std::fs::read_to_string(&self.mode_path).ok()?;
        serde_json::from_str::<ModeFileBody>(&raw)
            .ok()
            .map(|b| b.mode)
    }

    pub fn load_profile(&self) -> Profile {
        if self.highest_counter_missing_fail_closed() {
            return Profile::Prod;
        }
        let stored = match std::fs::read_to_string(&self.profile_path) {
            Ok(raw) => match serde_json::from_str::<ProfileFileBody>(&raw) {
                Ok(body) => Some(body),
                Err(e) => {
                    self.fail_closed(AuditKind::ModeCorrupt, format!("profile.json: {e}"));
                    return Profile::Prod;
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                self.fail_closed(AuditKind::ModeCorrupt, e.to_string());
                return Profile::Prod;
            }
        };

        let epoch_profile = stored
            .as_ref()
            .map(|b| b.profile)
            .unwrap_or(self.boot_profile);
        let last = match self.last_counter(epoch_profile) {
            Ok(n) => n,
            Err(e) => {
                self.fail_closed(AuditKind::ModeCorrupt, format!("mode.counter: {e}"));
                return Profile::Prod;
            }
        };

        match stored {
            None => {
                if last > 0 {
                    self.fail_closed(
                        AuditKind::ModeCorrupt,
                        "profile.json missing after mode.counter epoch started",
                    );
                    Profile::Prod
                } else {
                    self.boot_profile
                }
            }
            Some(body) if body.counter < last => {
                self.fail_closed_profile_rollback(body.counter, last);
                Profile::Prod
            }
            Some(body) if self.epoch_snapshot_stale_or_corrupt(body.counter, "profile.json") => {
                Profile::Prod
            }
            Some(body) => {
                if self.boot_profile == Profile::Prod && body.profile != Profile::Prod {
                    self.fail_closed(
                        AuditKind::ModeCorrupt,
                        format!(
                            "profile.json {:?} disagrees with prod data directory",
                            body.profile
                        ),
                    );
                    Profile::Prod
                } else {
                    body.profile
                }
            }
        }
    }

    fn fail_closed_profile_rollback(&self, file_counter: u64, last: u64) {
        self.fail_closed(
            AuditKind::ModeCounterRollback,
            format!("profile.json counter {file_counter} < epoch {last}"),
        );
    }

    fn file_counter(path: &Path) -> Option<u64> {
        let raw = std::fs::read_to_string(path).ok()?;
        let body = serde_json::from_str::<ModeFileBody>(&raw).ok()?;
        Some(body.counter)
    }

    fn effective_highest_epoch(&self) -> Result<u64, ModeError> {
        let profiles = match self.boot_profile {
            Profile::Prod => [Profile::Prod].as_slice(),
            Profile::Sim | Profile::Test => &[Profile::Sim, Profile::Test][..],
        };
        epoch_store::effective_highest_for_profiles(&self.provision_root, profiles)
            .map_err(ModeError::from)
    }

    /// Fail closed when profile counters exist but `highest.counter` was removed (post-bump tamper).
    fn highest_counter_missing_fail_closed(&self) -> bool {
        let path = crate::config::highest_epoch_counter_path(&self.provision_root);
        if path.exists() {
            return false;
        }
        let profiles = match self.boot_profile {
            Profile::Prod => [Profile::Prod].as_slice(),
            Profile::Sim | Profile::Test => &[Profile::Sim, Profile::Test][..],
        };
        for &profile in profiles {
            match epoch_store::read_counter(&self.provision_root, profile) {
                Ok(Some(_)) => {
                    self.fail_closed(
                        AuditKind::ModeCorrupt,
                        "highest.counter missing while per-profile epoch counters exist",
                    );
                    return true;
                }
                Ok(None) => {}
                Err(e) => {
                    self.fail_closed(AuditKind::ModeCorrupt, format!("epoch highest: {e}"));
                    return true;
                }
            }
        }
        false
    }

    /// Returns true when the caller should treat stored mode/profile as rejected (Prod).
    fn epoch_snapshot_stale_or_corrupt(&self, counter: u64, label: &str) -> bool {
        match self.effective_highest_epoch() {
            Err(e) => {
                self.fail_closed(
                    AuditKind::ModeCorrupt,
                    format!("{label} epoch highest: {e}"),
                );
                true
            }
            Ok(highest) if highest > 0 && counter < highest => {
                self.fail_closed(
                    AuditKind::ModeCounterRollback,
                    format!(
                        "{label} counter {counter} below highest epoch ever written ({highest})"
                    ),
                );
                true
            }
            Ok(_) => false,
        }
    }

    fn stored_epoch_claim_for_profile(&self, profile: Profile) -> Result<u64, ModeError> {
        let mode_c = Self::file_counter(&self.mode_path).unwrap_or(0);
        match std::fs::read_to_string(&self.profile_path) {
            Ok(raw) => match serde_json::from_str::<ProfileFileBody>(&raw) {
                Ok(body) if body.profile == profile => Ok(body.counter.max(mode_c)),
                Ok(_) => Ok(0),
                Err(_) if mode_c > 0 => Err(ModeError::CounterCorrupt),
                Err(_) => Ok(0),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if profile == self.boot_profile {
                    Ok(mode_c)
                } else {
                    Ok(0)
                }
            }
            Err(_) if mode_c > 0 => Err(ModeError::CounterCorrupt),
            Err(_) => Ok(0),
        }
    }

    fn last_counter(&self, profile: Profile) -> Result<u64, ModeError> {
        match epoch_store::read_counter(&self.provision_root, profile)? {
            None => {
                if self.stored_epoch_claim_for_profile(profile)? > 0 {
                    return Err(ModeError::CounterCorrupt);
                }
                Ok(0)
            }
            Some(n) => Ok(n),
        }
    }

    fn save_counter(&self, profile: Profile, counter: u64) -> Result<(), ModeError> {
        epoch_store::write_counter(&self.provision_root, profile, counter)?;
        Ok(())
    }

    fn fail_closed(&self, kind: AuditKind, detail: impl Into<String>) -> EffectiveMode {
        let detail = detail.into();
        alert_mode_failure(&kind, &detail);
        let _ = self.audit.append(&AuditEntry {
            at_ms: now_ms(),
            kind,
            detail,
        });
        EffectiveMode {
            operational: OperationalMode::Production,
        }
    }

    pub fn effective(&self, profile: Profile) -> EffectiveMode {
        if self.highest_counter_missing_fail_closed() {
            return EffectiveMode {
                operational: OperationalMode::Production,
            };
        }
        let raw = match std::fs::read_to_string(&self.mode_path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return self.fail_closed(AuditKind::ModeMissing, "mode.json missing");
            }
            Err(e) => {
                return self.fail_closed(AuditKind::ModeCorrupt, e.to_string());
            }
        };
        let body: ModeFileBody = match serde_json::from_str(&raw) {
            Ok(b) => b,
            Err(e) => {
                return self.fail_closed(AuditKind::ModeCorrupt, e.to_string());
            }
        };
        let last = match self.last_counter(profile) {
            Ok(n) => n,
            Err(e) => {
                return self.fail_closed(AuditKind::ModeCorrupt, format!("mode.counter: {e}"));
            }
        };
        if body.counter < last {
            return self.fail_closed(
                AuditKind::ModeCounterRollback,
                format!("mode.json counter {} < epoch {last}", body.counter),
            );
        }
        if self.epoch_snapshot_stale_or_corrupt(body.counter, "mode.json") {
            return EffectiveMode {
                operational: OperationalMode::Production,
            };
        }
        if let Ok(prof_raw) = std::fs::read_to_string(&self.profile_path) {
            if let Ok(prof_body) = serde_json::from_str::<ProfileFileBody>(&prof_raw) {
                if prof_body.counter < last {
                    return self.fail_closed(
                        AuditKind::ModeCounterRollback,
                        format!("profile.json counter {} < epoch {last}", prof_body.counter),
                    );
                }
                if prof_body.counter != body.counter && last > 0 {
                    return self.fail_closed(
                        AuditKind::ModeCounterRollback,
                        format!(
                            "mode/profile counter mismatch ({} vs {})",
                            body.counter, prof_body.counter
                        ),
                    );
                }
            }
        }
        if body.mode == OperationalMode::Testing && profile != Profile::Test {
            return self.fail_closed(
                AuditKind::ModeTestingInvalidProfile,
                format!("testing mode invalid for profile {profile:?}"),
            );
        }
        EffectiveMode {
            operational: body.mode,
        }
    }

    /// Root admin: set mode/profile while daemon is idle.
    pub fn set_operational(
        &self,
        mode: OperationalMode,
        profile: Profile,
        idle: bool,
    ) -> Result<(EffectiveMode, Profile, u64), ModeError> {
        if !idle {
            return Err(ModeError::NotIdle);
        }
        if mode == OperationalMode::Testing && profile != Profile::Test {
            return Err(ModeError::TestingProfile);
        }
        let last = self.last_counter(profile)?;
        let highest = self.effective_highest_epoch()?;
        let floor = last.max(highest);
        let counter = floor.saturating_add(1);
        if counter <= floor {
            return Err(ModeError::CounterRollback);
        }
        let body = ModeFileBody { mode, counter };
        crate::atomic_write::write(&self.mode_path, &serde_json::to_vec_pretty(&body)?)?;
        crate::atomic_write::write(
            &self.profile_path,
            &serde_json::to_vec_pretty(&ProfileFileBody { profile, counter })?,
        )?;
        self.save_counter(profile, counter)?;
        let _ = self.audit.append(&AuditEntry {
            at_ms: now_ms(),
            kind: AuditKind::ModeSet,
            detail: format!("mode={mode:?} profile={profile:?} counter={counter}"),
        });
        Ok((EffectiveMode { operational: mode }, profile, counter))
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }
}

/// G5: approval gate applies to prod profile writes only (v2.11).
pub fn write_approval_required(profile: Profile, _operational: OperationalMode) -> bool {
    profile == Profile::Prod
}

#[cfg(all(test, feature = "test-util"))]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use kxprov_api::OperationalMode;

    #[test]
    fn restart_keeps_testing_after_set_mode_switches_profile_epoch() {
        let root = tempfile::tempdir().unwrap();
        let sim_dir = root.path().join("sim");
        std::fs::create_dir_all(&sim_dir).unwrap();
        let store = ModeStore::new_with_epoch_root(&sim_dir, root.path(), Profile::Sim);
        store
            .set_operational(OperationalMode::Testing, Profile::Test, true)
            .unwrap();
        let restarted = ModeStore::new_with_epoch_root(&sim_dir, root.path(), Profile::Sim);
        assert_eq!(restarted.load_profile(), Profile::Test);
        assert_eq!(
            restarted.effective(Profile::Test).operational,
            OperationalMode::Testing
        );
    }

    #[test]
    fn fresh_install_switch_sim_test_sim() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("sim");
        std::fs::create_dir_all(&data).unwrap();
        let store = ModeStore::new_with_epoch_root(&data, root.path(), Profile::Sim);
        store
            .set_operational(OperationalMode::Production, Profile::Sim, true)
            .unwrap();
        store
            .set_operational(OperationalMode::Testing, Profile::Test, true)
            .unwrap();
        store
            .set_operational(OperationalMode::Production, Profile::Sim, true)
            .unwrap();
        let restarted = ModeStore::new_with_epoch_root(&data, root.path(), Profile::Sim);
        assert_eq!(restarted.load_profile(), Profile::Sim);
        assert_eq!(
            restarted.effective(Profile::Sim).operational,
            OperationalMode::Production
        );
    }

    #[test]
    fn switch_profiles_with_existing_epoch_counters() {
        use crate::config::profile_epoch_counter_path;
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("sim");
        std::fs::create_dir_all(&data).unwrap();
        epoch_store::write_counter(root.path(), Profile::Sim, 3).unwrap();
        epoch_store::write_counter(root.path(), Profile::Test, 2).unwrap();
        std::fs::write(
            data.join("profile.json"),
            serde_json::to_vec_pretty(&ProfileFileBody {
                profile: Profile::Sim,
                counter: 3,
            })
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            data.join("mode.json"),
            serde_json::to_vec_pretty(&ModeFileBody {
                mode: OperationalMode::Production,
                counter: 3,
            })
            .unwrap(),
        )
        .unwrap();
        let store = ModeStore::new_with_epoch_root(&data, root.path(), Profile::Sim);
        store
            .set_operational(OperationalMode::Testing, Profile::Test, true)
            .unwrap();
        assert!(profile_epoch_counter_path(root.path(), Profile::Test).exists());
        let restarted = ModeStore::new_with_epoch_root(&data, root.path(), Profile::Sim);
        assert_eq!(restarted.load_profile(), Profile::Test);
    }

    #[test]
    fn cross_profile_old_snapshot_rollback_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("sim");
        std::fs::create_dir_all(&data).unwrap();
        let store = ModeStore::new_with_epoch_root(&data, root.path(), Profile::Sim);
        store
            .set_operational(OperationalMode::Testing, Profile::Test, true)
            .unwrap();
        let old_mode = std::fs::read(data.join("mode.json")).unwrap();
        let old_profile = std::fs::read(data.join("profile.json")).unwrap();
        store
            .set_operational(OperationalMode::Production, Profile::Sim, true)
            .unwrap();
        store
            .set_operational(OperationalMode::Production, Profile::Sim, true)
            .unwrap();
        std::fs::write(data.join("mode.json"), &old_mode).unwrap();
        std::fs::write(data.join("profile.json"), &old_profile).unwrap();
        let restarted = ModeStore::new_with_epoch_root(&data, root.path(), Profile::Sim);
        assert_eq!(restarted.load_profile(), Profile::Prod);
        assert_eq!(
            restarted.effective(Profile::Test).operational,
            OperationalMode::Production
        );
    }

    #[test]
    fn switch_to_test_after_sim_epochs_uses_max_counter_not_prod_lock() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("sim");
        std::fs::create_dir_all(&data).unwrap();
        let store = ModeStore::new_with_epoch_root(&data, root.path(), Profile::Sim);
        store
            .set_operational(OperationalMode::Production, Profile::Sim, true)
            .unwrap();
        store
            .set_operational(OperationalMode::Production, Profile::Sim, true)
            .unwrap();
        store
            .set_operational(OperationalMode::Production, Profile::Sim, true)
            .unwrap();
        let (_, profile, counter) = store
            .set_operational(OperationalMode::Testing, Profile::Test, true)
            .unwrap();
        assert_eq!(profile, Profile::Test);
        assert_eq!(counter, 4);
        assert_eq!(store.load_profile(), Profile::Test);
        assert_eq!(
            store.effective(Profile::Test).operational,
            OperationalMode::Testing
        );
        let restarted = ModeStore::new_with_epoch_root(&data, root.path(), Profile::Sim);
        assert_eq!(restarted.load_profile(), Profile::Test);
        assert_eq!(
            restarted.effective(Profile::Test).operational,
            OperationalMode::Testing
        );
    }

    #[test]
    fn forged_high_highest_counter_only_raises_next_set_operational() {
        use crate::config::highest_epoch_counter_path;
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("sim");
        std::fs::create_dir_all(&data).unwrap();
        epoch_store::ensure_epoch_dir(root.path()).unwrap();
        std::fs::write(highest_epoch_counter_path(root.path()), b"999\n").unwrap();
        let store = ModeStore::new_with_epoch_root(&data, root.path(), Profile::Sim);
        let (_, profile, counter) = store
            .set_operational(OperationalMode::Production, Profile::Sim, true)
            .unwrap();
        assert_eq!(profile, Profile::Sim);
        assert_eq!(counter, 1000);
        assert_eq!(store.load_profile(), Profile::Sim);
    }

    #[test]
    fn corrupt_highest_counter_fail_closed() {
        use crate::config::{highest_epoch_counter_path, profile_data_dir};
        let root = tempfile::tempdir().unwrap();
        let data = profile_data_dir(root.path(), Profile::Sim);
        std::fs::create_dir_all(&data).unwrap();
        epoch_store::ensure_epoch_dir(root.path()).unwrap();
        std::fs::write(highest_epoch_counter_path(root.path()), b"not-a-number\n").unwrap();
        std::fs::write(
            data.join("profile.json"),
            serde_json::to_vec_pretty(&ProfileFileBody {
                profile: Profile::Sim,
                counter: 1,
            })
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            data.join("mode.json"),
            serde_json::to_vec_pretty(&ModeFileBody {
                mode: OperationalMode::Production,
                counter: 1,
            })
            .unwrap(),
        )
        .unwrap();
        let store = ModeStore::new_with_epoch_root(&data, root.path(), Profile::Sim);
        assert_eq!(store.load_profile(), Profile::Prod);
    }

    #[test]
    fn test_daemon_restart_stays_test_when_sim_epoch_counter_lower() {
        use crate::config::{highest_epoch_counter_path, profile_epoch_counter_path};
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("test");
        std::fs::create_dir_all(&data).unwrap();
        let store = ModeStore::new_with_epoch_root(&data, root.path(), Profile::Test);
        store
            .set_operational(OperationalMode::Testing, Profile::Test, true)
            .unwrap();
        std::fs::write(
            profile_epoch_counter_path(root.path(), Profile::Sim),
            b"1\n",
        )
        .unwrap();
        let restarted = ModeStore::new_with_epoch_root(&data, root.path(), Profile::Test);
        assert_eq!(restarted.load_profile(), Profile::Test);
        assert_eq!(
            restarted.effective(Profile::Test).operational,
            OperationalMode::Testing
        );
        std::fs::write(highest_epoch_counter_path(root.path()), b"999\n").unwrap();
        let tampered = ModeStore::new_with_epoch_root(&data, root.path(), Profile::Test);
        assert_eq!(tampered.load_profile(), Profile::Prod);
    }

    #[test]
    fn effective_highest_is_max_of_highest_file_and_scoped_profile_counters() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("sim");
        std::fs::create_dir_all(&data).unwrap();
        epoch_store::write_counter(root.path(), Profile::Sim, 5).unwrap();
        epoch_store::write_counter(root.path(), Profile::Test, 3).unwrap();
        epoch_store::bump_highest_epoch(root.path(), 4).unwrap();
        assert_eq!(
            epoch_store::effective_highest_for_profiles(
                root.path(),
                &[Profile::Sim, Profile::Test]
            )
            .unwrap(),
            5
        );
    }

    #[test]
    fn test_to_sim_in_production_restart_stays_sim() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("test");
        std::fs::create_dir_all(&data).unwrap();
        let store = ModeStore::new_with_epoch_root(&data, root.path(), Profile::Test);
        store
            .set_operational(OperationalMode::Testing, Profile::Test, true)
            .unwrap();
        store
            .set_operational(OperationalMode::Production, Profile::Sim, true)
            .unwrap();
        let restarted = ModeStore::new_with_epoch_root(&data, root.path(), Profile::Test);
        assert_eq!(restarted.load_profile(), Profile::Sim);
        assert_eq!(
            restarted.effective(Profile::Sim).operational,
            OperationalMode::Production
        );
    }

    fn sim_testing_snapshot_with_epoch_counters(root: &Path, data: &Path) -> ModeStore {
        let store = ModeStore::new_with_epoch_root(data, root, Profile::Sim);
        store
            .set_operational(OperationalMode::Production, Profile::Sim, true)
            .unwrap();
        store
            .set_operational(OperationalMode::Testing, Profile::Test, true)
            .unwrap();
        store
    }

    fn assert_highest_tamper_fail_closed(tamper: impl FnOnce(&Path)) {
        use crate::config::profile_epoch_counter_path;
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("sim");
        std::fs::create_dir_all(&data).unwrap();
        sim_testing_snapshot_with_epoch_counters(root.path(), &data);
        assert!(profile_epoch_counter_path(root.path(), Profile::Sim).exists());
        tamper(root.path());
        let restarted = ModeStore::new_with_epoch_root(&data, root.path(), Profile::Sim);
        assert_eq!(restarted.load_profile(), Profile::Prod);
        assert_eq!(
            restarted.effective(Profile::Test).operational,
            OperationalMode::Production
        );
    }

    #[test]
    fn rollback_snapshot_highest_deleted_fail_closed() {
        use crate::config::highest_epoch_counter_path;
        assert_highest_tamper_fail_closed(|root| {
            std::fs::remove_file(highest_epoch_counter_path(root)).unwrap();
        });
    }

    #[test]
    fn rollback_snapshot_highest_corrupt_fail_closed() {
        use crate::config::highest_epoch_counter_path;
        assert_highest_tamper_fail_closed(|root| {
            std::fs::write(highest_epoch_counter_path(root), b"not-a-number\n").unwrap();
        });
    }

    #[test]
    fn rollback_snapshot_highest_rolled_back_fail_closed() {
        use crate::config::highest_epoch_counter_path;
        assert_highest_tamper_fail_closed(|root| {
            std::fs::write(highest_epoch_counter_path(root), b"1\n").unwrap();
        });
    }

    #[test]
    fn rollback_snapshot_highest_empty_fail_closed() {
        use crate::config::highest_epoch_counter_path;
        assert_highest_tamper_fail_closed(|root| {
            std::fs::write(highest_epoch_counter_path(root), b"").unwrap();
        });
    }

    #[cfg(unix)]
    #[test]
    fn rollback_snapshot_highest_unreadable_fail_closed() {
        use crate::config::highest_epoch_counter_path;
        use std::os::unix::fs::PermissionsExt;
        assert_highest_tamper_fail_closed(|root| {
            let path = highest_epoch_counter_path(root);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        });
    }

    #[cfg(unix)]
    #[test]
    fn rollback_snapshot_highest_broken_symlink_fail_closed() {
        use crate::config::highest_epoch_counter_path;
        assert_highest_tamper_fail_closed(|root| {
            let path = highest_epoch_counter_path(root);
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink("/no/such/highest", &path).unwrap();
        });
    }

    #[test]
    fn rolled_back_mode_json_fail_closed_to_production() {
        let root = tempfile::tempdir().unwrap();
        let sim_dir = root.path().join("sim");
        std::fs::create_dir_all(&sim_dir).unwrap();
        let store = ModeStore::new_with_epoch_root(&sim_dir, root.path(), Profile::Sim);
        store
            .set_operational(OperationalMode::Testing, Profile::Test, true)
            .unwrap();
        store
            .set_operational(OperationalMode::Testing, Profile::Test, true)
            .unwrap();
        std::fs::write(
            sim_dir.join("mode.json"),
            serde_json::to_vec_pretty(&ModeFileBody {
                mode: OperationalMode::Testing,
                counter: 1,
            })
            .unwrap(),
        )
        .unwrap();
        let restarted = ModeStore::new_with_epoch_root(&sim_dir, root.path(), Profile::Sim);
        assert_eq!(
            restarted.effective(Profile::Test).operational,
            OperationalMode::Production
        );
    }
}
