//! Operational mode + runtime profile (v2.7 F1, unsigned, fail-closed Production).

use crate::audit::{alert_mode_failure, AuditEntry, AuditKind, AuditLog};
use crate::epoch_store;
use crate::time::now_ms;
use kxprov_api::{resolve_profile_data_dir, OperationalMode, Profile};
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
    /// `state_base` is the daemon data root; profile payload under [`resolve_profile_data_dir`].
    pub fn new(state_base: &Path, boot_profile: Profile) -> Self {
        Self::new_with_epoch_root(
            &resolve_profile_data_dir(state_base, boot_profile),
            state_base,
            boot_profile,
        )
    }

    pub fn new_with_epoch_root(
        profile_data_dir: &Path,
        provision_root: &Path,
        boot_profile: Profile,
    ) -> Self {
        Self {
            mode_path: profile_data_dir.join("mode.json"),
            profile_path: profile_data_dir.join("profile.json"),
            provision_root: provision_root.to_path_buf(),
            audit: AuditLog::new(profile_data_dir),
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
            Some(body) if self.later_epoch_on_other_profile(body.profile, body.counter) => {
                self.fail_closed(
                    AuditKind::ModeCounterRollback,
                    format!(
                        "profile.json counter {} stale after switch to another profile epoch",
                        body.counter
                    ),
                );
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

    /// Non-zero only when on-disk mode/profile files claim an epoch for `profile`.
    fn cross_profile_epoch_peers(&self) -> &'static [Profile] {
        match self.boot_profile {
            Profile::Sim | Profile::Test => &[Profile::Sim, Profile::Test],
            Profile::Prod => &[],
        }
    }

    fn later_epoch_on_other_profile(&self, profile: Profile, counter: u64) -> bool {
        for &other in self.cross_profile_epoch_peers() {
            if other == profile {
                continue;
            }
            let Ok(epoch) = epoch_store::read_counter(&self.provision_root, other) else {
                continue;
            };
            if epoch.is_some_and(|n| n > counter) {
                return true;
            }
        }
        false
    }

    fn stored_epoch_claim_for_profile(&self, profile: Profile) -> u64 {
        match std::fs::read_to_string(&self.profile_path) {
            Ok(raw) => match serde_json::from_str::<ProfileFileBody>(&raw) {
                Ok(body) if body.profile == profile => {
                    let mode_c = Self::file_counter(&self.mode_path).unwrap_or(0);
                    body.counter.max(mode_c)
                }
                Ok(_) => 0,
                Err(_) => 0,
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if profile == self.boot_profile {
                    Self::file_counter(&self.mode_path).unwrap_or(0)
                } else {
                    0
                }
            }
            Err(_) => 0,
        }
    }

    fn last_counter(&self, profile: Profile) -> Result<u64, ModeError> {
        match epoch_store::read_counter(&self.provision_root, profile)? {
            None => {
                if self.stored_epoch_claim_for_profile(profile) > 0 {
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
        if self.later_epoch_on_other_profile(profile, body.counter) {
            return self.fail_closed(
                AuditKind::ModeCounterRollback,
                format!(
                    "mode.json counter {} stale after switch to another profile epoch",
                    body.counter
                ),
            );
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
        let counter = last.saturating_add(1);
        if counter <= last {
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
    fn corrupt_epoch_file_surfaces_mode_error_epoch_not_counter_corrupt() {
        use crate::config::profile_epoch_counter_path;
        let root = tempfile::tempdir().unwrap();
        let sim_dir = root.path().join("sim");
        std::fs::create_dir_all(&sim_dir).unwrap();
        let counter = profile_epoch_counter_path(root.path(), Profile::Test);
        std::fs::create_dir_all(counter.parent().unwrap()).unwrap();
        std::fs::write(counter, "not-a-number\n").unwrap();
        let store = ModeStore::new_with_epoch_root(&sim_dir, root.path(), Profile::Sim);
        let err = store
            .set_operational(OperationalMode::Testing, Profile::Test, true)
            .unwrap_err();
        assert!(matches!(
            err,
            ModeError::Epoch(epoch_store::EpochError::Corrupt)
        ));
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
