//! Operational mode + runtime profile (v2.7 F1, unsigned, fail-closed Production).

use crate::audit::{alert_mode_failure, AuditEntry, AuditKind, AuditLog};
use crate::time::now_ms;
use kxprov_api::{mode_counter_path, resolve_profile_data_dir, OperationalMode, Profile};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("counter rollback")]
    CounterRollback,
    #[error("testing mode requires Test profile")]
    TestingProfile,
    #[error("daemon not idle")]
    NotIdle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeFileBody {
    pub mode: OperationalMode,
    /// Monotonic revision; must match `mode.counter` and `profile.json` (v2.12 rollback guard).
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
    counter_path: PathBuf,
    audit: AuditLog,
    boot_profile: Profile,
}

impl ModeStore {
    pub fn new(state_base: &Path, boot_profile: Profile) -> Self {
        let profile_root = resolve_profile_data_dir(state_base, boot_profile);
        Self {
            mode_path: profile_root.join("mode.json"),
            profile_path: profile_root.join("profile.json"),
            counter_path: mode_counter_path(state_base),
            audit: AuditLog::new(&profile_root),
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
        let last = self.last_counter().unwrap_or(0);
        match std::fs::read_to_string(&self.profile_path) {
            Ok(raw) => match serde_json::from_str::<ProfileFileBody>(&raw) {
                Ok(body) if body.counter < last => {
                    self.fail_closed_profile_rollback(body.counter, last);
                    Profile::Prod
                }
                Ok(body) => body.profile,
                Err(e) => {
                    self.fail_closed(AuditKind::ModeCorrupt, format!("profile.json: {e}"));
                    Profile::Prod
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => self.boot_profile,
            Err(e) => {
                self.fail_closed(AuditKind::ModeCorrupt, e.to_string());
                Profile::Prod
            }
        }
    }

    fn fail_closed_profile_rollback(&self, file_counter: u64, last: u64) {
        self.fail_closed(
            AuditKind::ModeCounterRollback,
            format!("profile.json counter {file_counter} < epoch {last}"),
        );
    }

    fn last_counter(&self) -> Result<u64, ModeError> {
        if !self.counter_path.exists() {
            return Ok(0);
        }
        let s = std::fs::read_to_string(&self.counter_path)?;
        Ok(s.trim().parse().unwrap_or(0))
    }

    fn save_counter(&self, counter: u64) -> Result<(), ModeError> {
        std::fs::write(&self.counter_path, counter.to_string())?;
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
        let last = self.last_counter().unwrap_or(0);
        if body.counter < last {
            return self.fail_closed(
                AuditKind::ModeCounterRollback,
                format!("mode.json counter {} < epoch {last}", body.counter),
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
        let last = self.last_counter()?;
        let counter = last.saturating_add(1);
        if counter <= last {
            return Err(ModeError::CounterRollback);
        }
        let body = ModeFileBody { mode, counter };
        std::fs::write(&self.mode_path, serde_json::to_vec_pretty(&body)?)?;
        std::fs::write(
            &self.profile_path,
            serde_json::to_vec_pretty(&ProfileFileBody { profile, counter })?,
        )?;
        self.save_counter(counter)?;
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
