//! Operational mode + runtime profile (v2.7 F1, unsigned, fail-closed Production).

use crate::audit::{alert_mode_failure, AuditEntry, AuditKind, AuditLog};
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileFileBody {
    pub profile: Profile,
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
    pub fn new(data_dir: &Path, boot_profile: Profile) -> Self {
        Self {
            mode_path: data_dir.join("mode.json"),
            profile_path: data_dir.join("profile.json"),
            counter_path: data_dir.join("mode.counter"),
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
        match std::fs::read_to_string(&self.profile_path) {
            Ok(raw) => serde_json::from_str::<ProfileFileBody>(&raw)
                .map(|b| b.profile)
                .unwrap_or(self.boot_profile),
            Err(_) => self.boot_profile,
        }
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
        let body = ModeFileBody { mode };
        std::fs::write(&self.mode_path, serde_json::to_vec_pretty(&body)?)?;
        std::fs::write(
            &self.profile_path,
            serde_json::to_vec_pretty(&ProfileFileBody { profile })?,
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
