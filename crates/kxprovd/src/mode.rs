//! Signed mode.json with fail-closed Production (v2.6 F1).

use crate::audit::{alert_mode_failure, AuditEntry, AuditKind, AuditLog};
use crate::sshsig_verify::{verify_mode_nonce, SshsigError};
use crate::time::now_ms;
use kxprov_api::mode_sign_message;
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
    #[error("bad signature: {0}")]
    BadSignature(#[from] SshsigError),
    #[error("counter rollback")]
    CounterRollback,
    #[error("testing mode requires Test profile")]
    TestingProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeFileBody {
    pub mode: OperationalMode,
    pub counter: u64,
    /// PEM armored OpenSSH signature over the mode nonce (`ssh-keygen -Y sign`).
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveMode {
    pub operational: OperationalMode,
}

pub struct ModeStore {
    mode_path: PathBuf,
    counter_path: PathBuf,
    signers_path: PathBuf,
    audit: AuditLog,
}

impl ModeStore {
    pub fn new(data_dir: &Path, signers_path: PathBuf) -> Self {
        Self {
            mode_path: data_dir.join("mode.json"),
            counter_path: data_dir.join("mode.counter"),
            signers_path,
            audit: AuditLog::new(data_dir),
        }
    }

    pub fn signers_path(&self) -> &Path {
        &self.signers_path
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

    fn verify_signature(&self, body: &ModeFileBody) -> Result<(), ModeError> {
        let nonce = mode_sign_message(body.mode, body.counter);
        verify_mode_nonce(&nonce, &body.signature, &self.signers_path)?;
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
        if let Err(e) = self.verify_signature(&body) {
            return self.fail_closed(
                AuditKind::ModeBadSignature,
                format!("signature verification failed: {e}"),
            );
        }
        let last = match self.last_counter() {
            Ok(c) => c,
            Err(e) => {
                return self.fail_closed(AuditKind::ModeCorrupt, e.to_string());
            }
        };
        if body.counter <= last {
            return self.fail_closed(
                AuditKind::ModeCounterRollback,
                format!("counter {} <= committed {}", body.counter, last),
            );
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

    /// Root admin: install a new signed mode.json after verification.
    pub fn set_signed(&self, body: ModeFileBody) -> Result<EffectiveMode, ModeError> {
        self.verify_signature(&body)?;
        let last = self.last_counter()?;
        if body.counter <= last {
            return Err(ModeError::CounterRollback);
        }
        std::fs::write(&self.mode_path, serde_json::to_vec_pretty(&body)?)?;
        self.save_counter(body.counter)?;
        Ok(EffectiveMode {
            operational: body.mode,
        })
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }
}

/// Whether apply requires a prior approval for this profile/mode (v2.6 F1).
pub fn write_approval_required(profile: Profile, operational: OperationalMode) -> bool {
    match profile {
        Profile::Prod => true,
        Profile::Test => operational == OperationalMode::Production,
        Profile::Sim => false,
    }
}
