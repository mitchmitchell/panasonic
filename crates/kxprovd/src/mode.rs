//! Signed mode.json with fail-closed Production (v2.6 F1).

use crate::audit::{alert_mode_failure, AuditEntry, AuditKind, AuditLog};
use crate::time::now_ms;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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
    #[error("bad signature")]
    BadSignature,
    #[error("unknown signer")]
    UnknownSigner,
    #[error("counter rollback")]
    CounterRollback,
    #[error("testing mode requires Test profile")]
    TestingProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeFileBody {
    pub mode: OperationalMode,
    pub counter: u64,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeSignersFile {
    pub signers: Vec<ModeSigner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeSigner {
    pub id: String,
    pub public_key_hex: String,
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
    pub fn new(data_dir: &Path) -> Self {
        Self {
            mode_path: data_dir.join("mode.json"),
            counter_path: data_dir.join("mode.counter"),
            signers_path: data_dir.join("mode-signers.json"),
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

    fn load_signers(&self) -> Result<ModeSignersFile, ModeError> {
        if !self.signers_path.exists() {
            return Ok(ModeSignersFile { signers: vec![] });
        }
        Ok(serde_json::from_slice(&std::fs::read(&self.signers_path)?)?)
    }

    fn verify_signature(&self, body: &ModeFileBody) -> Result<(), ModeError> {
        let sig_bytes = hex::decode(body.signature.trim()).map_err(|_| ModeError::BadSignature)?;
        let signature = Signature::from_slice(&sig_bytes).map_err(|_| ModeError::BadSignature)?;
        let msg = mode_sign_message(body.mode, body.counter);
        let signers = self.load_signers()?;
        for s in &signers.signers {
            let pk_bytes =
                hex::decode(s.public_key_hex.trim()).map_err(|_| ModeError::BadSignature)?;
            let pk_array: [u8; 32] = pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ModeError::BadSignature)?;
            let Ok(key) = VerifyingKey::from_bytes(&pk_array) else {
                continue;
            };
            if key.verify(&msg, &signature).is_ok() {
                return Ok(());
            }
        }
        Err(ModeError::BadSignature)
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

pub fn write_approval_required(profile: Profile, operational: OperationalMode) -> bool {
    match profile {
        Profile::Prod => true,
        Profile::Test => operational == OperationalMode::Production,
        Profile::Sim => true,
    }
}
