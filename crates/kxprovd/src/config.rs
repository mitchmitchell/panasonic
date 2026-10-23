use crate::gates::GateConfig;
use crate::peer::PeerPolicy;
use kxprov_api::Profile;
use kxtd1232::{Timing, TimingConfigError};
#[cfg(feature = "inprocess-sim")]
use kxtd1232_sim::SimPbx;
use serde::Deserialize;
use std::path::{Path, PathBuf};
#[cfg(feature = "inprocess-sim")]
use std::sync::{Arc, Mutex};
use thiserror::Error;

pub const ETC_CONFIG: &str = "/etc/kxprov/kxprovd.json";
pub const PROVISION_ROOT: &str = "/var/lib/kx-provision";
pub const DEFAULT_SOCKET: &str = "/run/kx-provision/kxprovd.sock";
/// Root-only epoch counters (P4-R10), separate from per-profile `mode.json` / `profile.json`.
pub const EPOCH_DIR_NAME: &str = ".epoch";

pub fn profile_data_dir(provision_root: impl AsRef<Path>, profile: Profile) -> PathBuf {
    let seg = match profile {
        Profile::Sim => "sim",
        Profile::Test => "test",
        Profile::Prod => "prod",
    };
    provision_root.as_ref().join(seg)
}

pub fn profile_epoch_counter_path(provision_root: impl AsRef<Path>, profile: Profile) -> PathBuf {
    let seg = match profile {
        Profile::Sim => "sim",
        Profile::Test => "test",
        Profile::Prod => "prod",
    };
    provision_root
        .as_ref()
        .join(EPOCH_DIR_NAME)
        .join(format!("{seg}.counter"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Sim,
    Serial,
}

#[derive(Clone)]
pub struct Config {
    pub profile: Profile,
    pub transport: TransportKind,
    pub provision_root: PathBuf,
    pub data_dir: PathBuf,
    pub socket_path: PathBuf,
    pub password: String,
    pub gates: GateConfig,
    pub peer_policy: PeerPolicy,
    pub goliath_target: PathBuf,
    pub serial_device: PathBuf,
    pub gateway_uid: u32,
    pub admin_uid: u32,
    pub totp_enabled: bool,
    pub totp_secret_path: Option<PathBuf>,
    pub timing: Timing,
    #[cfg(feature = "inprocess-sim")]
    pub sim_pbx: Option<Arc<Mutex<SimPbx>>>,
    pub tokens_path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct EtcConfigFile {
    #[serde(default)]
    data_dir: Option<PathBuf>,
    #[serde(default = "default_provision_root")]
    provision_root: PathBuf,
    #[serde(default = "default_socket")]
    socket_path: PathBuf,
    #[serde(default = "default_tokens_path")]
    tokens_path: PathBuf,
    password_path: PathBuf,
    #[serde(default)]
    goliath_target: Option<PathBuf>,
    #[serde(default = "default_serial")]
    serial_device: PathBuf,
    #[serde(default = "default_gateway_uid")]
    gateway_uid: u32,
    #[serde(default = "default_admin_uid")]
    admin_uid: u32,
    #[serde(default)]
    profile: Profile,
    #[serde(default)]
    transport: TransportKindWire,
    #[serde(default)]
    gates: GateConfig,
    #[serde(default)]
    totp_enabled: bool,
    totp_secret_path: Option<PathBuf>,
    #[serde(default)]
    link_baud: Option<u32>,
    #[serde(default)]
    reply_guard_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransportKindWire {
    #[default]
    Serial,
    Sim,
}

fn default_provision_root() -> PathBuf {
    PathBuf::from(PROVISION_ROOT)
}

fn default_socket() -> PathBuf {
    PathBuf::from(DEFAULT_SOCKET)
}

fn default_tokens_path() -> PathBuf {
    PathBuf::from(PROVISION_ROOT).join("tokens.json")
}

fn default_serial() -> PathBuf {
    PathBuf::from("/dev/kxpbx")
}

fn default_gateway_uid() -> u32 {
    1000
}

fn default_admin_uid() -> u32 {
    0
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("timing: {0}")]
    Timing(#[from] TimingConfigError),
    #[error("gateway_uid must differ from admin_uid")]
    UidsMustDiffer,
    #[error("in-process sim transport was not enabled at build time (rebuild with feature inprocess-sim)")]
    SimTransportNotBuilt,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("profile", &self.profile)
            .field("transport", &self.transport)
            .field("data_dir", &self.data_dir)
            .field("timing", &self.timing)
            .field("tokens_path", &self.tokens_path)
            .finish_non_exhaustive()
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.timing.validate()?;
        if self.gateway_uid == self.admin_uid {
            return Err(ConfigError::UidsMustDiffer);
        }
        #[cfg(not(feature = "inprocess-sim"))]
        if self.transport == TransportKind::Sim {
            return Err(ConfigError::SimTransportNotBuilt);
        }
        Ok(())
    }

    pub fn load_from_etc(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let raw = std::fs::read(path.as_ref())?;
        let file: EtcConfigFile = serde_json::from_slice(&raw)?;
        let password = std::fs::read_to_string(&file.password_path)?;
        let transport = match file.transport {
            TransportKindWire::Sim => TransportKind::Sim,
            TransportKindWire::Serial => TransportKind::Serial,
        };
        let mut timing = Timing::default();
        if let Some(baud) = file.link_baud {
            timing.link_baud = baud;
        }
        if let Some(guard) = file.reply_guard_ms {
            timing.reply_guard_ms = guard;
        }
        let data_dir = file
            .data_dir
            .unwrap_or_else(|| profile_data_dir(&file.provision_root, file.profile));
        let goliath_target = file
            .goliath_target
            .unwrap_or_else(|| data_dir.join("goliath"));
        let cfg = Self {
            profile: file.profile,
            transport,
            provision_root: file.provision_root,
            data_dir,
            socket_path: file.socket_path,
            password: password.trim().to_string(),
            gates: file.gates,
            peer_policy: PeerPolicy::new(file.gateway_uid, file.admin_uid),
            goliath_target,
            serial_device: file.serial_device,
            gateway_uid: file.gateway_uid,
            admin_uid: file.admin_uid,
            totp_enabled: file.totp_enabled,
            totp_secret_path: file.totp_secret_path,
            timing,
            #[cfg(feature = "inprocess-sim")]
            sim_pbx: None,
            tokens_path: file.tokens_path,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    #[cfg(feature = "test-util")]
    pub fn sim_test(data_dir: PathBuf, socket_path: PathBuf, peer_uid: u32) -> Self {
        Self {
            profile: Profile::Sim,
            transport: TransportKind::Sim,
            provision_root: data_dir.clone(),
            data_dir: data_dir.clone(),
            socket_path,
            password: kxtd1232_sim::PLACEHOLDER_PASSWORD.to_string(),
            gates: GateConfig::default(),
            peer_policy: PeerPolicy::new(peer_uid.wrapping_add(1), peer_uid),
            goliath_target: data_dir.join("goliath"),
            serial_device: PathBuf::from("/dev/kxpbx"),
            gateway_uid: peer_uid.wrapping_add(1),
            admin_uid: peer_uid,
            totp_enabled: false,
            totp_secret_path: None,
            timing: Timing::default(),
            sim_pbx: Some(Arc::new(Mutex::new(SimPbx::default()))),
            tokens_path: data_dir.join("tokens.json"),
        }
    }
}
