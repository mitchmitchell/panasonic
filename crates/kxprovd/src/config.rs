use crate::gates::GateConfig;
use crate::peer::PeerPolicy;
use kxprov_api::Profile;
use kxprov_api::{
    goliath_dir, resolve_profile_data_dir, sim_passed_path, DAEMON_ETC_CONFIG, DAEMON_SOCKET,
    DATA_DIR, TOKENS_JSON,
};
use kxtd1232::{SignOn, Timing, TimingConfigError};
use kxtd1232_sim::SimPbx;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;

pub const ETC_CONFIG: &str = DAEMON_ETC_CONFIG;

pub use kxprov_api::{profile_epoch_counter_path, EPOCH_DIR_NAME};

/// Profile-scoped tree under the provision root (`{root}/sim`, etc.).
pub fn profile_data_dir(provision_root: impl AsRef<Path>, profile: Profile) -> PathBuf {
    resolve_profile_data_dir(provision_root.as_ref(), profile)
}

/// Monotonic highest epoch ever written under this provision root (cross-profile rollback guard).
pub fn highest_epoch_counter_path(provision_root: impl AsRef<Path>) -> PathBuf {
    provision_root
        .as_ref()
        .join(EPOCH_DIR_NAME)
        .join("highest.counter")
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
    /// Group on the daemon Unix socket (`0660`), e.g. `kxprovision`.
    pub daemon_socket_group: String,
    pub totp_enabled: bool,
    pub totp_secret_path: Option<PathBuf>,
    pub timing: Timing,
    pub signon: SignOn,
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
    goliath_target: Option<PathBuf>,
    #[serde(default = "default_serial")]
    serial_device: PathBuf,
    #[serde(default)]
    gateway_uid: Option<u32>,
    #[serde(default = "default_gateway_user")]
    gateway_user: String,
    #[serde(default = "default_admin_uid")]
    admin_uid: u32,
    #[serde(default = "default_daemon_socket_group")]
    daemon_socket_group: String,
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
    #[serde(default)]
    signon_path: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignOnFile {
    banner: String,
    password_prompt: String,
    mode_start: String,
    in_use: String,
}

fn load_signon(path: &Path) -> Result<SignOn, ConfigError> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    if meta.mode() & 0o077 != 0 {
        return Err(ConfigError::SignOnPermissions(format!(
            "{} must not be readable by group or others (mode {:o})",
            path.display(),
            meta.mode() & 0o777
        )));
    }
    if meta.uid() != nix::unistd::geteuid().as_raw() {
        return Err(ConfigError::SignOnPermissions(format!(
            "{} must be owned by the daemon user",
            path.display()
        )));
    }
    let file: SignOnFile = serde_json::from_slice(&std::fs::read(path)?)?;
    let signon = SignOn {
        banner: file.banner,
        password_prompt: file.password_prompt,
        mode_start: file.mode_start,
        in_use: file.in_use,
    };
    for (field, v) in [
        ("password_prompt", &signon.password_prompt),
        ("mode_start", &signon.mode_start),
        ("in_use", &signon.in_use),
    ] {
        if v.trim().is_empty() {
            return Err(ConfigError::SignOnEmpty(field));
        }
    }
    Ok(signon)
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransportKindWire {
    #[default]
    Sim,
    Serial,
}

fn default_provision_root() -> PathBuf {
    PathBuf::from(DATA_DIR)
}

fn default_socket() -> PathBuf {
    PathBuf::from(DAEMON_SOCKET)
}

fn default_tokens_path() -> PathBuf {
    PathBuf::from(TOKENS_JSON)
}

/// Production path defaults (serde defaults and package layout).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionPathDefaults {
    pub provision_root: PathBuf,
    pub data_dir: PathBuf,
    pub socket_path: PathBuf,
    pub tokens_path: PathBuf,
    pub goliath_target: PathBuf,
}

pub fn production_path_defaults() -> ProductionPathDefaults {
    let profile = Profile::Sim;
    let provision_root = default_provision_root();
    ProductionPathDefaults {
        socket_path: default_socket(),
        data_dir: profile_data_dir(&provision_root, profile),
        provision_root,
        tokens_path: default_tokens_path(),
        goliath_target: PathBuf::from(goliath_dir(profile)),
    }
}

impl Config {
    /// Active profile state directory (plans, backups, mode.json, …).
    pub fn profile_data_dir(&self) -> PathBuf {
        self.data_dir.clone()
    }

    /// Simulator pass marker path (same resolution as `kxprov sim-mark`).
    pub fn sim_passed_path(&self) -> PathBuf {
        sim_passed_path(&self.provision_root)
    }
}

fn default_serial() -> PathBuf {
    PathBuf::from("/dev/kxpbx")
}

fn default_gateway_user() -> String {
    "kxprov-gw".into()
}

fn default_daemon_socket_group() -> String {
    "kxprovision".into()
}

fn resolve_gateway_uid(explicit: Option<u32>, user_name: &str) -> Result<u32, ConfigError> {
    if let Some(uid) = explicit {
        return Ok(uid);
    }
    #[cfg(unix)]
    {
        use nix::unistd::User;
        let user = User::from_name(user_name).map_err(|e| ConfigError::Io(e.into()))?;
        user.ok_or_else(|| ConfigError::UnknownGatewayUser(user_name.to_string()))
            .map(|u| u.uid.as_raw())
    }
    #[cfg(not(unix))]
    {
        let _ = user_name;
        Err(ConfigError::Missing)
    }
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
    #[error("gateway user {0} not found (set gateway_uid explicitly)")]
    UnknownGatewayUser(String),
    #[error("missing config")]
    Missing,
    #[error("transport \"serial\" requires signon_path (private sign-on file)")]
    SignOnRequired,
    #[error("signon file: {0}")]
    SignOnPermissions(String),
    #[error("signon file: {0} must not be empty")]
    SignOnEmpty(&'static str),
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("profile", &self.profile)
            .field("transport", &self.transport)
            .field("provision_root", &self.provision_root)
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
        let provision_root = file
            .data_dir
            .clone()
            .unwrap_or_else(|| file.provision_root.clone());
        let data_dir = profile_data_dir(&provision_root, file.profile);
        let goliath_target = file
            .goliath_target
            .unwrap_or_else(|| data_dir.join("goliath"));
        let sim_pbx = if transport == TransportKind::Sim {
            Some(Arc::new(Mutex::new(SimPbx::default())))
        } else {
            None
        };
        let signon = match (transport, &file.signon_path) {
            (_, Some(p)) => load_signon(p)?,
            (TransportKind::Serial, None) => return Err(ConfigError::SignOnRequired),
            (TransportKind::Sim, None) => SignOn::default(),
        };
        let gateway_uid = resolve_gateway_uid(file.gateway_uid, &file.gateway_user)?;
        let cfg = Self {
            profile: file.profile,
            transport,
            provision_root,
            data_dir,
            socket_path: file.socket_path,
            password: password.trim().to_string(),
            gates: file.gates,
            peer_policy: PeerPolicy::new(gateway_uid, file.admin_uid),
            goliath_target,
            serial_device: file.serial_device,
            gateway_uid,
            admin_uid: file.admin_uid,
            daemon_socket_group: file.daemon_socket_group,
            totp_enabled: file.totp_enabled,
            totp_secret_path: file.totp_secret_path,
            timing,
            signon,
            sim_pbx,
            tokens_path: file.tokens_path,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    #[cfg(feature = "test-util")]
    pub fn sim_test(data_dir: PathBuf, socket_path: PathBuf, peer_uid: u32) -> Self {
        let provision_root = data_dir.clone();
        let profile_dir = profile_data_dir(&provision_root, Profile::Sim);
        Self {
            profile: Profile::Sim,
            transport: TransportKind::Sim,
            provision_root,
            data_dir: profile_dir.clone(),
            socket_path,
            password: kxtd1232_sim::PLACEHOLDER_PASSWORD.to_string(),
            gates: GateConfig::default(),
            peer_policy: PeerPolicy::new(peer_uid.wrapping_add(1), peer_uid),
            goliath_target: profile_dir.join("goliath"),
            serial_device: PathBuf::from("/dev/kxpbx"),
            gateway_uid: peer_uid.wrapping_add(1),
            admin_uid: peer_uid,
            daemon_socket_group: String::new(),
            totp_enabled: false,
            totp_secret_path: None,
            timing: Timing::default(),
            signon: SignOn::default(),
            sim_pbx: Some(Arc::new(Mutex::new(SimPbx::default()))),
            tokens_path: data_dir.join("tokens.json"),
        }
    }

    #[cfg(feature = "test-util")]
    pub fn sim_test_gateway_caller(
        data_dir: PathBuf,
        socket_path: PathBuf,
        gateway_uid: u32,
    ) -> Self {
        let admin_uid = gateway_uid.wrapping_add(1);
        let provision_root = data_dir.clone();
        let profile_dir = profile_data_dir(&provision_root, Profile::Sim);
        Self {
            profile: Profile::Sim,
            transport: TransportKind::Sim,
            provision_root,
            data_dir: profile_dir.clone(),
            socket_path,
            password: kxtd1232_sim::PLACEHOLDER_PASSWORD.to_string(),
            gates: GateConfig::default(),
            peer_policy: PeerPolicy::new(gateway_uid, admin_uid),
            goliath_target: profile_dir.join("goliath"),
            serial_device: PathBuf::from("/dev/kxpbx"),
            gateway_uid,
            admin_uid,
            daemon_socket_group: String::new(),
            totp_enabled: false,
            totp_secret_path: None,
            timing: Timing::default(),
            signon: SignOn::default(),
            sim_pbx: Some(Arc::new(Mutex::new(SimPbx::default()))),
            tokens_path: data_dir.join("tokens.json"),
        }
    }
}
