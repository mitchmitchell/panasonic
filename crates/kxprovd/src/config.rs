use crate::gates::GateConfig;
use crate::peer::PeerPolicy;
use kxprov_api::Profile;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Sim,
    Serial,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub profile: Profile,
    pub transport: TransportKind,
    pub data_dir: PathBuf,
    pub socket_path: PathBuf,
    pub password: String,
    pub gates: GateConfig,
    pub peer_policy: PeerPolicy,
    pub goliath_target: PathBuf,
    pub serial_device: PathBuf,
    pub gateway_uid: u32,
    pub admin_uid: u32,
    /// Optional TOTP for admin re-auth (A4 wires verification; off by default).
    pub totp_enabled: bool,
    pub totp_secret_path: Option<PathBuf>,
}

impl Config {
    pub fn sim_test(data_dir: PathBuf, socket_path: PathBuf, peer_uid: u32) -> Self {
        Self {
            profile: Profile::Sim,
            transport: TransportKind::Sim,
            data_dir: data_dir.clone(),
            socket_path,
            password: kxtd1232_sim::PLACEHOLDER_PASSWORD.to_string(),
            gates: GateConfig::default(),
            peer_policy: PeerPolicy::new(peer_uid, peer_uid),
            goliath_target: data_dir.join("goliath"),
            serial_device: PathBuf::from("/dev/kxpbx"),
            gateway_uid: peer_uid,
            admin_uid: peer_uid,
            totp_enabled: false,
            totp_secret_path: None,
        }
    }
}
