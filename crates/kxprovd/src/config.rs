use crate::gates::GateConfig;
use crate::peer::PeerPolicy;
use kxprov_api::{DaemonMode, Profile, Scope};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Sim,
    Serial,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub profile: Profile,
    pub mode: DaemonMode,
    pub transport: TransportKind,
    pub data_dir: PathBuf,
    pub socket_path: PathBuf,
    pub password: String,
    pub gates: GateConfig,
    pub peer_policy: PeerPolicy,
    pub goliath_target: PathBuf,
    pub serial_device: PathBuf,
}

impl Config {
    pub fn sim_test(data_dir: PathBuf, socket_path: PathBuf, peer_uid: u32) -> Self {
        Self {
            profile: Profile::Sim,
            mode: DaemonMode::Simulator,
            transport: TransportKind::Sim,
            data_dir: data_dir.clone(),
            socket_path,
            password: kxtd1232_sim::PLACEHOLDER_PASSWORD.to_string(),
            gates: GateConfig::default(),
            peer_policy: PeerPolicy::new([
                (
                    peer_uid,
                    vec![Scope::Read, Scope::Plan, Scope::Write, Scope::Arm],
                ),
                (0, vec![Scope::Read, Scope::Plan, Scope::Write, Scope::Arm]),
            ]),
            goliath_target: data_dir.join("goliath"),
            serial_device: PathBuf::from("/dev/kxpbx"),
        }
    }
}
