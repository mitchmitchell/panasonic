use kxprov_api::Profile;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GateConfig {
    pub live_writes_approved: bool,
}

#[derive(Debug, Clone, Default)]
pub struct GateState {
    pub config: GateConfig,
}

/// Prod-profile write gates (v2.11): G1, G2, G4 — skipped on Test/Sim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProdWriteGate {
    /// G1
    LiveWrites,
    /// G2
    Locked,
    /// G4
    TransitionMismatch,
}

pub fn prod_write_gate(
    profile: Profile,
    locked: bool,
    live_writes_approved: bool,
    transition_blocked: bool,
) -> Option<ProdWriteGate> {
    if profile != Profile::Prod {
        return None;
    }
    if locked {
        return Some(ProdWriteGate::Locked);
    }
    if !live_writes_approved {
        return Some(ProdWriteGate::LiveWrites);
    }
    if transition_blocked {
        return Some(ProdWriteGate::TransitionMismatch);
    }
    None
}
