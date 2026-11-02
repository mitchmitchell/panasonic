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

/// Write gates (v2.11): G1, G2, G4 on prod; G1 alone on any other profile that talks to a
/// serial transport (#61). The simulator transport is never gated.
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
    serial: bool,
    locked: bool,
    live_writes_approved: bool,
    transition_blocked: bool,
) -> Option<ProdWriteGate> {
    if profile != Profile::Prod {
        return (serial && !live_writes_approved).then_some(ProdWriteGate::LiveWrites);
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

#[cfg(test)]
mod serial_gate_tests {
    use super::*;

    #[test]
    fn every_serial_profile_needs_live_writes_approved() {
        for p in [Profile::Sim, Profile::Test, Profile::Prod] {
            assert_eq!(
                prod_write_gate(p, true, false, false, false),
                Some(ProdWriteGate::LiveWrites),
                "{p:?}"
            );
        }
        assert_eq!(
            prod_write_gate(Profile::Test, true, false, true, false),
            None
        );
        assert_eq!(
            prod_write_gate(Profile::Test, false, false, false, false),
            None
        );
        assert_eq!(
            prod_write_gate(Profile::Sim, false, true, false, true),
            None
        );
    }
}
