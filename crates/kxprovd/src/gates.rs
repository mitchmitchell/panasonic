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

/// Write gates (v2.11): G2 and G4 apply on the Prod profile; G1 applies on the Prod
/// profile and on every profile that uses a serial transport (#61).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProdWriteGate {
    /// G1
    LiveWrites,
    /// G2
    Locked,
    /// G4
    TransitionMismatch,
}

/// Returns the first write gate that blocks a write, or `None` when writes may run.
///
/// `serial_transport` is true when the daemon talks to a real unit over a serial line.
/// `live_writes_approved` gates such a daemon on every profile, so a Test or Sim profile
/// pointed at real hardware cannot write while the gate is false.
pub fn prod_write_gate(
    profile: Profile,
    serial_transport: bool,
    locked: bool,
    live_writes_approved: bool,
    transition_blocked: bool,
) -> Option<ProdWriteGate> {
    if profile != Profile::Prod {
        if serial_transport && !live_writes_approved {
            return Some(ProdWriteGate::LiveWrites);
        }
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

#[cfg(test)]
mod tests {
    use super::{prod_write_gate, ProdWriteGate};
    use kxprov_api::Profile;

    #[test]
    fn live_writes_gate_covers_every_profile_on_serial_transport() {
        for profile in [Profile::Prod, Profile::Test, Profile::Sim] {
            assert_eq!(
                prod_write_gate(profile, true, false, false, false),
                Some(ProdWriteGate::LiveWrites),
                "{profile:?}"
            );
        }
    }

    #[test]
    fn serial_non_prod_profile_writes_when_approved() {
        for profile in [Profile::Test, Profile::Sim] {
            assert_eq!(prod_write_gate(profile, true, true, true, true), None);
        }
    }

    #[test]
    fn sim_transport_non_prod_profile_is_not_gated() {
        for profile in [Profile::Test, Profile::Sim] {
            assert_eq!(prod_write_gate(profile, false, true, false, true), None);
        }
    }

    #[test]
    fn prod_profile_gates_on_sim_transport_too() {
        assert_eq!(
            prod_write_gate(Profile::Prod, false, false, false, false),
            Some(ProdWriteGate::LiveWrites)
        );
        assert_eq!(
            prod_write_gate(Profile::Prod, false, true, true, false),
            Some(ProdWriteGate::Locked)
        );
    }
}
