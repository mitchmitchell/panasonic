use kxprov_api::{Profile, Scope};

use crate::error::BackendError;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeSet {
    bits: u8,
}

impl ScopeSet {
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    pub const fn with(mut self, scope: Scope) -> Self {
        self.bits |= scope_bit(scope);
        self
    }

    pub fn validate(&self) -> Result<(), BackendError> {
        if self.contains(Scope::Approve)
            && (self.contains(Scope::Plan) || self.contains(Scope::Write))
        {
            return Err(BackendError::InvalidScopeSet);
        }
        Ok(())
    }

    pub fn contains(&self, scope: Scope) -> bool {
        self.bits & scope_bit(scope) != 0
    }

    pub fn allows_read(&self) -> bool {
        self.contains(Scope::Read)
    }

    pub fn allows_plan(&self) -> bool {
        self.contains(Scope::Plan)
    }

    pub fn allows_write(&self) -> bool {
        self.contains(Scope::Write)
    }

    pub fn allows_approve(&self) -> bool {
        self.contains(Scope::Approve)
    }

    pub fn allows_call_log(&self) -> bool {
        self.contains(Scope::CallLog)
    }
}

const fn scope_bit(scope: Scope) -> u8 {
    match scope {
        Scope::Read => 1,
        Scope::Plan => 2,
        Scope::Write => 4,
        Scope::Approve => 8,
        Scope::CallLog => 16,
    }
}

pub fn scopes_for_role(role: &str) -> ScopeSet {
    let set = match role {
        "tester" => ScopeSet::empty().with(Scope::Read).with(Scope::Plan),
        "communications" => ScopeSet::empty()
            .with(Scope::Read)
            .with(Scope::Plan)
            .with(Scope::Write),
        "approver" => ScopeSet::empty().with(Scope::Read).with(Scope::Approve),
        "bots" => ScopeSet::empty().with(Scope::Read).with(Scope::CallLog),
        _ => ScopeSet::empty(),
    };
    set.validate().expect("role scope sets are valid");
    set
}

/// Scopes for an MCP role on a given profile. The tester role gains
/// [`Scope::CallLog`] on the simulator only (S6 design §3).
pub fn scopes_for_role_on(role: &str, profile: Profile) -> ScopeSet {
    let set = scopes_for_role(role);
    match (role, profile) {
        ("tester", Profile::Sim) => set.with(Scope::CallLog),
        _ => set,
    }
}

/// Refuses MCP scope sets that a profile must not grant: on test and prod no token may
/// hold both [`Scope::Plan`] and [`Scope::CallLog`], so tester-shaped call-log access is sim-only.
pub fn validate_scopes_for_profile(set: &ScopeSet, profile: Profile) -> Result<(), BackendError> {
    set.validate()?;
    if profile != Profile::Sim && set.contains(Scope::Plan) && set.contains(Scope::CallLog) {
        return Err(BackendError::InvalidScopeSet);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROLES: [&str; 4] = ["tester", "communications", "approver", "bots"];

    #[test]
    fn tester_has_call_log_on_sim_only() {
        assert!(scopes_for_role_on("tester", Profile::Sim).allows_call_log());
        for p in [Profile::Test, Profile::Prod] {
            assert!(!scopes_for_role_on("tester", p).allows_call_log(), "{p:?}");
        }
    }

    #[test]
    fn validator_refuses_plan_with_call_log_off_sim() {
        let tester_sim = scopes_for_role_on("tester", Profile::Sim);
        assert_eq!(
            validate_scopes_for_profile(&tester_sim, Profile::Sim),
            Ok(())
        );
        for p in [Profile::Test, Profile::Prod] {
            assert_eq!(
                validate_scopes_for_profile(&tester_sim, p),
                Err(BackendError::InvalidScopeSet),
                "{p:?}"
            );
            for role in ROLES {
                assert_eq!(
                    validate_scopes_for_profile(&scopes_for_role_on(role, p), p),
                    Ok(()),
                    "{role} {p:?}"
                );
            }
        }
    }

    #[test]
    fn bots_role_is_read_and_call_log_only() {
        let bots = scopes_for_role("bots");
        assert_eq!(
            bots,
            ScopeSet::empty().with(Scope::Read).with(Scope::CallLog)
        );
    }

    #[test]
    fn only_communications_holds_write_on_any_profile() {
        for p in [Profile::Sim, Profile::Test, Profile::Prod] {
            for role in ROLES {
                assert_eq!(
                    scopes_for_role_on(role, p).allows_write(),
                    role == "communications",
                    "{role} {p:?}"
                );
            }
        }
    }
}
