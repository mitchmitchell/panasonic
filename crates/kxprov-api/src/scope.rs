use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Read,
    Plan,
    Write,
    Approve,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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

    pub fn from_scopes(scopes: &[Scope]) -> Self {
        let mut set = Self::empty();
        for s in scopes {
            set = set.with(*s);
        }
        set
    }

    /// F1: `Approve` is never combinable with `Plan` or `Write`.
    pub fn validate(&self) -> Result<(), crate::error::ApiError> {
        if self.contains(Scope::Approve)
            && (self.contains(Scope::Plan) || self.contains(Scope::Write))
        {
            return Err(crate::error::ApiError::InvalidScopeSet);
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
}

const fn scope_bit(scope: Scope) -> u8 {
    match scope {
        Scope::Read => 1,
        Scope::Plan => 2,
        Scope::Write => 4,
        Scope::Approve => 8,
    }
}

/// Fixed roles for Phase A contract tests (hashes live in gateway config, not here).
pub fn scopes_for_role(role: &str) -> ScopeSet {
    let set = match role {
        "tester" => ScopeSet::empty().with(Scope::Read).with(Scope::Plan),
        "communications" => ScopeSet::empty()
            .with(Scope::Read)
            .with(Scope::Plan)
            .with(Scope::Write),
        "approver" => ScopeSet::empty().with(Scope::Read).with(Scope::Approve),
        _ => ScopeSet::empty(),
    };
    set.validate().expect("role scope sets are valid");
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tester_never_has_write() {
        assert!(!scopes_for_role("tester").allows_write());
        assert!(scopes_for_role("tester").allows_read());
        assert!(scopes_for_role("tester").allows_plan());
    }

    #[test]
    fn communications_has_write() {
        assert!(scopes_for_role("communications").allows_write());
    }

    #[test]
    fn approve_cannot_combine_with_plan_or_write() {
        let bad = ScopeSet::empty().with(Scope::Approve).with(Scope::Plan);
        assert_eq!(bad.validate(), Err(crate::error::ApiError::InvalidScopeSet));
        let bad = ScopeSet::empty().with(Scope::Approve).with(Scope::Write);
        assert_eq!(bad.validate(), Err(crate::error::ApiError::InvalidScopeSet));
    }

    #[test]
    fn approver_role_is_valid() {
        let a = scopes_for_role("approver");
        assert!(a.allows_approve());
        assert!(!a.allows_plan());
        assert!(!a.allows_write());
    }
}
