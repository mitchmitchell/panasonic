use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Read,
    Plan,
    Write,
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
}

const fn scope_bit(scope: Scope) -> u8 {
    match scope {
        Scope::Read => 1,
        Scope::Plan => 2,
        Scope::Write => 4,
    }
}

/// Fixed roles for Phase A contract tests (hashes live in gateway config, not here).
pub fn scopes_for_role(role: &str) -> ScopeSet {
    match role {
        "tester" => ScopeSet::empty().with(Scope::Read).with(Scope::Plan),
        "communications" => ScopeSet::empty()
            .with(Scope::Read)
            .with(Scope::Plan)
            .with(Scope::Write),
        _ => ScopeSet::empty(),
    }
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
}
