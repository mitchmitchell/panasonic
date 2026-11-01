use kxprov_api::Scope;

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
