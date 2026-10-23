//! Daemon-local token store (hashed secrets live outside the repo in production).

use kxprov_api::{Scope, TokenId};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TokenRecord {
    pub id: TokenId,
    pub scopes: Vec<Scope>,
}

#[derive(Debug, Clone, Default)]
pub struct TokenStore {
    by_id: HashMap<String, TokenRecord>,
}

impl TokenStore {
    pub fn with_test_defaults() -> Self {
        let mut by_id = HashMap::new();
        by_id.insert(
            "tester".into(),
            TokenRecord {
                id: TokenId("tester".into()),
                scopes: vec![Scope::Read, Scope::Plan],
            },
        );
        by_id.insert(
            "writer".into(),
            TokenRecord {
                id: TokenId("writer".into()),
                scopes: vec![Scope::Read, Scope::Plan, Scope::Write],
            },
        );
        by_id.insert(
            "comm".into(),
            TokenRecord {
                id: TokenId("comm".into()),
                scopes: vec![Scope::Read, Scope::Plan, Scope::Write],
            },
        );
        by_id.insert(
            "approver".into(),
            TokenRecord {
                id: TokenId("approver".into()),
                scopes: vec![Scope::Read, Scope::Approve],
            },
        );
        Self { by_id }
    }

    pub fn get(&self, id: &TokenId) -> Option<&TokenRecord> {
        self.by_id.get(id.as_str())
    }

    pub fn require_scope(&self, id: &TokenId, need: Scope) -> bool {
        self.get(id)
            .is_some_and(|t| t.scopes.iter().any(|s| *s == need))
    }
}
