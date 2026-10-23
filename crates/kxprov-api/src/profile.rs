use serde::{Deserialize, Serialize};

/// Active daemon profile (`test` or `prod` in production configs).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Profile(pub String);

impl Profile {
    pub fn test() -> Self {
        Self("test".into())
    }

    pub fn prod() -> Self {
        Self("prod".into())
    }
}
