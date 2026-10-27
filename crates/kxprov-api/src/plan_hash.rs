//! Canonical plan bytes for stable [`DiffHash`] (v2.3 §5b F1/F7).

use crate::{DiffHash, Profile};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
pub struct CanonicalWrite<'a> {
    pub table: u8,
    pub record: u16,
    pub word: u16,
    pub base: &'a [u8],
    pub new: &'a [u8],
}

#[derive(Serialize)]
pub struct CanonicalPlan<'a> {
    pub profile: Profile,
    pub table: u8,
    pub record_size: usize,
    pub writes: Vec<CanonicalWrite<'a>>,
}

pub fn diff_hash(plan: &CanonicalPlan<'_>) -> DiffHash {
    let bytes = serde_json::to_vec(plan).expect("canonical plan serializes");
    DiffHash(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_hash_stable() {
        let plan = CanonicalPlan {
            profile: Profile::Sim,
            table: 0x25,
            record_size: 16,
            writes: vec![CanonicalWrite {
                table: 0x25,
                record: 1,
                word: 0,
                base: &[0u8; 4],
                new: &[1u8; 4],
            }],
        };
        let a = diff_hash(&plan);
        let b = diff_hash(&plan);
        assert_eq!(a, b);
    }
}
