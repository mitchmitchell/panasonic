use kxprov_api::Profile;
use kxprov_api::{diff_hash, CanonicalPlan, CanonicalWrite};
use kxprov_mock::{canonical_diff_hash, PlanChangeRequest};

#[test]
fn diff_hash_is_stable_for_canonical_bytes() {
    let profile = Profile::Test;
    let req = PlanChangeRequest {
        table: 0x24,
        record: 1,
        field: "name".into(),
        new_value: "x".into(),
        base_bytes: vec![1, 2, 3, 4],
        new_bytes: vec![5, 6, 7, 8],
    };
    let a = canonical_diff_hash(profile, &req);
    let b = canonical_diff_hash(profile, &req);
    assert_eq!(a, b);

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
    assert_eq!(diff_hash(&plan), diff_hash(&plan));
}
