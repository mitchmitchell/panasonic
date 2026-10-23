use kxprov_api::{
    canonical_plan_bytes, DiffHash, PlanChangeRequest, Profile,
};

#[test]
fn diff_hash_is_stable_for_canonical_bytes() {
    let profile = Profile::test();
    let req = PlanChangeRequest {
        table: 0x24,
        record: 1,
        field: "name".into(),
        new_value: "x".into(),
        base_bytes: vec![1, 2, 3, 4],
        new_bytes: vec![5, 6, 7, 8],
    };
    let a = canonical_plan_bytes(&profile, &req).expect("canonical");
    let b = canonical_plan_bytes(&profile, &req).expect("canonical");
    assert_eq!(
        DiffHash::from_canonical_bytes(&a),
        DiffHash::from_canonical_bytes(&b)
    );
}
