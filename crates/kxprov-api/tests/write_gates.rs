use kxprov_api::{prod_profile_write_gates_active, Profile};

#[test]
fn prod_profile_activates_write_gates() {
    assert!(prod_profile_write_gates_active(&Profile::prod()));
    assert!(!prod_profile_write_gates_active(&Profile::test()));
}
