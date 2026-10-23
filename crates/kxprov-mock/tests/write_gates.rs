use kxprov_api::Profile;
use kxprov_mock::prod_profile_write_gates_active;

#[test]
fn prod_profile_activates_write_gates() {
    assert!(prod_profile_write_gates_active(Profile::Prod));
    assert!(!prod_profile_write_gates_active(Profile::Test));
}
