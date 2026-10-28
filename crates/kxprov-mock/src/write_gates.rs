use kxprov_api::Profile;

pub fn prod_profile_write_gates_active(profile: Profile) -> bool {
    profile == Profile::Prod
}
