//! Prod-profile write gates (design v2.11). Test profile skips G1–G2/G4–G5 enforcement paths in the mock.

use crate::profile::Profile;

/// Gates G1, G2, G4, and G5 apply only when the active daemon profile is `prod`.
pub fn prod_profile_write_gates_active(profile: &Profile) -> bool {
    profile == &Profile::prod()
}
