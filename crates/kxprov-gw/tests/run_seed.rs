#![allow(clippy::unwrap_used)]

use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::Argon2;
use std::path::PathBuf;

/// Used by `scripts/run-a4.sh` for dev admin + MCP token files.
#[test]
fn seed_run_dir_gateway_secrets() {
    let Some(run) = std::env::var("KXPROV_RUN_DIR").ok() else {
        return;
    };
    let secrets = PathBuf::from(run).join("secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let hash = Argon2::default()
        .hash_password(b"test-admin-password", &salt)
        .expect("hash")
        .to_string();
    std::fs::write(secrets.join("admin.hash"), hash).unwrap();
}
