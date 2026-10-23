#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use kxprovd::test_util::write_integration_tokens;

/// Used by `scripts/run-a4.sh` to write integration tokens into `KXPROV_RUN_DIR/data`.
#[test]
fn seed_run_dir_tokens() {
    let Some(run) = std::env::var("KXPROV_RUN_DIR").ok() else {
        return;
    };
    let tokens = PathBuf::from(run).join("data/tokens.json");
    if let Some(parent) = tokens.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    write_integration_tokens(&tokens);
}
