#[test]
fn kxprov_api_matches_a3_module_layout() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in [
        "client.rs",
        "ids.rs",
        "lib.rs",
        "plan_hash.rs",
        "protocol.rs",
        "surface.rs",
        "types.rs",
    ] {
        assert!(
            manifest.join("src").join(name).is_file(),
            "missing canonical module {name}"
        );
    }
}
