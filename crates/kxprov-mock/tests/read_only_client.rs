//! S6 design §3 and §6.4a: the call-log read paths hold only a read-only client.

#[test]
fn read_only_client_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/read_only_client_cannot_apply.rs");
    t.compile_fail("tests/ui/read_only_client_hides_backend.rs");
}

fn normal_deps(krate: &str) -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(krate)
        .join("Cargo.toml");
    let text = std::fs::read_to_string(&path).expect("crate manifest");
    let manifest: toml::Table = toml::from_str(&text).expect("valid manifest");
    manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .map(|t| t.keys().cloned().collect())
        .unwrap_or_default()
}

#[test]
fn surfaces_do_not_link_the_daemon_or_its_transports() {
    for krate in ["kxprov-gw", "kxprov-web", "kxprov-mcp", "kxprov-mock"] {
        let deps = normal_deps(krate);
        for forbidden in ["kxprovd", "kxtd1232-sim", "serialport"] {
            assert!(
                !deps.iter().any(|d| d == forbidden),
                "{krate} must not depend on {forbidden}"
            );
        }
    }
}

#[test]
fn call_log_sources_use_only_the_read_only_client() {
    for (name, src) in [
        (
            "kxprov-web/src/calls.rs",
            include_str!("../../kxprov-web/src/calls.rs"),
        ),
        ("kxprov-mcp/src/lib.rs smdr_query", {
            let s = include_str!("../../kxprov-mcp/src/lib.rs");
            let start = s.find("async fn smdr_query").expect("tool");
            &s[start..start + s[start..].find("\n    }\n").expect("end")]
        }),
    ] {
        for word in [
            ".backend.smdr_query",
            "apply_plan",
            "plan_change",
            "backup_now",
        ] {
            assert!(!src.contains(word), "{name} must not call {word}");
        }
        assert!(src.contains("ReadOnlyPbxClient::new"), "{name}");
    }
}
