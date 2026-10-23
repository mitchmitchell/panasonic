use kxprov_mock::{
    mcp_tool_mutates_mode_or_profile, FORBIDDEN_MODE_PROFILE_PATHS, MCP_TOOLS, WEB_ROUTES,
};

#[test]
fn forbidden_samples_are_not_registered_web_routes() {
    for path in FORBIDDEN_MODE_PROFILE_PATHS {
        for route in WEB_ROUTES {
            assert_ne!(
                route.path, *path,
                "forbidden path {path} must not appear in WEB_ROUTES"
            );
        }
    }
}

#[test]
fn web_routes_are_unique() {
    let mut seen = std::collections::HashSet::new();
    for route in WEB_ROUTES {
        let key = (route.method, route.path);
        assert!(
            seen.insert(key),
            "duplicate route {} {}",
            route.method,
            route.path
        );
    }
}

#[test]
fn mcp_tools_are_unique() {
    let mut seen = std::collections::HashSet::new();
    for name in MCP_TOOLS {
        assert!(seen.insert(*name), "duplicate MCP tool {name}");
    }
}

#[test]
fn canonical_tables_do_not_mutate_mode_or_profile() {
    for route in WEB_ROUTES {
        assert!(!kxprov_mock::http_route_mutates_mode_or_profile(route));
    }
    for name in MCP_TOOLS {
        assert!(!mcp_tool_mutates_mode_or_profile(name));
    }
}
