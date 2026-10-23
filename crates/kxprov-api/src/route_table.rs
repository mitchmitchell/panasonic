//! Design v2.8 N1: canonical HTTP and MCP surface — mode/profile are not mutable via gateway.

/// Registered web HTTP routes (method + path pattern). Keep in sync with `kxprov_web::router`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpRoute {
    pub method: &'static str,
    pub path: &'static str,
}

pub const WEB_ROUTES: &[HttpRoute] = &[
    HttpRoute {
        method: "GET",
        path: "/static/{file}",
    },
    HttpRoute {
        method: "GET",
        path: "/login",
    },
    HttpRoute {
        method: "POST",
        path: "/login",
    },
    HttpRoute {
        method: "POST",
        path: "/logout",
    },
    HttpRoute {
        method: "GET",
        path: "/",
    },
    HttpRoute {
        method: "POST",
        path: "/plan",
    },
];

/// MCP tools exposed by `KxMcpServer`. Keep in sync with `kxprov-mcp` tool definitions.
pub const MCP_TOOLS: &[&str] = &[
    "status",
    "list_backups",
    "backup_now",
    "read_fields",
    "plan_change",
    "apply_plan",
    "submit_approval",
    "rollback",
];

/// Paths that must not exist (no mode/profile control plane on HTTP).
pub const FORBIDDEN_MODE_PROFILE_PATHS: &[&str] = &[
    "/mode",
    "/profile",
    "/api/mode",
    "/api/profile",
    "/api/mode/set",
    "/api/profile/set",
    "/set-mode",
    "/set-profile",
    "/daemon/mode",
    "/daemon/profile",
];

fn name_suggests_mode_or_profile_mutation(name: &str) -> bool {
    let n = name.to_ascii_lowercase().replace('-', "_");
    let blocked = [
        "set_mode",
        "set_profile",
        "change_mode",
        "change_profile",
        "update_mode",
        "update_profile",
        "switch_mode",
        "switch_profile",
    ];
    blocked.iter().any(|b| n == *b || n.contains(b))
}

fn path_suggests_mode_or_profile_mutation(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    if FORBIDDEN_MODE_PROFILE_PATHS
        .iter()
        .any(|sample| p == *sample || p.starts_with(&format!("{sample}/")))
    {
        return true;
    }
    p.contains("/set-mode")
        || p.contains("/set-profile")
        || p.contains("/set_mode")
        || p.contains("/set_profile")
}

/// True if this registered HTTP route would mutate mode or profile (must never be true).
pub fn http_route_mutates_mode_or_profile(route: &HttpRoute) -> bool {
    path_suggests_mode_or_profile_mutation(route.path)
        || name_suggests_mode_or_profile_mutation(route.path)
}

/// True if this MCP tool name would mutate mode or profile (must never be true).
pub fn mcp_tool_mutates_mode_or_profile(tool_name: &str) -> bool {
    name_suggests_mode_or_profile_mutation(tool_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_route_table_has_no_mode_or_profile_mutators() {
        for route in WEB_ROUTES {
            assert!(
                !http_route_mutates_mode_or_profile(route),
                "route {} {} must not change mode/profile",
                route.method,
                route.path
            );
        }
    }

    #[test]
    fn mcp_tool_table_has_no_mode_or_profile_mutators() {
        for name in MCP_TOOLS {
            assert!(
                !mcp_tool_mutates_mode_or_profile(name),
                "tool {name} must not change mode/profile"
            );
        }
    }
}
