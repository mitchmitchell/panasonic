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
        method: "GET",
        path: "/status",
    },
    HttpRoute {
        method: "POST",
        path: "/read",
    },
    HttpRoute {
        method: "POST",
        path: "/plan",
    },
    HttpRoute {
        method: "POST",
        path: "/api/plan",
    },
    HttpRoute {
        method: "POST",
        path: "/api/apply",
    },
    HttpRoute {
        method: "POST",
        path: "/api/approval/submit",
    },
];

/// MCP tools on the approval/apply path (N1 surface).
pub const MCP_APPROVAL_TOOLS: &[&str] = &["submit_approval", "apply_plan"];

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

pub fn http_route_mutates_mode_or_profile(route: &HttpRoute) -> bool {
    FORBIDDEN_MODE_PROFILE_PATHS
        .iter()
        .any(|p| route.path == *p || route.path.starts_with(&format!("{p}/")))
}

pub fn mcp_tool_mutates_mode_or_profile(tool_name: &str) -> bool {
    let n = tool_name.to_ascii_lowercase().replace('-', "_");
    ["set_mode", "set_profile", "change_mode", "change_profile"]
        .iter()
        .any(|b| n.contains(b))
}

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
