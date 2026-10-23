//! Declared HTTP and MCP surface (v2.8 N1). Mode/profile changes are root CLI only.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpStatus {
    Ok,
    NotFound,
    MethodNotAllowed,
}

#[derive(Debug, Clone, Copy)]
pub struct HttpRoute {
    pub method: HttpMethod,
    pub path: &'static str,
}

/// Planned A4 web routes (read/plan/approval only; no mode or profile).
pub const HTTP_ROUTES: &[HttpRoute] = &[
    HttpRoute {
        method: HttpMethod::Get,
        path: "/",
    },
    HttpRoute {
        method: HttpMethod::Get,
        path: "/status",
    },
    HttpRoute {
        method: HttpMethod::Post,
        path: "/api/plan",
    },
    HttpRoute {
        method: HttpMethod::Post,
        path: "/api/apply",
    },
    HttpRoute {
        method: HttpMethod::Post,
        path: "/api/approval/submit",
    },
];

/// Paths that must never switch mode or profile over HTTP (v2.8 N1).
pub const FORBIDDEN_MODE_PROFILE_HTTP: &[(&str, HttpMethod)] = &[
    ("/api/mode", HttpMethod::Post),
    ("/api/mode", HttpMethod::Put),
    ("/api/mode", HttpMethod::Patch),
    ("/api/profile", HttpMethod::Post),
    ("/api/profile", HttpMethod::Put),
    ("/api/profile", HttpMethod::Patch),
    ("/api/set_mode", HttpMethod::Post),
    ("/api/set_profile", HttpMethod::Post),
    ("/v1/mode", HttpMethod::Post),
    ("/v1/profile", HttpMethod::Post),
];

/// Planned MCP tools (v2.8 N1): no mode/profile tools.
pub const MCP_TOOLS: &[&str] = &[
    "status",
    "read_fields",
    "plan_change",
    "submit_approval",
    "apply_plan",
    "list_backups",
    "backup_now",
];

pub const FORBIDDEN_MCP_TOOLS: &[&str] = &[
    "set_mode",
    "set_profile",
    "switch_mode",
    "switch_profile",
    "mode_set",
    "profile_set",
];

pub fn http_dispatch(method: HttpMethod, path: &str) -> HttpStatus {
    if FORBIDDEN_MODE_PROFILE_HTTP
        .iter()
        .any(|(p, m)| *p == path && *m == method)
    {
        return HttpStatus::NotFound;
    }
    if HTTP_ROUTES
        .iter()
        .any(|r| r.path == path && r.method == method)
    {
        return HttpStatus::Ok;
    }
    if HTTP_ROUTES.iter().any(|r| r.path == path) {
        return HttpStatus::MethodNotAllowed;
    }
    HttpStatus::NotFound
}

pub fn mcp_invoke(tool: &str) -> HttpStatus {
    if FORBIDDEN_MCP_TOOLS.contains(&tool) {
        return HttpStatus::NotFound;
    }
    if MCP_TOOLS.contains(&tool) {
        return HttpStatus::Ok;
    }
    HttpStatus::NotFound
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_http_route_changes_mode_or_profile() {
        for (path, method) in FORBIDDEN_MODE_PROFILE_HTTP {
            assert_eq!(
                http_dispatch(*method, path),
                HttpStatus::NotFound,
                "{method:?} {path}"
            );
        }
        for route in HTTP_ROUTES {
            assert!(
                !path_switches_mode_or_profile(route.path),
                "registered route must not switch mode/profile: {}",
                route.path
            );
        }
    }

    #[test]
    fn forbidden_http_paths_return_404_or_405() {
        assert_eq!(
            http_dispatch(HttpMethod::Get, "/api/mode"),
            HttpStatus::NotFound
        );
        assert_eq!(http_dispatch(HttpMethod::Post, "/api/plan"), HttpStatus::Ok);
        assert_eq!(
            http_dispatch(HttpMethod::Get, "/api/plan"),
            HttpStatus::MethodNotAllowed
        );
    }

    #[test]
    fn no_mcp_tool_changes_mode_or_profile() {
        for tool in FORBIDDEN_MCP_TOOLS {
            assert_eq!(mcp_invoke(tool), HttpStatus::NotFound);
        }
        for tool in MCP_TOOLS {
            assert!(
                !FORBIDDEN_MCP_TOOLS.contains(tool),
                "allowed tool must not be forbidden: {tool}"
            );
        }
    }

    fn path_switches_mode_or_profile(path: &str) -> bool {
        path.contains("mode") || path.contains("profile")
    }
}
