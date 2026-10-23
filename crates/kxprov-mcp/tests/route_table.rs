use std::sync::Arc;

use kxprov_mock::{mcp_tool_mutates_mode_or_profile, MockDaemon, MCP_TOOLS};
use kxprov_mcp::KxMcpServer;

#[test]
fn registered_mcp_tools_match_canonical_table() {
    let server = KxMcpServer::new(Arc::new(MockDaemon::new()));
    let mut names = server.registered_tool_names();
    names.sort();
    let mut expected: Vec<String> = MCP_TOOLS.iter().map(|s| (*s).to_string()).collect();
    expected.sort();
    assert_eq!(names, expected);
}

#[test]
fn mcp_tools_do_not_mutate_mode_or_profile() {
    let server = KxMcpServer::new(Arc::new(MockDaemon::new()));
    for name in server.registered_tool_names() {
        assert!(
            !mcp_tool_mutates_mode_or_profile(&name),
            "tool {name} must not change mode or profile"
        );
    }
}
