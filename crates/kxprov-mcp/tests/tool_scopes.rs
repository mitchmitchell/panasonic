use kxprov_api::Scope;
use kxprov_mcp::KxMcpServer;
use kxprov_mock::{scopes_for_role, ScopeSet};

#[test]
fn tester_list_excludes_write_and_approve_tools() {
    let scopes = scopes_for_role("tester");
    assert!(KxMcpServer::tool_visible_for_scopes("status", &scopes));
    assert!(KxMcpServer::tool_visible_for_scopes("plan_change", &scopes));
    assert!(!KxMcpServer::tool_visible_for_scopes("apply_plan", &scopes));
    assert!(!KxMcpServer::tool_visible_for_scopes("rollback", &scopes));
    assert!(!KxMcpServer::tool_visible_for_scopes(
        "submit_approval",
        &scopes
    ));
}

#[test]
fn communications_list_includes_write_not_approve() {
    let scopes = scopes_for_role("communications");
    assert!(KxMcpServer::tool_visible_for_scopes("apply_plan", &scopes));
    assert!(!KxMcpServer::tool_visible_for_scopes(
        "submit_approval",
        &scopes
    ));
}

#[test]
fn approver_list_includes_approve_only_among_mutators() {
    let scopes = scopes_for_role("approver");
    assert!(KxMcpServer::tool_visible_for_scopes(
        "submit_approval",
        &scopes
    ));
    assert!(!KxMcpServer::tool_visible_for_scopes("apply_plan", &scopes));
    assert!(!KxMcpServer::tool_visible_for_scopes(
        "plan_change",
        &scopes
    ));
}

#[test]
fn empty_scopes_hide_all_tools() {
    let scopes = ScopeSet::empty();
    for name in [
        "status",
        "read_fields",
        "plan_change",
        "apply_plan",
        "submit_approval",
    ] {
        assert!(
            !KxMcpServer::tool_visible_for_scopes(name, &scopes),
            "{name} should be hidden"
        );
    }
}

#[test]
fn read_only_custom_scope_sees_status_not_plan() {
    let scopes = ScopeSet::empty().with(Scope::Read);
    assert!(KxMcpServer::tool_visible_for_scopes("status", &scopes));
    assert!(!KxMcpServer::tool_visible_for_scopes(
        "plan_change",
        &scopes
    ));
}
