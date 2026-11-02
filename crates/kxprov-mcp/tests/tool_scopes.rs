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

#[test]
fn bots_list_is_exactly_the_read_and_call_log_tools() {
    let server = KxMcpServer::new(std::sync::Arc::new(kxprov_mock::MockDaemon::default()));
    let bots = scopes_for_role("bots");
    let mut listed: Vec<String> = server
        .registered_tool_names()
        .into_iter()
        .filter(|t| KxMcpServer::tool_visible_for_scopes(t, &bots))
        .collect();
    listed.sort();
    assert_eq!(
        listed,
        [
            "list_backups",
            "read_fields",
            "smdr_query",
            "smdr_status",
            "status"
        ]
    );
}

#[test]
fn tester_sees_smdr_query_on_sim_only() {
    use kxprov_api::Profile;
    use kxprov_mock::scopes_for_role_on;
    assert!(KxMcpServer::tool_visible_for_scopes(
        "smdr_query",
        &scopes_for_role_on("tester", Profile::Sim)
    ));
    for p in [Profile::Test, Profile::Prod] {
        assert!(!KxMcpServer::tool_visible_for_scopes(
            "smdr_query",
            &scopes_for_role_on("tester", p)
        ));
    }
}
