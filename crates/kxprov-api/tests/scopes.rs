use kxprov_api::{
    ApiError, CallerIdentity, DaemonBackend, DiffHash, McpTokenIdentity, MockDaemon,
    PlanChangeRequest, Scope, ScopeSet, TokenId, WebAdminIdentity,
};

fn tester() -> CallerIdentity {
    CallerIdentity::Mcp(McpTokenIdentity {
        token_id: TokenId("tester-token-id".into()),
        agent_name: "Tester".into(),
        scopes: ScopeSet::empty().with(Scope::Read).with(Scope::Plan),
    })
}

fn comms() -> CallerIdentity {
    CallerIdentity::Mcp(McpTokenIdentity {
        token_id: TokenId("comms-token-id".into()),
        agent_name: "Communications".into(),
        scopes: ScopeSet::empty()
            .with(Scope::Read)
            .with(Scope::Plan)
            .with(Scope::Write),
    })
}

fn admin(session: &str) -> CallerIdentity {
    CallerIdentity::WebAdmin(WebAdminIdentity {
        session_id: session.into(),
    })
}

#[tokio::test]
async fn tester_cannot_apply_or_rollback() {
    let daemon = MockDaemon::new();
    let plan = daemon
        .plan_change(
            &tester(),
            PlanChangeRequest {
                table: 0x24,
                record: 1,
                field: "name".into(),
                new_value: "x".into(),
                base_bytes: vec![1, 2],
                new_bytes: vec![3, 4],
            },
        )
        .await
        .expect("plan");
    assert!(matches!(
        daemon
            .apply_plan(&tester(), plan.plan_id, plan.diff_hash)
            .await,
        Err(ApiError::ForbiddenScope)
    ));
    assert!(matches!(
        daemon
            .rollback(&tester(), kxprov_api::JobId("job-1".into()))
            .await,
        Err(ApiError::ForbiddenScope)
    ));
}

#[tokio::test]
async fn backup_now_requires_plan_scope() {
    let daemon = MockDaemon::new();
    assert!(daemon.backup_now(&comms()).await.is_ok());
}

#[tokio::test]
async fn apply_without_approval_returns_required() {
    let daemon = MockDaemon::new();
    let plan = daemon
        .plan_change(
            &comms(),
            PlanChangeRequest {
                table: 0x24,
                record: 1,
                field: "name".into(),
                new_value: "y".into(),
                base_bytes: vec![],
                new_bytes: vec![9],
            },
        )
        .await
        .expect("plan");
    assert!(matches!(
        daemon
            .apply_plan(&comms(), plan.plan_id, plan.diff_hash.clone())
            .await,
        Err(ApiError::ApprovalRequired { .. })
    ));
}

#[tokio::test]
async fn apply_after_daemon_minted_approval_succeeds() {
    let daemon = MockDaemon::new();
    let plan = daemon
        .plan_change(
            &comms(),
            PlanChangeRequest {
                table: 0x25,
                record: 2,
                field: "num".into(),
                new_value: "9".into(),
                base_bytes: vec![0],
                new_bytes: vec![9],
            },
        )
        .await
        .expect("plan");
    daemon
        .mint_plan_approval(
            &admin("s1"),
            plan.plan_id,
            plan.diff_hash.clone(),
            "test-admin-password",
        )
        .await
        .expect("mint");
    let job = daemon
        .apply_plan(&comms(), plan.plan_id, plan.diff_hash.clone())
        .await
        .expect("apply");
    assert_eq!(job.state, kxprov_api::JobState::Succeeded);
}

#[tokio::test]
async fn approval_is_single_use() {
    let daemon = MockDaemon::new();
    let plan = daemon
        .plan_change(
            &comms(),
            PlanChangeRequest {
                table: 0x24,
                record: 1,
                field: "f".into(),
                new_value: "v".into(),
                base_bytes: vec![],
                new_bytes: vec![1],
            },
        )
        .await
        .expect("plan");
    daemon
        .mint_plan_approval(
            &admin("s"),
            plan.plan_id,
            plan.diff_hash.clone(),
            "test-admin-password",
        )
        .await
        .expect("mint");
    daemon
        .apply_plan(&comms(), plan.plan_id, plan.diff_hash.clone())
        .await
        .expect("first");
    assert!(matches!(
        daemon
            .apply_plan(&comms(), plan.plan_id, plan.diff_hash)
            .await,
        Err(ApiError::ApprovalRequired { .. })
    ));
}

#[tokio::test]
async fn mcp_cannot_mint_approvals() {
    let daemon = MockDaemon::new();
    let plan = daemon
        .plan_change(
            &comms(),
            PlanChangeRequest {
                table: 0x24,
                record: 1,
                field: "f".into(),
                new_value: "v".into(),
                base_bytes: vec![],
                new_bytes: vec![2],
            },
        )
        .await
        .expect("plan");
    assert!(matches!(
        daemon
            .mint_plan_approval(&comms(), plan.plan_id, plan.diff_hash, "nope")
            .await,
        Err(ApiError::ForbiddenAdmin)
    ));
}

#[tokio::test]
async fn diff_hash_mismatch_rejects_mint() {
    let daemon = MockDaemon::new();
    let plan = daemon
        .plan_change(
            &comms(),
            PlanChangeRequest {
                table: 0x24,
                record: 1,
                field: "f".into(),
                new_value: "v".into(),
                base_bytes: vec![],
                new_bytes: vec![3],
            },
        )
        .await
        .expect("plan");
    assert!(matches!(
        daemon
            .mint_plan_approval(
                &admin("s"),
                plan.plan_id,
                DiffHash([0u8; 32]),
                "test-admin-password"
            )
            .await,
        Err(ApiError::InvalidApproval)
    ));
}
