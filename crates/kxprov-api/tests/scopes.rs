use kxprov_api::{
    ApiError, CallerIdentity, DaemonBackend, DiffHash, McpTokenIdentity,
    MockDaemon, Mode, PlanChangeRequest, Scope, ScopeSet, TokenId,
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

fn approver() -> CallerIdentity {
    CallerIdentity::Mcp(McpTokenIdentity {
        token_id: TokenId("approver-token-id".into()),
        agent_name: "Approver".into(),
        scopes: ScopeSet::empty().with(Scope::Read).with(Scope::Approve),
    })
}

async fn sample_plan(daemon: &MockDaemon) -> kxprov_api::PlanSummary {
    daemon
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
        .expect("plan")
}

#[tokio::test]
async fn tester_cannot_apply_or_rollback() {
    let daemon = MockDaemon::new();
    let plan = sample_plan(&daemon).await;
    assert!(matches!(
        daemon
            .apply_plan(&tester(), plan.plan_id, plan.diff_hash)
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
async fn dry_run_apply_does_not_require_mcp_approval() {
    let daemon = MockDaemon::with_mode(Mode::DryRun);
    let plan = sample_plan(&daemon).await;
    assert!(daemon
        .apply_plan(&comms(), plan.plan_id, plan.diff_hash)
        .await
        .is_ok());
}

#[tokio::test]
async fn production_apply_without_approval_returns_challenge() {
    let daemon = MockDaemon::with_mode(Mode::Production);
    let plan = sample_plan(&daemon).await;
    let err = daemon
        .apply_plan(&comms(), plan.plan_id, plan.diff_hash.clone())
        .await
        .expect_err("needs approval");
    match err {
        ApiError::ApprovalRequired {
            summary, challenge, ..
        } => {
            assert!(summary.contains("→"));
            assert!(!challenge.0.is_empty());
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn submit_approval_then_apply_succeeds() {
    let daemon = MockDaemon::with_mode(Mode::Production);
    let plan = sample_plan(&daemon).await;
    let challenge = match daemon
        .apply_plan(&comms(), plan.plan_id, plan.diff_hash.clone())
        .await
        .expect_err("challenge")
    {
        ApiError::ApprovalRequired { challenge, .. } => challenge,
        other => panic!("expected approval required, got {other:?}"),
    };
    daemon
        .submit_approval(&approver(), plan.plan_id, plan.diff_hash.clone(), challenge)
        .await
        .expect("submit");
    let job = daemon
        .apply_plan(&comms(), plan.plan_id, plan.diff_hash)
        .await
        .expect("apply");
    assert_eq!(job.state, kxprov_api::JobState::Succeeded);
}

#[tokio::test]
async fn approver_cannot_approve_own_plan() {
    let daemon = MockDaemon::with_mode(Mode::Production);
    let approver_only = CallerIdentity::Mcp(McpTokenIdentity {
        token_id: TokenId("solo-approver".into()),
        agent_name: "Solo".into(),
        scopes: ScopeSet::empty()
            .with(Scope::Read)
            .with(Scope::Plan)
            .with(Scope::Write),
    });
    let plan = daemon
        .plan_change(
            &approver_only,
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
    let challenge = match daemon
        .apply_plan(&approver_only, plan.plan_id, plan.diff_hash.clone())
        .await
        .expect_err("need challenge")
    {
        ApiError::ApprovalRequired { challenge, .. } => challenge,
        other => panic!("expected approval required, got {other:?}"),
    };
    let approver_same = CallerIdentity::Mcp(McpTokenIdentity {
        token_id: TokenId("solo-approver".into()),
        agent_name: "SoloApprover".into(),
        scopes: ScopeSet::empty().with(Scope::Read).with(Scope::Approve),
    });
    assert!(matches!(
        daemon
            .submit_approval(&approver_same, plan.plan_id, plan.diff_hash, challenge)
            .await,
        Err(ApiError::ApproverMustDiffer)
    ));
}

#[tokio::test]
async fn write_scope_cannot_submit_approval() {
    let daemon = MockDaemon::with_mode(Mode::Production);
    let plan = sample_plan(&daemon).await;
    let challenge = match daemon
        .apply_plan(&comms(), plan.plan_id, plan.diff_hash.clone())
        .await
        .expect_err("challenge")
    {
        ApiError::ApprovalRequired { challenge, .. } => challenge,
        other => panic!("expected approval required, got {other:?}"),
    };
    assert!(matches!(
        daemon
            .submit_approval(&comms(), plan.plan_id, plan.diff_hash, challenge)
            .await,
        Err(ApiError::ForbiddenScope)
    ));
}

#[tokio::test]
async fn approval_is_single_use_in_production() {
    let daemon = MockDaemon::with_mode(Mode::Production);
    let plan = sample_plan(&daemon).await;
    let challenge = match daemon
        .apply_plan(&comms(), plan.plan_id, plan.diff_hash.clone())
        .await
        .expect_err("challenge")
    {
        ApiError::ApprovalRequired { challenge, .. } => challenge,
        other => panic!("expected approval required, got {other:?}"),
    };
    daemon
        .submit_approval(&approver(), plan.plan_id, plan.diff_hash.clone(), challenge)
        .await
        .expect("submit");
    daemon
        .apply_plan(&comms(), plan.plan_id, plan.diff_hash.clone())
        .await
        .expect("first apply");
    assert!(matches!(
        daemon
            .apply_plan(&comms(), plan.plan_id, plan.diff_hash)
            .await,
        Err(ApiError::ApprovalRequired { .. })
    ));
}

#[tokio::test]
async fn submit_approval_rate_limit() {
    let daemon = MockDaemon::with_mode(Mode::Production);
    for i in 0..kxprov_api::APPROVAL_SUBMIT_LIMIT_PER_HOUR {
        let plan = daemon
            .plan_change(
                &comms(),
                PlanChangeRequest {
                    table: 0x24,
                    record: i as u16 + 1,
                    field: "f".into(),
                    new_value: format!("v{i}"),
                    base_bytes: vec![],
                    new_bytes: vec![i as u8],
                },
            )
            .await
            .expect("plan");
        let challenge = match daemon
            .apply_plan(&comms(), plan.plan_id, plan.diff_hash.clone())
            .await
            .expect_err("challenge")
        {
            ApiError::ApprovalRequired { challenge, .. } => challenge,
            other => panic!("expected approval required, got {other:?}"),
        };
        daemon
            .submit_approval(&approver(), plan.plan_id, plan.diff_hash, challenge)
            .await
            .expect("submit");
    }
    let plan = sample_plan(&daemon).await;
    let challenge = match daemon
        .apply_plan(&comms(), plan.plan_id, plan.diff_hash.clone())
        .await
        .expect_err("challenge")
    {
        ApiError::ApprovalRequired { challenge, .. } => challenge,
        other => panic!("expected approval required, got {other:?}"),
    };
    assert!(matches!(
        daemon
            .submit_approval(&approver(), plan.plan_id, plan.diff_hash, challenge)
            .await,
        Err(ApiError::ApprovalRateLimited)
    ));
}

#[tokio::test]
async fn diff_hash_mismatch_rejects_submit() {
    let daemon = MockDaemon::with_mode(Mode::Production);
    let plan = sample_plan(&daemon).await;
    let challenge = match daemon
        .apply_plan(&comms(), plan.plan_id, plan.diff_hash.clone())
        .await
        .expect_err("challenge")
    {
        ApiError::ApprovalRequired { challenge, .. } => challenge,
        other => panic!("expected approval required, got {other:?}"),
    };
    assert!(matches!(
        daemon
            .submit_approval(&approver(), plan.plan_id, DiffHash([0u8; 32]), challenge)
            .await,
        Err(ApiError::InvalidApproval)
    ));
}
