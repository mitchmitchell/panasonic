use kxprov_api::{
    ApiError, ApplyApprovalRequiredResult, ApplyPlanAwaitingStatus, CallerIdentity, DaemonBackend,
    DiffHash, McpTokenIdentity, MockDaemon, Mode, PlanChangeRequest, Profile, Scope, ScopeSet,
    TokenId,
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

async fn enable_prod_live_writes(daemon: &MockDaemon) {
    daemon.test_set_live_writes_approved(true).await;
}

async fn submit_for_plan(daemon: &MockDaemon, plan: &kxprov_api::PlanSummary, profile: &Profile) {
    daemon
        .submit_approval(
            &approver(),
            &plan.plan_id.to_hex(),
            plan.diff_hash.clone(),
            profile,
        )
        .await
        .expect("submit");
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
async fn test_profile_apply_skips_prod_approval_gates() {
    let daemon = MockDaemon::with_mode(Mode::Production);
    let plan = sample_plan(&daemon).await;
    assert!(daemon
        .apply_plan(&comms(), plan.plan_id, plan.diff_hash)
        .await
        .is_ok());
}

#[tokio::test]
async fn prod_profile_apply_without_approval_returns_status_only() {
    let daemon = MockDaemon::with_profile(Profile::prod());
    enable_prod_live_writes(&daemon).await;
    let plan = sample_plan(&daemon).await;
    let err = daemon
        .apply_plan(&comms(), plan.plan_id, plan.diff_hash.clone())
        .await
        .expect_err("needs approval");
    assert!(matches!(
        err,
        ApiError::ApprovalRequired(ApplyApprovalRequiredResult {
            status: ApplyPlanAwaitingStatus::ApprovalRequired,
            ..
        })
    ));
}

#[tokio::test]
async fn prod_profile_blocks_writes_until_live_writes_gate() {
    let daemon = MockDaemon::with_profile(Profile::prod());
    let plan = sample_plan(&daemon).await;
    assert!(matches!(
        daemon
            .apply_plan(&comms(), plan.plan_id, plan.diff_hash)
            .await,
        Err(ApiError::LiveWritesBlocked)
    ));
}

#[tokio::test]
async fn submit_approval_then_apply_succeeds_on_prod_profile() {
    let daemon = MockDaemon::with_profile(Profile::prod());
    enable_prod_live_writes(&daemon).await;
    let plan = sample_plan(&daemon).await;
    assert!(matches!(
        daemon
            .apply_plan(&comms(), plan.plan_id.clone(), plan.diff_hash.clone())
            .await,
        Err(ApiError::ApprovalRequired(_))
    ));
    submit_for_plan(&daemon, &plan, &Profile::prod()).await;
    let job = daemon
        .apply_plan(&comms(), plan.plan_id, plan.diff_hash)
        .await
        .expect("apply");
    assert_eq!(job.state, kxprov_api::JobState::Succeeded);
}

#[tokio::test]
async fn submit_approval_accepts_eight_hex_prefix() {
    let daemon = MockDaemon::with_profile(Profile::prod());
    enable_prod_live_writes(&daemon).await;
    let plan = sample_plan(&daemon).await;
    let _ = daemon
        .apply_plan(&comms(), plan.plan_id.clone(), plan.diff_hash.clone())
        .await;
    let prefix = &plan.plan_id.to_hex()[..8];
    daemon
        .submit_approval(
            &approver(),
            prefix,
            plan.diff_hash.clone(),
            &Profile::prod(),
        )
        .await
        .expect("prefix submit");
}

#[tokio::test]
async fn submit_rejects_diff_hash_mismatch() {
    let daemon = MockDaemon::with_profile(Profile::prod());
    let plan = sample_plan(&daemon).await;
    assert!(matches!(
        daemon
            .submit_approval(
                &approver(),
                &plan.plan_id.to_hex(),
                DiffHash("0000000000000000000000000000000000000000000000000000000000000000".into()),
                &Profile::prod(),
            )
            .await,
        Err(ApiError::InvalidApproval)
    ));
}

#[tokio::test]
async fn submit_rejects_profile_mismatch() {
    let daemon = MockDaemon::with_profile(Profile::prod());
    let plan = sample_plan(&daemon).await;
    assert!(matches!(
        daemon
            .submit_approval(
                &approver(),
                &plan.plan_id.to_hex(),
                plan.diff_hash.clone(),
                &Profile::test(),
            )
            .await,
        Err(ApiError::BadRequest("profile mismatch"))
    ));
}

#[tokio::test]
async fn approver_cannot_approve_own_plan() {
    let daemon = MockDaemon::with_profile(Profile::prod());
    enable_prod_live_writes(&daemon).await;
    let solo = CallerIdentity::Mcp(McpTokenIdentity {
        token_id: TokenId("solo-token".into()),
        agent_name: "Solo".into(),
        scopes: ScopeSet::empty()
            .with(Scope::Read)
            .with(Scope::Plan)
            .with(Scope::Write),
    });
    let plan = daemon
        .plan_change(
            &solo,
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
    let _ = daemon
        .apply_plan(&solo, plan.plan_id.clone(), plan.diff_hash.clone())
        .await;
    let approver_same = CallerIdentity::Mcp(McpTokenIdentity {
        token_id: TokenId("solo-token".into()),
        agent_name: "SoloApprover".into(),
        scopes: ScopeSet::empty().with(Scope::Read).with(Scope::Approve),
    });
    assert!(matches!(
        daemon
            .submit_approval(
                &approver_same,
                &plan.plan_id.to_hex(),
                plan.diff_hash,
                &Profile::prod(),
            )
            .await,
        Err(ApiError::ApproverMustDiffer)
    ));
}

#[tokio::test]
async fn write_scope_cannot_submit_approval() {
    let daemon = MockDaemon::with_profile(Profile::prod());
    let plan = sample_plan(&daemon).await;
    assert!(matches!(
        daemon
            .submit_approval(
                &comms(),
                &plan.plan_id.to_hex(),
                plan.diff_hash.clone(),
                &Profile::prod(),
            )
            .await,
        Err(ApiError::ForbiddenScope)
    ));
}

#[tokio::test]
async fn approval_is_single_use_on_prod_profile() {
    let daemon = MockDaemon::with_profile(Profile::prod());
    enable_prod_live_writes(&daemon).await;
    let plan = sample_plan(&daemon).await;
    let _ = daemon
        .apply_plan(&comms(), plan.plan_id.clone(), plan.diff_hash.clone())
        .await;
    submit_for_plan(&daemon, &plan, &Profile::prod()).await;
    daemon
        .apply_plan(&comms(), plan.plan_id.clone(), plan.diff_hash.clone())
        .await
        .expect("first apply");
    assert!(matches!(
        daemon
            .apply_plan(&comms(), plan.plan_id, plan.diff_hash)
            .await,
        Err(ApiError::ApprovalRequired(_))
    ));
}

#[tokio::test]
async fn submit_approval_rate_limit() {
    let daemon = MockDaemon::with_profile(Profile::prod());
    enable_prod_live_writes(&daemon).await;
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
        let _ = daemon
            .apply_plan(&comms(), plan.plan_id.clone(), plan.diff_hash.clone())
            .await;
        daemon
            .submit_approval(
                &approver(),
                &plan.plan_id.to_hex(),
                plan.diff_hash,
                &Profile::prod(),
            )
            .await
            .expect("submit");
    }
    let plan = sample_plan(&daemon).await;
    assert!(matches!(
        daemon
            .submit_approval(
                &approver(),
                &plan.plan_id.to_hex(),
                plan.diff_hash,
                &Profile::prod(),
            )
            .await,
        Err(ApiError::ApprovalRateLimited)
    ));
}
