use kxprov_api::{
    ApplyApprovalRequiredResult, ApplyPlanAwaitingStatus, DiffHash, JobRef, PlanId, Profile,
    SubmitApprovalParams,
};

#[test]
fn apply_success_body_is_job_id_only() {
    let body = JobRef {
        job_id: "job-1".into(),
    };
    let value = serde_json::to_value(&body).unwrap();
    let obj = value.as_object().unwrap();
    assert_eq!(obj.len(), 1);
    assert_eq!(obj.get("job_id").unwrap(), "job-1");
}

#[test]
fn apply_approval_required_body_shape() {
    let body = ApplyApprovalRequiredResult {
        plan_id: PlanId::from_hex("00000000000000000000000000000001").unwrap(),
        diff_hash: DiffHash(
            "0101010101010101010101010101010101010101010101010101010101010101".into(),
        ),
        status: ApplyPlanAwaitingStatus::ApprovalRequired,
    };
    let value = serde_json::to_value(&body).unwrap();
    let obj = value.as_object().unwrap();
    assert_eq!(obj.len(), 3);
    assert_eq!(obj.get("status").unwrap(), "approval_required");
    assert_eq!(
        obj.get("plan_id").unwrap(),
        "00000000000000000000000000000001"
    );
    assert!(obj.get("diff_hash").is_some());
    assert!(obj.get("challenge").is_none());
    assert!(obj.get("summary").is_none());
}

#[test]
fn submit_approval_params_shape() {
    let params = SubmitApprovalParams {
        plan_id: "aabbccdd".into(),
        diff_hash: DiffHash(
            "0101010101010101010101010101010101010101010101010101010101010101".into(),
        ),
        profile: Profile::Prod,
    };
    let value = serde_json::to_value(&params).unwrap();
    let obj = value.as_object().unwrap();
    assert_eq!(obj.get("plan_id").unwrap(), "aabbccdd");
    assert_eq!(obj.get("profile").unwrap(), "prod");
}
