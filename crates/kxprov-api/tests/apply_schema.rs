use kxprov_api::{ApplyPlanAccepted, ApplyPlanApprovalRequired, DiffHash, JobId, PlanId};

#[test]
fn apply_success_body_is_job_id_only() {
    let body = ApplyPlanAccepted {
        job_id: JobId("job-1".into()),
    };
    let value = serde_json::to_value(&body).unwrap();
    let obj = value.as_object().unwrap();
    assert_eq!(obj.len(), 1);
    assert_eq!(obj.get("job_id").unwrap(), "job-1");
}

#[test]
fn apply_approval_required_body_shape() {
    let body = ApplyPlanApprovalRequired {
        plan_id: PlanId::from_hex("00000000000000000000000000000001").unwrap(),
        diff_hash: DiffHash([1u8; 32]),
        status: "approval_required".into(),
    };
    let value = serde_json::to_value(&body).unwrap();
    let obj = value.as_object().unwrap();
    assert_eq!(obj.len(), 3);
    assert_eq!(obj.get("status").unwrap(), "approval_required");
    assert!(obj.get("plan_id").is_some());
    assert!(obj.get("diff_hash").is_some());
    assert!(obj.get("challenge").is_none());
    assert!(obj.get("summary").is_none());
}
