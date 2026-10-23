use askama::Template;

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub banner: String,
    pub show_error: bool,
    pub error: String,
    pub csrf_token: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub show_status: bool,
    pub profile: String,
    pub locked: bool,
    pub queue_depth: u32,
    pub show_plan: bool,
    pub plan_id_hex: String,
    pub diff_hash_hex: String,
    pub plan_summary: String,
    pub show_message: bool,
    pub message: String,
    pub csrf_token: String,
}

/// Reserved for per-plan approval links (login return flow not wired yet).
#[allow(dead_code)]
#[derive(Template)]
#[template(path = "approve.html")]
pub struct ApproveTemplate {
    pub plan_id_hex: String,
    pub diff_hash_hex: String,
    pub plan_summary: String,
    pub show_requested_by: bool,
    pub requested_by_agent: String,
    pub requested_by_token: String,
    pub csrf_token: String,
}

/// Reserved for expired approval windows (login return flow not wired yet).
#[allow(dead_code)]
#[derive(Template)]
#[template(path = "approval_expired.html")]
pub struct ApprovalExpiredTemplate {}
