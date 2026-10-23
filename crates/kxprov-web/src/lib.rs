mod static_files;
mod templates;

use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::Router;
use kxprov_api::{
    CallerIdentity, DaemonBackend, DiffHash, PlanChangeRequest, PlanId, WebAdminIdentity,
};
use serde::Deserialize;
use templates::{DashboardTemplate, LoginTemplate};

pub use static_files::serve_static;

#[derive(Clone)]
pub struct WebState {
    pub backend: Arc<dyn DaemonBackend>,
    pub session_id: Arc<str>,
}

pub fn router(state: WebState) -> Router {
    Router::new()
        .route("/static/{file}", get(static_file))
        .route("/login", get(login_form).post(login_submit))
        .route("/logout", post(logout))
        .route("/", get(dashboard))
        .route("/plan", post(plan_change))
        .route("/approve-plan", post(approve_plan))
        .route("/apply", post(apply_plan))
        .with_state(state)
}

async fn static_file(Path(file): Path<String>) -> impl IntoResponse {
    serve_static(file).await
}

fn empty_dashboard(csrf: &str) -> DashboardTemplate {
    DashboardTemplate {
        show_status: false,
        profile: String::new(),
        locked: false,
        queue_depth: 0,
        show_plan: false,
        plan_id_hex: String::new(),
        diff_hash_hex: String::new(),
        plan_summary: String::new(),
        show_message: false,
        message: String::new(),
        csrf_token: csrf.to_string(),
    }
}

async fn login_form() -> impl IntoResponse {
    Html(
        LoginTemplate {
            banner: "Simulator profile".into(),
            show_error: false,
            error: String::new(),
            csrf_token: String::new(),
        }
        .render()
        .unwrap_or_default(),
    )
}

#[derive(Deserialize)]
struct LoginForm {
    #[serde(rename = "password")]
    _password: String,
    #[serde(rename = "_csrf")]
    _csrf: String,
}

async fn login_submit() -> impl IntoResponse {
    Redirect::to("/")
}

async fn logout() -> impl IntoResponse {
    Redirect::to("/login")
}

#[derive(Deserialize)]
pub struct PlanForm {
    table: String,
    record: String,
    field: String,
    new_value: String,
    #[serde(rename = "_csrf")]
    pub _csrf: String,
}

#[derive(Deserialize)]
pub struct ApproveForm {
    plan_id: String,
    diff_hash: String,
    password: String,
    #[serde(rename = "_csrf")]
    pub _csrf: String,
}

#[derive(Deserialize)]
pub struct ApplyForm {
    plan_id: String,
    diff_hash: String,
    #[serde(rename = "_csrf")]
    pub _csrf: String,
}

fn admin_caller(state: &WebState) -> CallerIdentity {
    CallerIdentity::WebAdmin(WebAdminIdentity {
        session_id: state.session_id.to_string(),
    })
}

async fn dashboard(State(state): State<WebState>) -> impl IntoResponse {
    let caller = admin_caller(&state);
    let mut tpl = empty_dashboard("");
    if let Ok(status) = state.backend.status(&caller).await {
        tpl.show_status = true;
        tpl.profile = status.profile;
        tpl.locked = status.locked;
        tpl.queue_depth = status.queue_depth;
    }
    Html(tpl.render().unwrap_or_default())
}

async fn plan_change(
    State(state): State<WebState>,
    Form(form): Form<PlanForm>,
) -> Result<Html<String>, StatusCode> {
    let table = u8::from_str_radix(form.table.trim_start_matches("0x"), 16)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let record = form.record.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let caller = admin_caller(&state);
    let summary = state
        .backend
        .plan_change(
            &caller,
            PlanChangeRequest {
                table,
                record,
                field: form.field,
                new_value: form.new_value,
                base_bytes: Vec::new(),
                new_bytes: Vec::new(),
            },
        )
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let mut tpl = empty_dashboard("");
    if let Ok(status) = state.backend.status(&caller).await {
        tpl.show_status = true;
        tpl.profile = status.profile;
        tpl.locked = status.locked;
        tpl.queue_depth = status.queue_depth;
    }
    tpl.show_plan = true;
    tpl.plan_id_hex = summary.plan_id.to_hex();
    tpl.diff_hash_hex = summary.diff_hash.to_hex();
    tpl.plan_summary = summary.summary;
    Ok(Html(tpl.render().unwrap_or_default()))
}

async fn approve_plan(
    State(state): State<WebState>,
    Form(form): Form<ApproveForm>,
) -> Result<Html<String>, StatusCode> {
    let caller = admin_caller(&state);
    let plan_id = PlanId::from_hex(&form.plan_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let diff_hash = DiffHash::from_hex(&form.diff_hash).map_err(|_| StatusCode::BAD_REQUEST)?;
    state
        .backend
        .mint_plan_approval(&caller, plan_id, diff_hash, &form.password)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let mut tpl = empty_dashboard("");
    tpl.show_message = true;
    tpl.message = "Approval minted (10 min, single-use)".into();
    Ok(Html(tpl.render().unwrap_or_default()))
}

async fn apply_plan(
    State(state): State<WebState>,
    Form(form): Form<ApplyForm>,
) -> Result<Html<String>, StatusCode> {
    let caller = admin_caller(&state);
    let plan_id = PlanId::from_hex(&form.plan_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let diff_hash = DiffHash::from_hex(&form.diff_hash).map_err(|_| StatusCode::BAD_REQUEST)?;
    let job = state
        .backend
        .apply_plan(&caller, plan_id, diff_hash)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut tpl = empty_dashboard("");
    tpl.show_message = true;
    tpl.message = format!("Apply job {}: {}", job.job_id.0, job.message);
    Ok(Html(tpl.render().unwrap_or_default()))
}
