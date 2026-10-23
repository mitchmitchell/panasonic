mod static_files;
mod templates;

use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::Router;
use kxprov_api::{
    ApiError, CallerIdentity, DaemonBackend, Mode, PlanChangeRequest, PlanSummary, WebAdminIdentity,
};
use serde::Deserialize;
use templates::DashboardTemplate;

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
        .with_state(state)
}

async fn static_file(Path(file): Path<String>) -> impl IntoResponse {
    serve_static(file).await
}

fn default_plan_form() -> (String, String, String, String) {
    ("36".into(), "1".into(), "name".into(), "test".into())
}

fn empty_dashboard(csrf: &str) -> DashboardTemplate {
    let (table_value, record_value, field_value, new_value_value) = default_plan_form();
    DashboardTemplate {
        show_mode_banner: false,
        mode_banner: String::new(),
        mode_banner_class: String::new(),
        show_profile_badge: false,
        profile_badge: String::new(),
        profile_badge_class: String::new(),
        show_status: false,
        locked: false,
        queue_depth: 0,
        table_value,
        record_value,
        field_value,
        new_value_value,
        show_plan_form_error: false,
        plan_form_error: String::new(),
        show_plan: false,
        plan_id_hex: String::new(),
        diff_hash_hex: String::new(),
        diff_hash_prefix: String::new(),
        plan_summary: String::new(),
        show_production_plan_hint: false,
        plan_expires_at: String::new(),
        csrf_token: csrf.to_string(),
    }
}

fn profile_badge_label(profile: &str) -> (String, String) {
    let trimmed = profile.trim();
    let class = trimmed.to_ascii_lowercase();
    (trimmed.to_ascii_uppercase(), class)
}

async fn fill_dashboard_from_status(
    tpl: &mut DashboardTemplate,
    state: &WebState,
    caller: &CallerIdentity,
) {
    if let Ok(status) = state.backend.status(caller).await {
        tpl.show_mode_banner = true;
        tpl.mode_banner = status.mode.banner_label().into();
        tpl.mode_banner_class = status.mode.banner_class().into();
        tpl.show_profile_badge = true;
        let (badge, badge_class) = profile_badge_label(&status.profile);
        tpl.profile_badge = badge;
        tpl.profile_badge_class = badge_class;
        tpl.show_status = true;
        tpl.locked = status.locked;
        tpl.queue_depth = status.queue_depth;
    }
}

fn apply_plan_result(tpl: &mut DashboardTemplate, summary: &PlanSummary, mode: Mode) {
    tpl.show_plan = true;
    tpl.plan_id_hex = summary.plan_id.to_hex();
    tpl.diff_hash_hex = summary.diff_hash.to_hex();
    tpl.plan_summary = summary.summary.clone();
    if mode == Mode::Production {
        let hex = summary.diff_hash.to_hex();
        tpl.diff_hash_prefix = hex.chars().take(8).collect();
        tpl.plan_expires_at = summary.expires_at.clone();
        tpl.show_production_plan_hint = true;
    }
}

fn plan_error_message(err: ApiError) -> String {
    match err {
        ApiError::ForbiddenScope => {
            "You don't have permission to create plans with this session.".into()
        }
        ApiError::BadRequest(field) => format!("Invalid input: {field}."),
        ApiError::PlanExpired => "That plan window has expired. Create a new plan.".into(),
        _ => "Could not create the plan. Check your entries and try again.".into(),
    }
}

async fn login_form() -> impl IntoResponse {
    Html(
        templates::LoginTemplate {
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

fn admin_caller(state: &WebState) -> CallerIdentity {
    CallerIdentity::WebAdmin(WebAdminIdentity {
        session_id: state.session_id.to_string(),
    })
}

async fn dashboard(State(state): State<WebState>) -> impl IntoResponse {
    let caller = admin_caller(&state);
    let mut tpl = empty_dashboard("");
    fill_dashboard_from_status(&mut tpl, &state, &caller).await;
    Html(tpl.render().unwrap_or_default())
}

fn parse_plan_form(form: &PlanForm) -> Result<(u8, u16, PlanChangeRequest), String> {
    let table_str = form.table.trim();
    let table = if let Some(hex) = table_str
        .strip_prefix("0x")
        .or_else(|| table_str.strip_prefix("0X"))
    {
        u8::from_str_radix(hex, 16).map_err(|_| "phone table must be a valid number".to_string())?
    } else {
        table_str
            .parse::<u8>()
            .map_err(|_| "phone table must be a valid number".to_string())?
    };
    let record = form
        .record
        .trim()
        .parse()
        .map_err(|_| "record number must be a valid integer".to_string())?;
    Ok((
        table,
        record,
        PlanChangeRequest {
            table,
            record,
            field: form.field.clone(),
            new_value: form.new_value.clone(),
            base_bytes: Vec::new(),
            new_bytes: Vec::new(),
        },
    ))
}

async fn plan_change(State(state): State<WebState>, Form(form): Form<PlanForm>) -> Html<String> {
    let caller = admin_caller(&state);
    let mut tpl = empty_dashboard("");
    tpl.table_value = form.table.clone();
    tpl.record_value = form.record.clone();
    tpl.field_value = form.field.clone();
    tpl.new_value_value = form.new_value.clone();
    fill_dashboard_from_status(&mut tpl, &state, &caller).await;

    let mode = state
        .backend
        .status(&caller)
        .await
        .map(|s| s.mode)
        .unwrap_or(Mode::Testing);

    let request = match parse_plan_form(&form) {
        Ok((_table, _record, req)) => req,
        Err(msg) => {
            tpl.show_plan_form_error = true;
            tpl.plan_form_error = msg;
            return Html(tpl.render().unwrap_or_default());
        }
    };

    match state.backend.plan_change(&caller, request).await {
        Ok(summary) => {
            apply_plan_result(&mut tpl, &summary, mode);
        }
        Err(err) => {
            tpl.show_plan_form_error = true;
            tpl.plan_form_error = plan_error_message(err);
        }
    }

    Html(tpl.render().unwrap_or_default())
}
