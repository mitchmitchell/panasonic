mod redirect;
mod session_auth;
mod static_files;
mod templates;

use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use kxprov_api::{
    ApiError, CallerIdentity, DaemonBackend, DiffHash, PlanChangeRequest, PlanId, WebAdminIdentity,
};
use redirect::{login_url_with_next, validate_return_path};
use serde::Deserialize;
use session_auth::{admin_session_id, clear_authenticated, is_authenticated, set_authenticated};
use templates::{ApprovalExpiredTemplate, ApproveTemplate, DashboardTemplate, LoginTemplate};
use tower_sessions::Session;

pub use static_files::serve_static;

#[derive(Clone)]
pub struct WebState {
    pub backend: Arc<dyn DaemonBackend>,
}

pub fn router(state: WebState) -> Router {
    Router::new()
        .route("/static/{file}", get(static_file))
        .route("/login", get(login_form).post(login_submit))
        .route("/logout", post(logout))
        .route("/", get(dashboard))
        .route("/plan", post(plan_change))
        .route("/plans/{plan_id}/approve", get(approve_page))
        .route("/approve-plan", post(approve_plan))
        .route("/apply", post(apply_plan))
        .with_state(state)
}

pub async fn rate_limit_key_for_session(session: &Session) -> String {
    if is_authenticated(session).await {
        format!("web-admin:{}", admin_session_id(session))
    } else {
        "web-guest".into()
    }
}

async fn static_file(Path(file): Path<String>) -> impl IntoResponse {
    serve_static(file).await
}

#[derive(Deserialize)]
struct LoginQuery {
    next: Option<String>,
}

async fn login_form(Query(query): Query<LoginQuery>) -> impl IntoResponse {
    let next_path = query
        .next
        .as_deref()
        .and_then(validate_return_path)
        .unwrap_or_else(|| "/".into());
    Html(
        LoginTemplate {
            banner: "Simulator profile".into(),
            show_error: false,
            error: String::new(),
            csrf_token: String::new(),
            next_path,
        }
        .render()
        .unwrap_or_default(),
    )
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
    next: String,
    #[serde(rename = "_csrf")]
    _csrf: String,
}

async fn login_submit(
    State(state): State<WebState>,
    session: Session,
    Form(form): Form<LoginForm>,
) -> Result<Response, StatusCode> {
    if !state.backend.verify_admin_password(&form.password) {
        return Ok(Html(
            LoginTemplate {
                banner: "Simulator profile".into(),
                show_error: true,
                error: "Invalid password".into(),
                csrf_token: String::new(),
                next_path: validate_return_path(&form.next).unwrap_or_else(|| "/".into()),
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response());
    }
    set_authenticated(&session).await;
    let dest = validate_return_path(&form.next).unwrap_or_else(|| "/".into());
    Ok(Redirect::to(&dest).into_response())
}

async fn logout(session: Session) -> impl IntoResponse {
    clear_authenticated(&session).await;
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

#[derive(Deserialize)]
struct ApproveQuery {
    diff: String,
}

fn admin_caller(session: &Session) -> CallerIdentity {
    CallerIdentity::WebAdmin(WebAdminIdentity {
        session_id: admin_session_id(session),
    })
}

async fn ensure_authenticated(session: &Session, return_path: &str) -> Result<(), Redirect> {
    if is_authenticated(session).await {
        Ok(())
    } else {
        Err(Redirect::to(&login_url_with_next(return_path)))
    }
}

async fn dashboard(
    State(state): State<WebState>,
    session: Session,
) -> Result<impl IntoResponse, Redirect> {
    ensure_authenticated(&session, "/").await?;
    let caller = admin_caller(&session);
    let mut tpl = empty_dashboard("");
    if let Ok(status) = state.backend.status(&caller).await {
        tpl.show_status = true;
        tpl.profile = status.profile;
        tpl.locked = status.locked;
        tpl.queue_depth = status.queue_depth;
    }
    Ok(Html(tpl.render().unwrap_or_default()))
}

async fn approve_page(
    State(state): State<WebState>,
    session: Session,
    Path(plan_id_hex): Path<String>,
    Query(query): Query<ApproveQuery>,
) -> Result<impl IntoResponse, Redirect> {
    let return_path = format!("/plans/{plan_id_hex}/approve?diff={}", query.diff);
    ensure_authenticated(&session, &return_path).await?;
    let caller = admin_caller(&session);
    let plan_id = match PlanId::from_hex(&plan_id_hex) {
        Ok(id) => id,
        Err(_) => return Err(Redirect::to("/")),
    };
    let diff_hash = match DiffHash::from_hex(&query.diff) {
        Ok(h) => h,
        Err(_) => return Err(Redirect::to("/")),
    };
    match state.backend.get_plan(&caller, plan_id, diff_hash).await {
        Ok(summary) => {
            let (show_requested, agent, token) = match summary.requested_by {
                Some(r) => (true, r.agent, r.token_id.0),
                None => (false, String::new(), String::new()),
            };
            Ok(Html(
                ApproveTemplate {
                    plan_id_hex: summary.plan_id.to_hex(),
                    diff_hash_hex: summary.diff_hash.to_hex(),
                    plan_summary: summary.summary,
                    show_requested_by: show_requested,
                    requested_by_agent: agent,
                    requested_by_token: token,
                    csrf_token: String::new(),
                }
                .render()
                .unwrap_or_default(),
            ))
        }
        Err(ApiError::PlanExpired) => Ok(Html(
            ApprovalExpiredTemplate {}.render().unwrap_or_default(),
        )),
        Err(_) => Err(Redirect::to("/")),
    }
}

async fn plan_change(
    State(state): State<WebState>,
    session: Session,
    Form(form): Form<PlanForm>,
) -> Result<Html<String>, StatusCode> {
    if !is_authenticated(&session).await {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let table = u8::from_str_radix(form.table.trim_start_matches("0x"), 16)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let record = form.record.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let caller = admin_caller(&session);
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
    session: Session,
    Form(form): Form<ApproveForm>,
) -> Result<Html<String>, StatusCode> {
    if !is_authenticated(&session).await {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let caller = admin_caller(&session);
    let plan_id = PlanId::from_hex(&form.plan_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let diff_hash = DiffHash::from_hex(&form.diff_hash).map_err(|_| StatusCode::BAD_REQUEST)?;
    match state
        .backend
        .mint_plan_approval(&caller, plan_id, diff_hash, &form.password)
        .await
    {
        Ok(_) => {
            let mut tpl = empty_dashboard("");
            tpl.show_message = true;
            tpl.message = "Approval minted (10 min, single-use)".into();
            Ok(Html(tpl.render().unwrap_or_default()))
        }
        Err(ApiError::PlanExpired) => Ok(Html(
            ApprovalExpiredTemplate {}.render().unwrap_or_default(),
        )),
        Err(_) => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn apply_plan(
    State(state): State<WebState>,
    session: Session,
    Form(form): Form<ApplyForm>,
) -> Result<Html<String>, StatusCode> {
    if !is_authenticated(&session).await {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let caller = admin_caller(&session);
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
