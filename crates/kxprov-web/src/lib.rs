mod csrf;
mod expiry;
mod fields;
mod login_client;
mod login_limit;
mod session;
mod static_files;
mod templates;

use askama::Template;
use axum::extract::{ConnectInfo, Extension, Form, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use kxprov_api::{OperationalMode, Profile};
use kxprov_mock::{
    BackendError, CallerIdentity, DaemonBackend, PlanChangeRequest, PlanSummary, ReadFieldsRequest,
    WebSessionIdentity,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use templates::{DashboardTemplate, ReadFieldRow};
use tower_sessions::Session;

pub use login_client::{login_rate_ip_key, ServeProxyTrusted, WebConnectInfo};
pub use login_limit::{LoginGateError, LoginPrecheck, LoginRateLimiter};

/// Set by the gateway per listener: trust `X-Forwarded-For` only on Tailscale Serve fronted binds.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClientIpPolicy {
    pub trust_x_forwarded_for: bool,
}
pub use session::{
    absolute_session_valid, enforce_absolute_session_limit, is_n1_unregistered_web_path,
    now_unix_ms, reject_authenticated_login, require_web_session, SESSION_AUTH_KEY,
    SESSION_STARTED_MS_KEY, WEB_SESSION_ABSOLUTE_SECS, WEB_SESSION_IDLE_SECS,
};
pub use static_files::serve_static;

pub trait PasswordVerifier: Send + Sync {
    fn verify(&self, password: &str) -> bool;
}

#[derive(Clone)]
pub struct WebState {
    pub backend: Arc<dyn DaemonBackend>,
    pub admin: Arc<dyn PasswordVerifier>,
    pub login_limiter: Arc<crate::login_limit::LoginRateLimiter>,
}

pub fn sign_in_page_title() -> &'static str {
    "Sign in"
}

pub fn router(state: WebState) -> Router {
    Router::new()
        .route("/static/{file}", get(static_file))
        .route("/login", get(login_form).post(login_submit))
        .route("/logout", post(logout))
        .route("/", get(dashboard))
        .route("/status", get(dashboard))
        .route("/read", post(read_record))
        .route("/plan", post(plan_change))
        .route("/api/plan", post(plan_change))
        .with_state(state)
}

async fn static_file(Path(file): Path<String>) -> impl IntoResponse {
    serve_static(file).await
}

pub fn operational_mode_banner_label(mode: OperationalMode) -> &'static str {
    match mode {
        OperationalMode::Testing => "TESTING",
        OperationalMode::Production => "PRODUCTION",
    }
}

pub fn operational_mode_banner_class(mode: OperationalMode) -> &'static str {
    match mode {
        OperationalMode::Testing => "testing",
        OperationalMode::Production => "production",
    }
}

fn default_plan_form() -> (String, String, String, String) {
    (
        "36".into(),
        "1".into(),
        "cid_number".into(),
        "5550100".into(),
    )
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
        show_read_form_error: false,
        read_form_error: String::new(),
        show_read_result: false,
        read_table: 0,
        read_record: 0,
        read_fields: Vec::new(),
        show_plan_form_error: false,
        plan_form_error: String::new(),
        show_plan: false,
        plan_id_hex: String::new(),
        diff_hash_hex: String::new(),
        plan_id_prefix: String::new(),
        plan_summary: String::new(),
        plan_table: 0,
        plan_record: 0,
        plan_field: String::new(),
        plan_old_value: String::new(),
        plan_new_value: String::new(),
        show_production_plan_hint: false,
        plan_expires_at_iso: String::new(),
        plan_expires_at_chicago: String::new(),
        plan_expires_at_ms: String::new(),
        csrf_token: csrf.to_string(),
    }
}

fn profile_badge_label(profile: Profile) -> (String, String) {
    let wire = serde_json::to_string(&profile).unwrap_or_else(|_| "\"test\"".into());
    let trimmed = wire.trim_matches('"');
    (trimmed.to_ascii_uppercase(), trimmed.to_string())
}

async fn fill_dashboard_from_status(
    tpl: &mut DashboardTemplate,
    state: &WebState,
    caller: &CallerIdentity,
) {
    if let Ok(status) = state.backend.status(caller).await {
        tpl.show_mode_banner = true;
        tpl.mode_banner = operational_mode_banner_label(status.operational_mode).into();
        tpl.mode_banner_class = operational_mode_banner_class(status.operational_mode).into();
        tpl.show_profile_badge = true;
        let (badge, badge_class) = profile_badge_label(status.profile);
        tpl.profile_badge = badge;
        tpl.profile_badge_class = badge_class;
        tpl.show_status = true;
        tpl.locked = status.locked;
        tpl.queue_depth = status.queue_depth;
    }
}

fn apply_plan_result(tpl: &mut DashboardTemplate, summary: &PlanSummary, mode: OperationalMode) {
    tpl.show_plan = true;
    tpl.plan_id_hex = summary.plan_id.0.clone();
    tpl.diff_hash_hex = summary.diff_hash.0.clone();
    tpl.plan_summary = summary.summary.clone();
    tpl.plan_table = summary.table;
    tpl.plan_record = summary.record;
    tpl.plan_field = summary.field.clone();
    tpl.plan_old_value = summary.old_value.clone();
    tpl.plan_new_value = summary.new_value.clone();
    if mode == OperationalMode::Production {
        tpl.plan_id_prefix = summary.plan_id.0.chars().take(8).collect();
        tpl.plan_expires_at_iso = summary.expires_at.clone();
        tpl.plan_expires_at_chicago = expiry::format_expiry_chicago(&summary.expires_at);
        tpl.plan_expires_at_ms = expiry::expiry_unix_ms(&summary.expires_at)
            .map(|ms| ms.to_string())
            .unwrap_or_default();
        tpl.show_production_plan_hint = true;
    }
}

fn plan_error_message(err: BackendError) -> String {
    match err {
        BackendError::ForbiddenScope => {
            "You don't have permission to create plans with this session.".into()
        }
        BackendError::BadRequest(field) => match field {
            "field" => "That field is not valid for the phone table you chose.".into(),
            other => format!("Invalid input: {other}."),
        },
        BackendError::PlanExpired => "That plan window has expired. Create a new plan.".into(),
        _ => "Could not create the plan. Check your entries and try again.".into(),
    }
}

fn read_error_message(err: BackendError) -> String {
    match err {
        BackendError::ForbiddenScope => {
            "You don't have permission to read phone data with this session.".into()
        }
        BackendError::BadRequest(field) => format!("Invalid input: {field}."),
        _ => "Could not read that record. Check your entries and try again.".into(),
    }
}

fn caller_from_session(session: &Session) -> CallerIdentity {
    let session_key = session.id().map(|id| id.to_string()).unwrap_or_default();
    CallerIdentity::Web(WebSessionIdentity { session_key })
}

/// Display / audit client IP (last XFF hop when trusted Serve proxy, else socket peer).
pub fn client_ip(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trust_x_forwarded_for: bool,
    serve_proxy_trusted: bool,
) -> String {
    let peer = peer.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
    if trust_x_forwarded_for && serve_proxy_trusted {
        if let Some(ip) = login_client::x_forwarded_for_last(headers) {
            return ip.to_string();
        }
    }
    peer.ip().to_string()
}

fn login_rate_limited_response(message: &str, retry_after: std::time::Duration) -> Response {
    let secs = retry_after.as_secs().max(1);
    let mut resp = (StatusCode::TOO_MANY_REQUESTS, message.to_string()).into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&secs.to_string()) {
        resp.headers_mut()
            .insert(axum::http::header::RETRY_AFTER, value);
    }
    resp
}

async fn login_form(session: Session) -> impl IntoResponse {
    let token = csrf::token_for_session(&session).await;
    let cookie = csrf::csrf_set_cookie_value(&token);
    (
        [(header::SET_COOKIE, cookie)],
        Html(
            templates::LoginTemplate {
                page_title: sign_in_page_title().into(),
                show_error: false,
                error: String::new(),
                csrf_token: token,
            }
            .render()
            .unwrap_or_default(),
        ),
    )
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
    #[serde(default, rename = "_csrf")]
    _csrf: String,
}

#[derive(Deserialize)]
struct LogoutForm {
    #[serde(default, rename = "_csrf")]
    _csrf: String,
}

async fn login_submit(
    State(state): State<WebState>,
    session: Session,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    connect: Option<Extension<WebConnectInfo>>,
    policy: Option<Extension<ClientIpPolicy>>,
    Form(form): Form<LoginForm>,
) -> Response {
    if let Some(resp) = csrf::verify_form_csrf(&session, &headers, &form._csrf).await {
        return resp;
    }
    let trust = policy
        .as_ref()
        .map(|Extension(p)| p.trust_x_forwarded_for)
        .unwrap_or(false);
    let WebConnectInfo {
        remote: peer,
        serve_proxy_trusted,
    } = connect
        .map(|Extension(info)| info)
        .unwrap_or_else(|| WebConnectInfo::from_parts(peer, false));
    let ip_key = login_rate_ip_key(&headers, peer, trust, serve_proxy_trusted);
    let session_prior_ip_key = session
        .get::<String>(crate::session::SESSION_LOGIN_IP_KEY)
        .await
        .ok()
        .flatten();
    let acct_key = "acct:admin".to_string();
    match state.login_limiter.precheck_login(&acct_key, &ip_key).await {
        LoginPrecheck::IpRateLimited(delay) => {
            return login_rate_limited_response(
                "Too many login attempts from this address. Try again later.",
                delay,
            );
        }
        LoginPrecheck::Ready => {}
    }
    let outcome = state
        .login_limiter
        .enter_account_login(
            &acct_key,
            &ip_key,
            session_prior_ip_key.as_deref(),
            || async {
                if !state.admin.verify(&form.password) {
                    state.login_limiter.record_failure(&acct_key, &ip_key).await;
                    return Redirect::to("/login?error=1").into_response();
                }
                state.login_limiter.on_success(&acct_key, &ip_key).await;
                let _ = session
                    .insert(crate::session::SESSION_LOGIN_IP_KEY, ip_key.clone())
                    .await;
                let _ = session.cycle_id().await;
                let _ = csrf::rotate_for_session(&session).await;
                let _ = session.insert(crate::session::SESSION_AUTH_KEY, true).await;
                let _ = session
                    .insert(
                        crate::session::SESSION_STARTED_MS_KEY,
                        crate::session::now_unix_ms(),
                    )
                    .await;
                Redirect::to("/").into_response()
            },
        )
        .await;
    match outcome {
        Ok(resp) => resp,
        Err(LoginGateError::IpRateLimited(delay)) => login_rate_limited_response(
            "Too many login attempts from this address. Try again later.",
            delay,
        ),
        Err(
            LoginGateError::AccountQueueFull
            | LoginGateError::AccountQueueTimeout
            | LoginGateError::AccountPaceRejected,
        ) => (
            StatusCode::TOO_MANY_REQUESTS,
            "Too many login attempts. Try again shortly.",
        )
            .into_response(),
    }
}

async fn logout(session: Session, headers: HeaderMap, Form(form): Form<LogoutForm>) -> Response {
    if let Some(resp) = csrf::verify_form_csrf(&session, &headers, &form._csrf).await {
        return resp;
    }
    let _ = session.delete().await;
    Redirect::to("/login").into_response()
}

#[derive(Deserialize)]
pub struct TableRecordForm {
    table: String,
    record: String,
    #[serde(default, rename = "_csrf")]
    pub _csrf: String,
}

#[derive(Deserialize)]
pub struct PlanForm {
    table: String,
    record: String,
    field: String,
    new_value: String,
    #[serde(default, rename = "_csrf")]
    pub _csrf: String,
}

fn parse_table_record(form: &TableRecordForm) -> Result<(u8, u16), String> {
    let table = fields::parse_table_input(&form.table)?;
    let record = fields::parse_record_input(&form.record)?;
    Ok((table, record))
}

async fn read_record(
    State(state): State<WebState>,
    session: Session,
    headers: HeaderMap,
    Form(form): Form<TableRecordForm>,
) -> Response {
    if let Some(resp) = csrf::verify_form_csrf(&session, &headers, &form._csrf).await {
        return resp;
    }
    let token = csrf::token_for_session(&session).await;
    let caller = caller_from_session(&session);
    let mut tpl = empty_dashboard(&token);
    tpl.table_value = form.table.clone();
    tpl.record_value = form.record.clone();
    fill_dashboard_from_status(&mut tpl, &state, &caller).await;

    let (table, record) = match parse_table_record(&form) {
        Ok(v) => v,
        Err(msg) => {
            tpl.show_read_form_error = true;
            tpl.read_form_error = msg;
            return Html(tpl.render().unwrap_or_default()).into_response();
        }
    };

    match state
        .backend
        .read_fields(&caller, ReadFieldsRequest { table, record })
        .await
    {
        Ok(resp) => {
            tpl.show_read_result = true;
            tpl.read_table = table;
            tpl.read_record = record;
            tpl.read_fields = resp
                .fields
                .into_iter()
                .map(|f| ReadFieldRow {
                    name: f.name,
                    value: f.value,
                })
                .collect();
        }
        Err(err) => {
            tpl.show_read_form_error = true;
            tpl.read_form_error = read_error_message(err);
        }
    }

    Html(tpl.render().unwrap_or_default()).into_response()
}

async fn dashboard(State(state): State<WebState>, session: Session) -> impl IntoResponse {
    let token = csrf::token_for_session(&session).await;
    let cookie = csrf::csrf_set_cookie_value(&token);
    let caller = caller_from_session(&session);
    let mut tpl = empty_dashboard(&token);
    fill_dashboard_from_status(&mut tpl, &state, &caller).await;
    (
        [(header::SET_COOKIE, cookie)],
        Html(tpl.render().unwrap_or_default()),
    )
}

fn parse_plan_form(form: &PlanForm) -> Result<PlanChangeRequest, String> {
    let (table, record) = parse_table_record(&TableRecordForm {
        table: form.table.clone(),
        record: form.record.clone(),
        _csrf: String::new(),
    })?;
    let _field_kind = fields::field_for_table(table, &form.field)?;
    Ok(PlanChangeRequest {
        table,
        record,
        field: form.field.clone(),
        new_value: form.new_value.clone(),
        base_bytes: Vec::new(),
        new_bytes: Vec::new(),
    })
}

async fn plan_change(
    State(state): State<WebState>,
    session: Session,
    headers: HeaderMap,
    Form(form): Form<PlanForm>,
) -> Response {
    if let Some(resp) = csrf::verify_form_csrf(&session, &headers, &form._csrf).await {
        return resp;
    }
    let token = csrf::token_for_session(&session).await;
    let caller = caller_from_session(&session);
    let mut tpl = empty_dashboard(&token);
    tpl.table_value = form.table.clone();
    tpl.record_value = form.record.clone();
    tpl.field_value = form.field.clone();
    tpl.new_value_value = form.new_value.clone();
    fill_dashboard_from_status(&mut tpl, &state, &caller).await;

    let mode = match state.backend.status(&caller).await {
        Ok(status) => status.operational_mode,
        Err(_) => {
            tpl.show_plan_form_error = true;
            tpl.plan_form_error =
                "Could not read daemon status. Planning is unavailable until status succeeds."
                    .into();
            return Html(tpl.render().unwrap_or_default()).into_response();
        }
    };

    let request = match parse_plan_form(&form) {
        Ok(req) => req,
        Err(msg) => {
            tpl.show_plan_form_error = true;
            tpl.plan_form_error = msg;
            return Html(tpl.render().unwrap_or_default()).into_response();
        }
    };

    match state.backend.plan_change(&caller, request).await {
        Ok(summary) => apply_plan_result(&mut tpl, &summary, mode),
        Err(err) => {
            tpl.show_plan_form_error = true;
            tpl.plan_form_error = plan_error_message(err);
        }
    }

    Html(tpl.render().unwrap_or_default()).into_response()
}

#[cfg(test)]
mod client_ip_tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn trusts_x_forwarded_for_only_when_listener_allows() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.5".parse().unwrap());
        let peer = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(client_ip(&headers, Some(peer), true, true), "203.0.113.5");
        assert_eq!(client_ip(&headers, Some(peer), false, false), "127.0.0.1");

        let peer = "10.0.0.2:443".parse().unwrap();
        assert_eq!(client_ip(&headers, Some(peer), true, true), "203.0.113.5");
        assert_eq!(client_ip(&headers, Some(peer), false, false), "10.0.0.2");
    }
}
