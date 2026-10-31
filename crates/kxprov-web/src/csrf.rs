use askama::Template;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use subtle::ConstantTimeEq;
use tower_sessions::Session;

pub const SESSION_CSRF_KEY: &str = "_session_csrf";
pub const CSRF_COOKIE_NAME: &str = "__Host-kxprov.csrf";

pub async fn token_for_session(session: &Session) -> String {
    if let Ok(Some(existing)) = session.get::<String>(SESSION_CSRF_KEY).await {
        if !existing.is_empty() {
            return existing;
        }
    }
    rotate_for_session(session).await
}

pub async fn rotate_for_session(session: &Session) -> String {
    let token = uuid::Uuid::new_v4().to_string();
    let _ = session.insert(SESSION_CSRF_KEY, token.clone()).await;
    token
}

pub fn csrf_set_cookie_value(token: &str) -> String {
    format!("{CSRF_COOKIE_NAME}={token}; Secure; HttpOnly; SameSite=Strict; Path=/")
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let prefix = format!("{CSRF_COOKIE_NAME}=");
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|raw| raw.split(';'))
        .find_map(|part| part.trim().strip_prefix(&prefix).map(str::to_string))
}

fn csrf_rejection() -> Response {
    let html = crate::templates::ErrorTemplate {
        page_title: "Your session needs a refresh".into(),
        message: "This form was out of date or your sign-in expired, so nothing was changed."
            .into(),
        next_step: "Go back to the home page and try again. If it keeps happening, sign in again."
            .into(),
    }
    .render()
    .unwrap_or_else(|_| "Your session needs a refresh. Go back to / and try again.".into());
    (StatusCode::FORBIDDEN, Html(html)).into_response()
}

pub async fn verify_form_csrf(
    session: &Session,
    headers: &HeaderMap,
    form_token: &str,
) -> Option<Response> {
    let session_token = session.get::<String>(SESSION_CSRF_KEY).await.ok().flatten();
    let Some(session_token) = session_token else {
        return Some(csrf_rejection());
    };
    if form_token.is_empty() || !bool::from(session_token.as_bytes().ct_eq(form_token.as_bytes())) {
        return Some(csrf_rejection());
    }
    let cookie = cookie_token(headers);
    let Some(cookie) = cookie else {
        return Some(csrf_rejection());
    };
    if !bool::from(session_token.as_bytes().ct_eq(cookie.as_bytes())) {
        return Some(csrf_rejection());
    }
    None
}
