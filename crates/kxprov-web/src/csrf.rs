use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
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
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(&format!("{CSRF_COOKIE_NAME}=")) {
            return Some(v.to_string());
        }
    }
    None
}

pub async fn verify_form_csrf(
    session: &Session,
    headers: &HeaderMap,
    form_token: &str,
) -> Option<Response> {
    let session_token = session.get::<String>(SESSION_CSRF_KEY).await.ok().flatten();
    let Some(session_token) = session_token else {
        return Some((StatusCode::FORBIDDEN, "invalid or missing CSRF token").into_response());
    };
    if form_token.is_empty() || !bool::from(session_token.as_bytes().ct_eq(form_token.as_bytes())) {
        return Some((StatusCode::FORBIDDEN, "invalid or missing CSRF token").into_response());
    }
    let cookie = cookie_token(headers);
    let Some(cookie) = cookie else {
        return Some((StatusCode::FORBIDDEN, "invalid or missing CSRF token").into_response());
    };
    if !bool::from(session_token.as_bytes().ct_eq(cookie.as_bytes())) {
        return Some((StatusCode::FORBIDDEN, "invalid or missing CSRF token").into_response());
    }
    None
}
