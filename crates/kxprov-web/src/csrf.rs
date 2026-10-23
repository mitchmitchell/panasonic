use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_csrf::CsrfToken;

pub fn verify_form_csrf(csrf_token: &CsrfToken, form_token: &str) -> Option<Response> {
    if form_token.is_empty() || csrf_token.verify(form_token).is_err() {
        return Some((StatusCode::FORBIDDEN, "invalid or missing CSRF token").into_response());
    }
    None
}
