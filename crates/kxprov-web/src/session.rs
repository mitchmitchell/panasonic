use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use tower_sessions::Session;

/// Web admin session idle timeout (tower-sessions inactivity expiry).
pub const WEB_SESSION_IDLE_SECS: u64 = 900;
/// Maximum authenticated session lifetime from login, regardless of activity.
pub const WEB_SESSION_ABSOLUTE_SECS: u64 = 8 * 3600;

pub const SESSION_AUTH_KEY: &str = "web_authenticated";
pub const SESSION_STARTED_MS_KEY: &str = "web_session_started_ms";

pub fn is_public_web_path(path: &str) -> bool {
    path.starts_with("/static/") || path == "/login"
}

pub async fn require_web_session(session: Session, req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path();
    if is_public_web_path(path) {
        return next.run(req).await;
    }
    match session.get::<bool>(SESSION_AUTH_KEY).await {
        Ok(Some(true)) => next.run(req).await,
        _ => Redirect::to("/login").into_response(),
    }
}

pub fn absolute_session_valid(started_ms: u64, now_ms: u64, max_lifetime_secs: u64) -> bool {
    now_ms.saturating_sub(started_ms) <= max_lifetime_secs.saturating_mul(1000)
}

pub fn now_unix_ms() -> u64 {
    time::OffsetDateTime::now_utc().unix_timestamp().max(0) as u64 * 1000
}

pub async fn enforce_absolute_session_limit(
    session: Session,
    req: Request<Body>,
    next: Next,
    max_lifetime_secs: u64,
) -> Response {
    let path = req.uri().path();
    if is_public_web_path(path) {
        return next.run(req).await;
    }
    let authenticated = session.get::<bool>(SESSION_AUTH_KEY).await.ok().flatten() == Some(true);
    if !authenticated {
        return next.run(req).await;
    }
    let started = session
        .get::<u64>(SESSION_STARTED_MS_KEY)
        .await
        .ok()
        .flatten();
    let Some(started) = started else {
        let _ = session.delete().await;
        return Redirect::to("/login").into_response();
    };
    if !absolute_session_valid(started, now_unix_ms(), max_lifetime_secs) {
        let _ = session.delete().await;
        return Redirect::to("/login").into_response();
    }
    next.run(req).await
}

pub async fn reject_authenticated_login(
    session: Session,
    req: Request<Body>,
    next: Next,
) -> Response {
    if req.uri().path() != "/login" || req.method() != axum::http::Method::GET {
        return next.run(req).await;
    }
    if session.get::<bool>(SESSION_AUTH_KEY).await.ok().flatten() == Some(true) {
        return Redirect::to("/").into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_paths_include_static_and_login() {
        assert!(is_public_web_path("/login"));
        assert!(is_public_web_path("/static/site.css"));
        assert!(!is_public_web_path("/plan"));
    }

    #[test]
    fn absolute_limit_allows_within_eight_hours() {
        let start = 1_000_000u64;
        assert!(absolute_session_valid(
            start,
            start + WEB_SESSION_ABSOLUTE_SECS * 1000,
            WEB_SESSION_ABSOLUTE_SECS
        ));
    }

    #[test]
    fn absolute_limit_rejects_after_eight_hours() {
        let start = 1_000_000u64;
        assert!(!absolute_session_valid(
            start,
            start + WEB_SESSION_ABSOLUTE_SECS * 1000 + 1,
            WEB_SESSION_ABSOLUTE_SECS
        ));
    }
}
