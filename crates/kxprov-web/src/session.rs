use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use tower_sessions::Session;

pub const SESSION_AUTH_KEY: &str = "web_authenticated";

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
}
