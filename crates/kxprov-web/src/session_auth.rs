use tower_sessions::Session;

const AUTH_KEY: &str = "web_admin_authed";

pub async fn is_authenticated(session: &Session) -> bool {
    session
        .get::<bool>(AUTH_KEY)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

pub async fn set_authenticated(session: &Session) {
    let _ = session.insert(AUTH_KEY, true).await;
}

pub async fn clear_authenticated(session: &Session) {
    let _ = session.remove::<bool>(AUTH_KEY).await;
}

pub fn admin_session_id(session: &Session) -> String {
    session
        .id()
        .map(|id| id.to_string())
        .unwrap_or_else(|| "anonymous".into())
}
