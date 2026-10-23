use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum_csrf::CsrfConfig;
use kxprov_mock::MockDaemon;
use kxprov_web::{LoginRateLimiter, PasswordVerifier, WebState};

pub struct TestVerifier;

impl PasswordVerifier for TestVerifier {
    fn verify(&self, password: &str) -> bool {
        password == "test-admin-password"
    }
}

pub fn test_web_state() -> WebState {
    WebState {
        backend: Arc::new(MockDaemon::new()),
        admin: Arc::new(TestVerifier),
        login_limiter: Arc::new(LoginRateLimiter::new(20, Duration::from_secs(60))),
        csrf_config: CsrfConfig::default(),
    }
}

#[allow(dead_code)]
pub fn test_router() -> Router {
    kxprov_web::router(test_web_state())
}
