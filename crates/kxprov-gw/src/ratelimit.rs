use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct RateLimiter {
    limit_per_minute: u32,
    inner: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
}

impl RateLimiter {
    pub fn new(limit_per_minute: u32) -> Self {
        Self {
            limit_per_minute,
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn check(&self, key: &str) -> bool {
        let mut map = self.inner.lock().await;
        let now = Instant::now();
        let window = Duration::from_secs(60);
        let entry = map.entry(key.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) >= window {
            *entry = (0, now);
        }
        if entry.0 >= self.limit_per_minute {
            return false;
        }
        entry.0 += 1;
        true
    }
}

pub type RateLimitKeyFn = Arc<dyn Fn(&Request<Body>) -> Option<String> + Send + Sync>;

#[derive(Clone)]
pub struct RateLimitState {
    pub limiter: RateLimiter,
    pub key_from_request: RateLimitKeyFn,
}

pub async fn rate_limit_middleware(
    State(state): State<RateLimitState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(key) = (state.key_from_request)(&req) {
        if !state.limiter.check(&key).await {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }
    Ok(next.run(req).await)
}
