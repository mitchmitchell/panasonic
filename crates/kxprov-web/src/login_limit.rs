use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

#[derive(Clone)]
pub struct LoginRateLimiter {
    max_failures: u32,
    window: Duration,
    by_key: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
}

impl LoginRateLimiter {
    pub fn new(max_failures: u32, window: Duration) -> Self {
        Self {
            max_failures,
            window,
            by_key: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn allow(&self, key: &str) -> bool {
        let mut map = self.by_key.lock().await;
        let now = Instant::now();
        let entry = map.entry(key.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) >= self.window {
            *entry = (0, now);
        }
        entry.0 < self.max_failures
    }

    pub async fn record_failure(&self, account_key: &str, ip_key: &str) {
        for key in [account_key, ip_key] {
            let mut map = self.by_key.lock().await;
            let now = Instant::now();
            let entry = map.entry(key.to_string()).or_insert((0, now));
            if now.duration_since(entry.1) >= self.window {
                *entry = (1, now);
            } else {
                entry.0 += 1;
            }
        }
    }

    pub async fn reset(&self, account_key: &str, ip_key: &str) {
        let mut map = self.by_key.lock().await;
        map.remove(account_key);
        map.remove(ip_key);
    }
}
