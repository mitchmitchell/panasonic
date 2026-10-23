use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

#[derive(Clone)]
pub struct LoginRateLimiter {
    initial_backoff: Duration,
    max_backoff: Duration,
    by_key: Arc<Mutex<HashMap<String, Entry>>>,
}

#[derive(Debug, Clone)]
struct Entry {
    failures: u32,
    next_allowed: Instant,
}

impl LoginRateLimiter {
    pub fn new(initial_backoff: Duration, max_backoff: Duration) -> Self {
        Self {
            initial_backoff,
            max_backoff,
            by_key: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn allow(&self, key: &str) -> bool {
        let map = self.by_key.lock().await;
        let now = Instant::now();
        match map.get(key) {
            Some(entry) => now >= entry.next_allowed,
            None => true,
        }
    }

    pub async fn record_failure(&self, account_key: &str, ip_key: &str) {
        for key in [account_key, ip_key] {
            let mut map = self.by_key.lock().await;
            let now = Instant::now();
            let entry = map.entry(key.to_string()).or_insert(Entry {
                failures: 0,
                next_allowed: now,
            });
            entry.failures = entry.failures.saturating_add(1);
            let shift = entry.failures.saturating_sub(1).min(16);
            let mut backoff = self.initial_backoff.saturating_mul(1u32 << shift);
            if backoff > self.max_backoff {
                backoff = self.max_backoff;
            }
            entry.next_allowed = now + backoff;
        }
    }

    pub async fn reset(&self, account_key: &str, ip_key: &str) {
        let mut map = self.by_key.lock().await;
        map.remove(account_key);
        map.remove(ip_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn backoff_blocks_until_window_elapses() {
        let limiter = LoginRateLimiter::new(Duration::from_millis(50), Duration::from_secs(60));
        assert!(limiter.allow("acct:admin").await);
        limiter.record_failure("acct:admin", "ip:1").await;
        assert!(!limiter.allow("acct:admin").await);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(limiter.allow("acct:admin").await);
    }

    #[tokio::test]
    async fn account_and_ip_keys_are_independent_for_allow() {
        let limiter = LoginRateLimiter::new(Duration::from_secs(300), Duration::from_secs(300));
        limiter.record_failure("acct:admin", "ip:9").await;
        limiter.record_failure("acct:admin", "ip:9").await;
        assert!(!limiter.allow("acct:admin").await);
        assert!(limiter.allow("ip:10").await);
    }
}
