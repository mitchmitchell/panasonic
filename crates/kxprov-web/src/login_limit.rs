use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginBusy {
    /// Another login attempt for this account is already in progress.
    AccountInProgress,
}

#[derive(Clone)]
pub struct LoginRateLimiter {
    initial_backoff: Duration,
    max_account_backoff: Duration,
    max_ip_backoff: Duration,
    by_key: Arc<Mutex<HashMap<String, Entry>>>,
    account_active: Arc<std::sync::Mutex<HashMap<String, ()>>>,
}

#[derive(Debug, Clone)]
struct Entry {
    failures: u32,
    next_allowed: Instant,
}

/// Held for the duration of one login attempt; releases the per-account slot.
pub struct LoginAttemptGuard {
    limiter: LoginRateLimiter,
    account_key: String,
}

impl Drop for LoginAttemptGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = self.limiter.account_active.lock() {
            active.remove(&self.account_key);
        }
    }
}

impl LoginRateLimiter {
    pub fn new(
        initial_backoff: Duration,
        max_account_backoff: Duration,
        max_ip_backoff: Duration,
    ) -> Self {
        Self {
            initial_backoff,
            max_account_backoff,
            max_ip_backoff,
            by_key: Arc::new(Mutex::new(HashMap::new())),
            account_active: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Serialize login per account; reject concurrent attempts while one is in flight.
    pub async fn begin_login(
        &self,
        account_key: &str,
        ip_key: &str,
    ) -> Result<(LoginAttemptGuard, Duration), LoginBusy> {
        {
            let mut active = self.account_active.lock().expect("account login lock");
            if active.contains_key(account_key) {
                return Err(LoginBusy::AccountInProgress);
            }
            active.insert(account_key.to_string(), ());
        }
        let delay = self.delay_before_attempt(account_key, ip_key).await;
        Ok((
            LoginAttemptGuard {
                limiter: self.clone(),
                account_key: account_key.to_string(),
            },
            delay,
        ))
    }

    pub async fn delay_before_attempt(&self, account_key: &str, ip_key: &str) -> Duration {
        let map = self.by_key.lock().await;
        let now = Instant::now();
        let acct = wait_for_key(map.get(account_key), now, self.max_account_backoff);
        let ip = wait_for_key(map.get(ip_key), now, self.max_ip_backoff);
        acct.max(ip)
    }

    pub async fn record_failure(&self, account_key: &str, ip_key: &str) {
        self.bump(account_key, self.max_account_backoff).await;
        self.bump(ip_key, self.max_ip_backoff).await;
    }

    pub async fn on_success(&self, account_key: &str, ip_key: &str) {
        let mut map = self.by_key.lock().await;
        map.remove(account_key);
        map.remove(ip_key);
    }

    async fn bump(&self, key: &str, cap: Duration) {
        let mut map = self.by_key.lock().await;
        let now = Instant::now();
        let entry = map.entry(key.to_string()).or_insert(Entry {
            failures: 0,
            next_allowed: now,
        });
        entry.failures = entry.failures.saturating_add(1);
        let shift = entry.failures.saturating_sub(1).min(16);
        let mut backoff = self.initial_backoff.saturating_mul(1u32 << shift);
        if backoff > cap {
            backoff = cap;
        }
        entry.next_allowed = now + backoff;
    }
}

fn wait_for_key(entry: Option<&Entry>, now: Instant, cap: Duration) -> Duration {
    let Some(entry) = entry else {
        return Duration::ZERO;
    };
    if now >= entry.next_allowed {
        return Duration::ZERO;
    }
    let mut wait = entry.next_allowed - now;
    if wait > cap {
        wait = cap;
    }
    wait
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn account_backoff_caps_and_never_hard_locks() {
        let limiter = LoginRateLimiter::new(
            Duration::from_millis(50),
            Duration::from_millis(200),
            Duration::from_secs(60),
        );
        for _ in 0..20 {
            limiter.record_failure("acct:admin", "ip:1").await;
        }
        let wait = limiter.delay_before_attempt("acct:admin", "ip:2").await;
        assert!(wait <= Duration::from_millis(200));
        assert!(wait > Duration::ZERO);
    }

    #[tokio::test]
    async fn success_clears_ip_backoff() {
        let limiter = LoginRateLimiter::new(
            Duration::from_millis(100),
            Duration::from_secs(30),
            Duration::from_secs(30),
        );
        limiter.record_failure("acct:admin", "ip:9").await;
        assert!(limiter.delay_before_attempt("acct:admin", "ip:9").await > Duration::ZERO);
        limiter.on_success("acct:admin", "ip:9").await;
        assert_eq!(
            limiter.delay_before_attempt("acct:admin", "ip:9").await,
            Duration::ZERO
        );
    }

    #[tokio::test]
    async fn stranger_failures_cannot_delay_mitch_beyond_account_cap() {
        let limiter = LoginRateLimiter::new(
            Duration::from_secs(10),
            Duration::from_secs(30),
            Duration::from_secs(300),
        );
        for _ in 0..50 {
            limiter.record_failure("acct:admin", "ip:stranger").await;
        }
        let wait = limiter
            .delay_before_attempt("acct:admin", "ip:mitch-home")
            .await;
        assert!(wait <= Duration::from_secs(30));
    }

    #[tokio::test]
    async fn concurrent_logins_for_same_account_are_rejected() {
        let limiter = LoginRateLimiter::new(
            Duration::from_millis(1),
            Duration::from_secs(30),
            Duration::from_secs(30),
        );
        let (_guard, _) = limiter
            .begin_login("acct:admin", "ip:1")
            .await
            .expect("first");
        assert!(matches!(
            limiter.begin_login("acct:admin", "ip:2").await,
            Err(LoginBusy::AccountInProgress)
        ));
    }
}
