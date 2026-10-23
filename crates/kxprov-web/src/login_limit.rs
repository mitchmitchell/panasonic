use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginBusy {
    /// Another login attempt for this account is already verifying a password.
    AccountInProgress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginPrecheck {
    Ready,
    RateLimited(Duration),
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

/// Held only while the password is verified; releases the per-account slot on drop.
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

    /// Backoff / concurrency gate before password verification (does not take the verify slot).
    pub async fn precheck_login(&self, account_key: &str, ip_key: &str) -> LoginPrecheck {
        {
            let active = self.account_active.lock().expect("account login lock");
            if active.contains_key(account_key) {
                return LoginPrecheck::AccountInProgress;
            }
        }
        let delay = self.delay_before_attempt(account_key, ip_key).await;
        if delay > Duration::ZERO {
            return LoginPrecheck::RateLimited(delay);
        }
        LoginPrecheck::Ready
    }

    /// Serialize password verification per account.
    pub fn begin_password_verify(&self, account_key: &str) -> Result<LoginAttemptGuard, LoginBusy> {
        let mut active = self.account_active.lock().expect("account login lock");
        if active.contains_key(account_key) {
            return Err(LoginBusy::AccountInProgress);
        }
        active.insert(account_key.to_string(), ());
        Ok(LoginAttemptGuard {
            limiter: self.clone(),
            account_key: account_key.to_string(),
        })
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
    async fn concurrent_password_verify_for_same_account_is_rejected() {
        let limiter = LoginRateLimiter::new(
            Duration::from_millis(1),
            Duration::from_secs(30),
            Duration::from_secs(30),
        );
        let _guard = limiter
            .begin_password_verify("acct:admin")
            .expect("first");
        assert!(matches!(
            limiter.begin_password_verify("acct:admin"),
            Err(LoginBusy::AccountInProgress)
        ));
    }

    #[tokio::test]
    async fn rate_limited_precheck_does_not_hold_verify_slot() {
        let limiter = LoginRateLimiter::new(
            Duration::from_millis(200),
            Duration::from_secs(30),
            Duration::from_secs(30),
        );
        limiter.record_failure("acct:admin", "ip:1").await;
        assert!(matches!(
            limiter.precheck_login("acct:admin", "ip:2").await,
            LoginPrecheck::RateLimited(_)
        ));
        assert!(
            limiter
                .begin_password_verify("acct:admin")
                .is_ok(),
            "backoff must not hold the verify slot"
        );
    }

    #[tokio::test]
    async fn rapid_hammer_cannot_extend_mitch_delay_past_account_cap() {
        let limiter = LoginRateLimiter::new(
            Duration::from_secs(5),
            Duration::from_secs(30),
            Duration::from_secs(300),
        );
        for i in 0..100 {
            limiter
                .record_failure("acct:admin", &format!("ip:hammer-{i}"))
                .await;
        }
        let wait = limiter
            .precheck_login("acct:admin", "ip:mitch-home")
            .await;
        let LoginPrecheck::RateLimited(d) = wait else {
            panic!("mitch should still be rate limited");
        };
        assert!(d <= Duration::from_secs(30));
    }
}
