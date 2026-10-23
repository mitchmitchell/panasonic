use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

const MAX_ACCOUNT_WAITERS: u32 = 2;
const MAX_ACCOUNT_QUEUE_WAIT: Duration = Duration::from_secs(2);
const MAX_SOFT_PACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginGateError {
    /// Hard 429 + Retry-After: this IP (or peer|xff bucket) has failure backoff.
    IpRateLimited(Duration),
    /// Too many concurrent login attempts queued for this account (not an auth failure).
    AccountQueueFull,
    /// Waited too long for the account verify slot (not an auth failure).
    AccountQueueTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginPrecheck {
    Ready,
    IpRateLimited(Duration),
}

#[derive(Clone)]
pub struct LoginRateLimiter {
    initial_backoff: Duration,
    max_account_backoff: Duration,
    max_ip_backoff: Duration,
    by_key: Arc<Mutex<HashMap<String, Entry>>>,
    account_verify: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    account_waiters: Arc<Mutex<HashMap<String, u32>>>,
}

#[derive(Debug, Clone)]
struct Entry {
    failures: u32,
    next_allowed: Instant,
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
            account_verify: Arc::new(Mutex::new(HashMap::new())),
            account_waiters: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// IP backoff only (account pacing runs inside [`Self::enter_account_login`]).
    pub async fn precheck_login(&self, _account_key: &str, ip_key: &str) -> LoginPrecheck {
        let ip_delay = self.delay_for_key(ip_key).await;
        if ip_delay > Duration::ZERO {
            return LoginPrecheck::IpRateLimited(ip_delay);
        }
        LoginPrecheck::Ready
    }

    /// Serializes login attempts per account with bounded waiters and max wait.
    pub async fn enter_account_login<T, F, Fut>(
        &self,
        account_key: &str,
        ip_key: &str,
        attempt: F,
    ) -> Result<T, LoginGateError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let ip_delay = self.delay_for_key(ip_key).await;
        if ip_delay > Duration::ZERO {
            return Err(LoginGateError::IpRateLimited(ip_delay));
        }
        let ip_clean = !self.key_has_failure_history(ip_key).await;
        let bypass_waiter_cap = ip_clean;
        let verify = self.account_verify_lock(account_key).await;

        if !bypass_waiter_cap {
            let mut waiters = self.account_waiters.lock().await;
            let n = waiters.entry(account_key.to_string()).or_insert(0);
            if *n >= MAX_ACCOUNT_WAITERS {
                return Err(LoginGateError::AccountQueueFull);
            }
            *n += 1;
        }

        let lock_result = tokio::time::timeout(MAX_ACCOUNT_QUEUE_WAIT, verify.lock()).await;

        if !bypass_waiter_cap {
            let mut waiters = self.account_waiters.lock().await;
            if let Some(n) = waiters.get_mut(account_key) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    waiters.remove(account_key);
                }
            }
        }

        let _verify_guard = match lock_result {
            Err(_) => return Err(LoginGateError::AccountQueueTimeout),
            Ok(guard) => guard,
        };

        let soft = self.reserve_account_soft_delay(account_key).await;
        if soft > Duration::ZERO {
            tokio::time::sleep(soft.min(MAX_SOFT_PACE)).await;
        }
        Ok(attempt().await)
    }

    async fn account_verify_lock(&self, account_key: &str) -> Arc<Mutex<()>> {
        let mut map = self.account_verify.lock().await;
        map.entry(account_key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    async fn reserve_account_soft_delay(&self, account_key: &str) -> Duration {
        const SLOT_TAIL: Duration = Duration::from_millis(1);
        let mut map = self.by_key.lock().await;
        let now = Instant::now();
        let entry = map.entry(account_key.to_string()).or_insert(Entry {
            failures: 0,
            next_allowed: now,
        });
        let scheduled = now.max(entry.next_allowed);
        let mut wait = scheduled.saturating_duration_since(now);
        if wait > MAX_SOFT_PACE {
            wait = MAX_SOFT_PACE;
        }
        entry.next_allowed = scheduled + wait + SLOT_TAIL;
        wait
    }

    pub async fn delay_before_attempt(&self, account_key: &str, ip_key: &str) -> Duration {
        let map = self.by_key.lock().await;
        let now = Instant::now();
        let acct = wait_for_key(map.get(account_key), now, self.max_account_backoff);
        let ip = wait_for_key(map.get(ip_key), now, self.max_ip_backoff);
        acct.max(ip)
    }

    async fn delay_for_key(&self, key: &str) -> Duration {
        let cap = if key.starts_with("ip:") {
            self.max_ip_backoff
        } else {
            self.max_account_backoff
        };
        let map = self.by_key.lock().await;
        wait_for_key(map.get(key), Instant::now(), cap)
    }

    async fn key_has_failure_history(&self, key: &str) -> bool {
        let map = self.by_key.lock().await;
        map.get(key).is_some_and(|entry| entry.failures > 0)
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
    use std::sync::atomic::{AtomicU32, Ordering};

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
    async fn clean_ip_precheck_ignores_account_backoff() {
        let limiter = LoginRateLimiter::new(
            Duration::from_secs(10),
            Duration::from_secs(30),
            Duration::from_secs(300),
        );
        for _ in 0..50 {
            limiter.record_failure("acct:admin", "ip:stranger").await;
        }
        assert!(matches!(
            limiter.precheck_login("acct:admin", "ip:mitch-home").await,
            LoginPrecheck::Ready
        ));
    }

    #[tokio::test]
    async fn ip_backoff_yields_rate_limited_precheck() {
        let limiter = LoginRateLimiter::new(
            Duration::from_millis(200),
            Duration::from_secs(30),
            Duration::from_secs(30),
        );
        limiter.record_failure("acct:admin", "ip:1").await;
        assert!(matches!(
            limiter.precheck_login("acct:admin", "ip:1").await,
            LoginPrecheck::IpRateLimited(_)
        ));
        assert!(matches!(
            limiter.precheck_login("acct:admin", "ip:2").await,
            LoginPrecheck::Ready
        ));
    }

    #[tokio::test]
    async fn clean_ip_can_login_while_account_backoff_and_other_ips_fail() {
        let limiter = LoginRateLimiter::new(
            Duration::from_millis(100),
            Duration::from_secs(30),
            Duration::from_secs(300),
        );
        for i in 0..10 {
            limiter
                .record_failure("acct:admin", &format!("ip:attacker-{i}"))
                .await;
        }
        assert!(matches!(
            limiter.precheck_login("acct:admin", "ip:mitch-home").await,
            LoginPrecheck::Ready
        ));
        let started = Instant::now();
        limiter
            .enter_account_login("acct:admin", "ip:mitch-home", || async { "ok" })
            .await
            .expect("clean IP enters account slot");
        assert!(started.elapsed() <= Duration::from_secs(3));
    }

    #[tokio::test]
    async fn excess_concurrent_waiters_rejected_without_account_failure() {
        let limiter = Arc::new(LoginRateLimiter::new(
            Duration::from_millis(200),
            Duration::from_secs(30),
            Duration::from_secs(300),
        ));
        limiter.record_failure("acct:admin", "ip:dirty").await;
        tokio::time::sleep(Duration::from_millis(250)).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(4));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let limiter = Arc::clone(&limiter);
            let barrier = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                limiter
                    .enter_account_login("acct:admin", "ip:dirty", || async {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    })
                    .await
            }));
        }
        let mut full = 0;
        for h in handles {
            match h.await.unwrap() {
                Err(LoginGateError::AccountQueueFull)
                | Err(LoginGateError::AccountQueueTimeout) => {
                    full += 1;
                }
                Ok(()) => {}
                Err(_) => {}
            }
        }
        assert!(full >= 1, "expected at least one immediate queue rejection");
    }

    #[tokio::test]
    async fn clean_admin_login_under_ten_concurrent_attackers_completes_within_three_seconds() {
        let limiter = Arc::new(LoginRateLimiter::new(
            Duration::from_millis(150),
            Duration::from_secs(30),
            Duration::from_secs(300),
        ));
        limiter.record_failure("acct:admin", "ip:attacker").await;
        tokio::time::sleep(Duration::from_millis(250)).await;
        let n_attackers = 10;
        let barrier = Arc::new(tokio::sync::Barrier::new(n_attackers + 1));
        for _ in 0..n_attackers {
            let limiter = Arc::clone(&limiter);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                let _ = limiter
                    .enter_account_login("acct:admin", "ip:attacker", || async {
                        tokio::time::sleep(Duration::from_millis(80)).await;
                        "bad"
                    })
                    .await;
            });
        }
        let started = Instant::now();
        barrier.wait().await;
        limiter
            .enter_account_login("acct:admin", "ip:admin-clean", || async { "ok" })
            .await
            .expect("admin login succeeds");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "admin waited {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn parallel_login_attempts_serialize_account_pacing() {
        let limiter = Arc::new(LoginRateLimiter::new(
            Duration::from_millis(80),
            Duration::from_secs(30),
            Duration::from_secs(300),
        ));
        limiter.record_failure("acct:admin", "ip:attacker").await;
        let n = 3;
        let barrier = Arc::new(tokio::sync::Barrier::new(n));
        let order = Arc::new(AtomicU32::new(0));
        let mut handles = Vec::new();
        for _ in 0..n {
            let limiter = Arc::clone(&limiter);
            let barrier = Arc::clone(&barrier);
            let order = Arc::clone(&order);
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                limiter
                    .enter_account_login("acct:admin", "ip:clean", || async {
                        order.fetch_add(1, Ordering::SeqCst)
                    })
                    .await
                    .expect("enter")
            }));
        }
        let mut seq = Vec::new();
        for h in handles {
            seq.push(h.await.unwrap());
        }
        seq.sort();
        assert_eq!(seq, (0..n as u32).collect::<Vec<_>>());
    }
}
