use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginGateError {
    /// Hard 429 + Retry-After: this IP (or peer|xff bucket) has failure backoff.
    IpRateLimited(Duration),
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
    account_serial: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
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
            account_serial: Arc::new(Mutex::new(HashMap::new())),
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

    /// Serializes login attempts per account: reserves soft pacing before sleeping, then runs `attempt`.
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
        let serial = self.account_serial_gate(account_key).await;
        let _guard = serial.lock().await;
        let soft = self.reserve_account_soft_delay(account_key).await;
        if soft > Duration::ZERO {
            tokio::time::sleep(soft).await;
        }
        Ok(attempt().await)
    }

    async fn account_serial_gate(&self, account_key: &str) -> Arc<Mutex<()>> {
        let mut map = self.account_serial.lock().await;
        map.entry(account_key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Atomically reserve the next soft pacing slot for this account (max 2s sleep).
    async fn reserve_account_soft_delay(&self, account_key: &str) -> Duration {
        const MAX_SOFT: Duration = Duration::from_secs(2);
        const SLOT_TAIL: Duration = Duration::from_millis(1);
        let mut map = self.by_key.lock().await;
        let now = Instant::now();
        let entry = map.entry(account_key.to_string()).or_insert(Entry {
            failures: 0,
            next_allowed: now,
        });
        let scheduled = now.max(entry.next_allowed);
        let mut wait = scheduled.saturating_duration_since(now);
        if wait > MAX_SOFT {
            wait = MAX_SOFT;
        }
        let release = scheduled + wait + SLOT_TAIL;
        entry.next_allowed = release;
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
    async fn parallel_login_attempts_serialize_account_pacing() {
        let limiter = Arc::new(LoginRateLimiter::new(
            Duration::from_millis(80),
            Duration::from_secs(30),
            Duration::from_secs(300),
        ));
        limiter.record_failure("acct:admin", "ip:attacker").await;
        let n = 5;
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
