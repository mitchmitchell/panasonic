use std::collections::HashMap;
use std::net::IpAddr;
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
    /// Account verify slot is farther out than [`MAX_SOFT_PACE`] (not an auth failure).
    AccountPaceRejected,
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
    account_waiters: Arc<std::sync::Mutex<HashMap<String, u32>>>,
    /// In-process only (never written to disk): last successful login IP per account.
    last_success_ip: Arc<Mutex<HashMap<String, String>>>,
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
            account_waiters: Arc::new(std::sync::Mutex::new(HashMap::new())),
            last_success_ip: Arc::new(Mutex::new(HashMap::new())),
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
        session_prior_ip_key: Option<&str>,
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
        let privileged = self
            .is_privileged_login_ip(account_key, ip_key, session_prior_ip_key)
            .await;
        let bypass_waiter_cap = privileged
            || (!shared_loopback_ip_key(ip_key) && !self.key_has_failure_history(ip_key).await);
        let verify = self.account_verify_lock(account_key).await;

        let waiter_slot = if bypass_waiter_cap {
            None
        } else {
            let mut waiters = self.account_waiters.lock().expect("account waiters lock");
            let n = waiters.entry(account_key.to_string()).or_insert(0);
            if *n >= MAX_ACCOUNT_WAITERS {
                return Err(LoginGateError::AccountQueueFull);
            }
            *n += 1;
            Some(AccountWaiterSlot {
                account_key: account_key.to_string(),
                waiters: Arc::clone(&self.account_waiters),
            })
        };

        if !privileged {
            let reserve = {
                let _slot = verify.lock().await;
                self.reserve_account_soft_delay(account_key).await
            };
            match reserve {
                SoftPace::Rejected => return Err(LoginGateError::AccountPaceRejected),
                SoftPace::Ready(wait) => {
                    if wait > Duration::ZERO {
                        tokio::time::sleep(wait).await;
                    }
                }
            }
        }

        let ip_delay = self.delay_for_key(ip_key).await;
        if ip_delay > Duration::ZERO {
            return Err(LoginGateError::IpRateLimited(ip_delay));
        }

        let lock_result = tokio::time::timeout(MAX_ACCOUNT_QUEUE_WAIT, verify.lock()).await;

        let _verify_guard = match lock_result {
            Err(_) => return Err(LoginGateError::AccountQueueTimeout),
            Ok(guard) => guard,
        };
        drop(waiter_slot);

        Ok(attempt().await)
    }

    async fn is_privileged_login_ip(
        &self,
        account_key: &str,
        ip_key: &str,
        session_prior_ip_key: Option<&str>,
    ) -> bool {
        if session_prior_ip_key == Some(ip_key) {
            return true;
        }
        let map = self.last_success_ip.lock().await;
        map.get(account_key).is_some_and(|last| last == ip_key)
    }

    async fn account_verify_lock(&self, account_key: &str) -> Arc<Mutex<()>> {
        let mut map = self.account_verify.lock().await;
        map.entry(account_key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    async fn reserve_account_soft_delay(&self, account_key: &str) -> SoftPace {
        let pace_key = format!("pace:{account_key}");
        let mut map = self.by_key.lock().await;
        let now = Instant::now();
        let entry = map.entry(pace_key).or_insert(Entry {
            failures: 0,
            next_allowed: now,
        });
        let scheduled = now.max(entry.next_allowed);
        let wait = scheduled.saturating_duration_since(now);
        if wait > MAX_SOFT_PACE {
            return SoftPace::Rejected;
        }
        entry.next_allowed = scheduled + MAX_SOFT_PACE;
        SoftPace::Ready(wait)
    }

    pub async fn delay_before_attempt(&self, account_key: &str, ip_key: &str) -> Duration {
        let map = self.by_key.lock().await;
        let now = Instant::now();
        let acct = wait_for_key(map.get(account_key), now, self.max_account_backoff);
        let ip = wait_for_key(map.get(ip_key), now, self.max_ip_backoff);
        acct.max(ip)
    }

    async fn delay_for_key(&self, key: &str) -> Duration {
        let cap = if key.starts_with("ip:") || key.starts_with("ts-login:") {
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
        drop(map);
        let mut last = self.last_success_ip.lock().await;
        last.insert(account_key.to_string(), ip_key.to_string());
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SoftPace {
    Ready(Duration),
    Rejected,
}

struct AccountWaiterSlot {
    account_key: String,
    waiters: Arc<std::sync::Mutex<HashMap<String, u32>>>,
}

impl Drop for AccountWaiterSlot {
    fn drop(&mut self) {
        let mut waiters = self.waiters.lock().expect("account waiters lock");
        if let Some(n) = waiters.get_mut(&self.account_key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                waiters.remove(&self.account_key);
            }
        }
    }
}

fn shared_loopback_ip_key(ip_key: &str) -> bool {
    let Some(rest) = ip_key.strip_prefix("ip:") else {
        return false;
    };
    rest.parse::<IpAddr>()
        .ok()
        .is_some_and(|ip| ip.is_loopback())
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
            .enter_account_login("acct:admin", "ip:mitch-home", None, || async { "ok" })
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
        for i in 0..4 {
            limiter
                .record_failure("acct:admin", &format!("ip:dirty-{i}"))
                .await;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(4));
        let mut handles = Vec::new();
        for i in 0..4 {
            let limiter = Arc::clone(&limiter);
            let barrier = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                limiter
                    .enter_account_login("acct:admin", &format!("ip:dirty-{i}"), None, || async {
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
        limiter.on_success("acct:admin", "ip:admin-clean").await;
        for i in 0..20 {
            limiter
                .record_failure("acct:admin", &format!("ip:attacker-{i}"))
                .await;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        let n_attackers = 10;
        let barrier = Arc::new(tokio::sync::Barrier::new(n_attackers + 1));
        for i in 0..n_attackers {
            let limiter = Arc::clone(&limiter);
            let barrier = Arc::clone(&barrier);
            let ip = format!("ip:flood-{i}");
            tokio::spawn(async move {
                barrier.wait().await;
                let _ = limiter
                    .enter_account_login("acct:admin", &ip, None, || async {
                        tokio::time::sleep(Duration::from_millis(80)).await;
                        "bad"
                    })
                    .await;
            });
        }
        let started = Instant::now();
        barrier.wait().await;
        limiter
            .enter_account_login("acct:admin", "ip:admin-clean", None, || async { "ok" })
            .await
            .expect("admin login succeeds via in-memory last-success IP");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "admin waited {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn session_prior_ip_skips_queue_without_last_success_entry() {
        let limiter = LoginRateLimiter::new(
            Duration::from_millis(150),
            Duration::from_secs(30),
            Duration::from_secs(300),
        );
        for i in 0..10 {
            limiter
                .record_failure("acct:admin", &format!("ip:attacker-{i}"))
                .await;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        let started = Instant::now();
        limiter
            .enter_account_login(
                "acct:admin",
                "ip:session-home",
                Some("ip:session-home"),
                || async { "ok" },
            )
            .await
            .expect("session-stored IP skips pacing");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn last_success_ip_skips_queue_without_session() {
        let limiter = LoginRateLimiter::new(
            Duration::from_millis(150),
            Duration::from_secs(30),
            Duration::from_secs(300),
        );
        limiter.on_success("acct:admin", "ip:known-good").await;
        for i in 0..10 {
            limiter
                .record_failure("acct:admin", &format!("ip:attacker-{i}"))
                .await;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        let started = Instant::now();
        limiter
            .enter_account_login("acct:admin", "ip:known-good", None, || async { "ok" })
            .await
            .expect("last-success IP skips queue without session cookie");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn clean_admin_succeeds_under_account_backoff_cap_with_fresh_attacker_ips() {
        let limiter = Arc::new(LoginRateLimiter::new(
            Duration::from_millis(120),
            Duration::from_secs(30),
            Duration::from_secs(300),
        ));
        limiter.on_success("acct:admin", "ip:admin-home").await;
        for i in 0..30 {
            limiter
                .record_failure("acct:admin", &format!("ip:seed-{i}"))
                .await;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        let n = 8;
        let barrier = Arc::new(tokio::sync::Barrier::new(n + 1));
        for i in 0..n {
            let limiter = Arc::clone(&limiter);
            let barrier = Arc::clone(&barrier);
            let ip = format!("ip:burst-{i}");
            tokio::spawn(async move {
                barrier.wait().await;
                let _ = limiter
                    .enter_account_login("acct:admin", &ip, None, || async {
                        tokio::time::sleep(Duration::from_millis(60)).await;
                    })
                    .await;
            });
        }
        let started = Instant::now();
        barrier.wait().await;
        limiter
            .enter_account_login("acct:admin", "ip:admin-home", None, || async { "ok" })
            .await
            .expect("privileged admin ip via last-success");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn ten_concurrent_clean_ips_only_one_or_two_verify_within_two_seconds() {
        let limiter = Arc::new(LoginRateLimiter::new(
            Duration::from_secs(2),
            Duration::from_secs(30),
            Duration::from_secs(300),
        ));
        let n = 10;
        let barrier = Arc::new(tokio::sync::Barrier::new(n));
        let verified = Arc::new(AtomicU32::new(0));
        let rejected = Arc::new(AtomicU32::new(0));
        let mut handles = Vec::new();
        for i in 0..n {
            let limiter = Arc::clone(&limiter);
            let barrier = Arc::clone(&barrier);
            let verified = Arc::clone(&verified);
            let rejected = Arc::clone(&rejected);
            let ip = format!("ip:clean-{i}");
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                match limiter
                    .enter_account_login("acct:admin", &ip, None, || async {
                        verified.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    })
                    .await
                {
                    Ok(()) => {}
                    Err(LoginGateError::AccountPaceRejected) => {
                        rejected.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(e) => panic!("unexpected gate error: {e:?}"),
                }
            }));
        }
        let started = Instant::now();
        for h in handles {
            h.await.unwrap();
        }
        assert!(
            started.elapsed() <= Duration::from_secs(2) + Duration::from_millis(500),
            "burst took {:?}",
            started.elapsed()
        );
        let ok = verified.load(Ordering::SeqCst);
        let deny = rejected.load(Ordering::SeqCst);
        assert!(
            (1..=2).contains(&ok),
            "expected 1-2 verifies, got {ok} (rejected {deny})"
        );
        assert!(deny >= 8, "expected most attempts rejected, got {deny}");
    }

    #[tokio::test]
    async fn parallel_login_attempts_serialize_account_pacing() {
        let limiter = Arc::new(LoginRateLimiter::new(
            Duration::from_millis(80),
            Duration::from_secs(30),
            Duration::from_secs(300),
        ));
        limiter.record_failure("acct:admin", "ip:attacker").await;
        let started = Instant::now();
        limiter
            .enter_account_login("acct:admin", "ip:clean-0", None, || async {})
            .await
            .expect("first slot");
        limiter
            .enter_account_login("acct:admin", "ip:clean-1", None, || async {})
            .await
            .expect("second slot after 2s pacing");
        assert!(started.elapsed() >= Duration::from_secs(2));
        limiter
            .enter_account_login("acct:admin", "ip:clean-2", None, || async {})
            .await
            .expect("third slot after another 2s pacing");
        assert!(started.elapsed() >= Duration::from_secs(4));
    }
}
