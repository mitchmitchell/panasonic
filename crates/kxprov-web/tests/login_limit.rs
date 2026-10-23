use std::time::Duration;

use kxprov_web::LoginRateLimiter;

#[tokio::test]
async fn login_limiter_uses_separate_account_and_ip_keys() {
    let limiter = LoginRateLimiter::new(2, Duration::from_secs(120));
    limiter.record_failure("acct:admin", "ip:1").await;
    limiter.record_failure("acct:admin", "ip:1").await;
    assert!(!limiter.allow("acct:admin").await);
    assert!(limiter.allow("ip:2").await);
}
