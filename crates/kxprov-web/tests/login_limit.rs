use std::time::Duration;

use kxprov_web::LoginRateLimiter;

#[tokio::test]
async fn login_limiter_tracks_account_and_ip_separately() {
    let limiter = LoginRateLimiter::new(
        Duration::from_millis(100),
        Duration::from_secs(30),
        Duration::from_secs(30),
    );
    limiter.record_failure("acct:admin", "ip:1").await;
    assert!(
        limiter
            .delay_before_attempt("acct:admin", "ip:1")
            .await
            > Duration::ZERO
    );
    limiter.on_success("acct:admin", "ip:1").await;
    assert_eq!(
        limiter.delay_before_attempt("acct:admin", "ip:1").await,
        Duration::ZERO
    );
}
