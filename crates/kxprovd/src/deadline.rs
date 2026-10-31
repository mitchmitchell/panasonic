use std::time::{Duration, Instant};

pub fn recv_deadline(now: Instant, timeout_ms: u64) -> Option<Instant> {
    now.checked_add(Duration::from_millis(timeout_ms))
}

pub fn remaining(deadline: Option<Instant>, now: Instant) -> Duration {
    deadline.map_or(Duration::MAX, |d| d.saturating_duration_since(now))
}

#[cfg(any(test, feature = "test-util"))]
pub fn latest_instant() -> Instant {
    let mut latest = Instant::now();
    let mut step = Duration::from_secs(1 << 62);
    while step >= Duration::from_secs(1) {
        match latest.checked_add(step) {
            Some(later) => latest = later,
            None => step /= 2,
        }
    }
    latest
}

#[cfg(test)]
mod tests {
    use super::{latest_instant, recv_deadline, remaining};
    use std::time::{Duration, Instant};

    #[test]
    fn a_timeout_past_the_clock_range_is_no_deadline() {
        let latest = latest_instant();
        assert_eq!(recv_deadline(latest, 1_000), None);
        assert_eq!(recv_deadline(latest, u64::MAX), None);
        assert_eq!(remaining(None, latest), Duration::MAX);
    }

    #[test]
    fn an_in_range_timeout_is_a_deadline() {
        let now = Instant::now();
        let deadline = recv_deadline(now, 1_000);
        assert_eq!(deadline, Some(now + Duration::from_secs(1)));
        assert_eq!(remaining(deadline, now), Duration::from_secs(1));
        assert_eq!(
            remaining(deadline, now + Duration::from_secs(2)),
            Duration::ZERO
        );
    }
}
