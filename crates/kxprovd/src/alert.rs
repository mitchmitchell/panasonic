//! LOCKED notification timing (v2.4: hold until 08:00 America/Chicago).

use chrono::{Timelike, Utc};
use chrono_tz::America::Chicago;

/// Alerts for a LOCKED daemon may fire only at or after 08:00 Central Time.
pub fn locked_alert_may_fire_utc(now: chrono::DateTime<Utc>) -> bool {
    let local = now.with_timezone(&Chicago);
    local.hour() >= 8
}

/// Testing→production mismatch alerts are held between 02:00 and 08:00 Central (v2.8 N2).
pub fn transition_alert_may_fire_utc(now: chrono::DateTime<Utc>) -> bool {
    let local = now.with_timezone(&Chicago);
    let h = local.hour();
    !(2..8).contains(&h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn before_8am_ct_held() {
        let t = Utc.with_ymd_and_hms(2026, 1, 15, 13, 0, 0).unwrap();
        assert!(!locked_alert_may_fire_utc(t));
    }

    #[test]
    fn after_8am_ct_allowed() {
        let t = Utc.with_ymd_and_hms(2026, 1, 15, 15, 0, 0).unwrap();
        assert!(locked_alert_may_fire_utc(t));
    }

    #[test]
    fn transition_alert_held_2_to_8am_ct() {
        let t = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();
        assert!(!transition_alert_may_fire_utc(t));
    }

    #[test]
    fn transition_alert_outside_quiet_hours() {
        let t = Utc.with_ymd_and_hms(2026, 1, 15, 15, 0, 0).unwrap();
        assert!(transition_alert_may_fire_utc(t));
    }
}
