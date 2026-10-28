use chrono::{DateTime, Utc};
use chrono_tz::America::Chicago;

/// Formats an RFC3339 UTC timestamp for operators in Central Time, e.g. `Oct 23, 9:05 AM CT`.
pub fn format_expiry_chicago(rfc3339: &str) -> String {
    let Ok(parsed) = DateTime::parse_from_rfc3339(rfc3339) else {
        return rfc3339.to_string();
    };
    let local = parsed.with_timezone(&Chicago);
    local.format("%b %-d, %-I:%M %p CT").to_string()
}

/// Unix milliseconds for client-side countdowns (whole seconds, no subsecond noise).
pub fn expiry_unix_ms(rfc3339: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(rfc3339)
        .ok()
        .map(|dt| dt.with_timezone(&Utc).timestamp_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chicago_format_has_no_rfc3339_noise() {
        let formatted = format_expiry_chicago("2026-10-23T14:05:00Z");
        assert!(formatted.contains("CT"));
        assert!(!formatted.contains("2026-10-23T"));
        assert!(formatted.contains("Oct"));
    }
}
