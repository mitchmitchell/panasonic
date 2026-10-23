//! Web session idle (15m) and absolute (8h) limits (design v2.12).

use kxprov_gw::config::GatewayConfig;
use kxprov_web::{WEB_SESSION_ABSOLUTE_SECS, WEB_SESSION_IDLE_SECS};

#[test]
fn v212_session_constants() {
    assert_eq!(WEB_SESSION_IDLE_SECS, 900);
    assert_eq!(WEB_SESSION_ABSOLUTE_SECS, 8 * 3600);
}

#[test]
fn gateway_defaults_match_v212_session_limits() {
    let cfg = GatewayConfig::default();
    assert_eq!(cfg.session_ttl_secs, WEB_SESSION_IDLE_SECS);
    assert_eq!(cfg.session_absolute_secs, WEB_SESSION_ABSOLUTE_SECS);
}
